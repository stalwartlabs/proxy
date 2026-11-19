/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpSocket, TcpStream, lookup_host};
use tokio::time::timeout;

use crate::config::Forwarding;
use crate::error::{ProxyError, Result, Side, Stage};
use crate::net::proxy_protocol::OutboundHeader;
use crate::net::stream::BackendStream;
use crate::proto::forward::LoopGuard;
use crate::runtime::destination::{Destination, Endpoint, Host, LegTls};

const PER_ADDRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug)]
pub struct Peers {
    pub peer: SocketAddr,
    pub local: SocketAddr,
}

pub struct DnsCache {
    ttl: Duration,
    entry: Mutex<Option<Resolved>>,
    refreshing: AtomicBool,
}

struct Resolved {
    expires: Instant,
    ips: Arc<[IpAddr]>,
}

struct ExpireOnDrop<'a>(Option<(&'a DnsCache, &'a Arc<[IpAddr]>)>);

impl Drop for ExpireOnDrop<'_> {
    fn drop(&mut self) {
        if let Some((cache, used)) = self.0 {
            cache.expire(used);
        }
    }
}

struct RefreshingFlag<'a>(&'a AtomicBool);

impl Drop for RefreshingFlag<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl DnsCache {
    pub fn new(ttl: Duration) -> Self {
        DnsCache {
            ttl,
            entry: Mutex::new(None),
            refreshing: AtomicBool::new(false),
        }
    }

    async fn resolve(&self, name: &str, port: u16) -> Result<Arc<[IpAddr]>> {
        let now = Instant::now();
        let stale = {
            let entry = self.entry.lock();
            match entry.as_ref() {
                Some(resolved) if resolved.expires > now => return Ok(resolved.ips.clone()),
                Some(resolved) => Some(resolved.ips.clone()),
                None => None,
            }
        };
        let Some(stale) = stale else {
            return self.refresh(name, port).await;
        };
        if self.refreshing.swap(true, Ordering::Acquire) {
            return Ok(stale);
        }
        let _flag = RefreshingFlag(&self.refreshing);
        match self.refresh(name, port).await {
            Ok(ips) => Ok(ips),
            Err(err) => {
                tracing::debug!(host = name, error = %err, "DNS refresh failed, keeping the previous addresses");
                Ok(stale)
            }
        }
    }

    async fn refresh(&self, name: &str, port: u16) -> Result<Arc<[IpAddr]>> {
        let ips: Arc<[IpAddr]> = lookup_host((name, port))
            .await
            .map_err(ProxyError::dns_error)?
            .map(|addr| addr.ip())
            .collect();
        if ips.is_empty() {
            return Err(ProxyError::no_address());
        }
        let expires = Instant::now() + self.ttl;
        *self.entry.lock() = Some(Resolved {
            expires,
            ips: ips.clone(),
        });
        Ok(ips)
    }

    fn expire(&self, used: &Arc<[IpAddr]>) {
        let mut entry = self.entry.lock();
        if let Some(resolved) = entry
            .as_mut()
            .filter(|resolved| Arc::ptr_eq(&resolved.ips, used))
        {
            resolved.expires = Instant::now();
        }
    }
}

impl Destination {
    pub async fn dial(
        &self,
        ep: &Endpoint,
        client: Peers,
        guard: &LoopGuard,
    ) -> Result<BackendStream> {
        guard.check_target(ep)?;
        let mut tcp = self.connect(ep).await?;
        guard.check_connected(ep, &tcp)?;
        ep.check_peer(&tcp)?;
        let _ = tcp.set_nodelay(true);

        if ep.forwarding == Forwarding::Proxy {
            let header = OutboundHeader::new(client.peer, client.local);
            tcp.write_all(&header).await.map_err(|e| {
                ProxyError::unavailable(Stage::Forwarding, format!("writing PROXY header: {e}"))
            })?;
        }

        let stream = BackendStream::from(tcp);
        match &ep.leg {
            LegTls::Implicit(config) => stream.connect_tls(config, self.server_name.as_ref()).await,
            LegTls::Plain | LegTls::Starttls(_) => Ok(stream),
        }
    }

    pub async fn connect(&self, ep: &Endpoint) -> Result<TcpStream> {
        if let Some(addrs) = &ep.addrs {
            return self.connect_any(addrs.iter().copied()).await;
        }
        let Host::Name(name) = &self.host else {
            return Err(ProxyError::no_address());
        };
        let Some(cache) = &self.dns_cache else {
            let addrs = lookup_host((name.as_ref(), ep.port))
                .await
                .map_err(ProxyError::dns_error)?;
            return self.connect_any(addrs).await;
        };
        let ips = cache.resolve(name, ep.port).await?;
        let addrs = ips.iter().map(|&ip| SocketAddr::new(ip, ep.port));
        if !self.source_ips.is_empty() && !addrs.clone().any(|addr| self.source_ips.serves(&addr)) {
            return Err(ProxyError::no_source_ip());
        }
        let mut expire = ExpireOnDrop(Some((cache, &ips)));
        let tcp = self.connect_any(addrs).await?;
        expire.0 = None;
        Ok(tcp)
    }

    async fn connect_any(&self, addrs: impl Iterator<Item = SocketAddr>) -> Result<TcpStream> {
        let mut skipped = false;
        let bind = !self.source_ips.is_empty();
        let mut usable = addrs.filter(|addr| {
            let serves = !bind || self.source_ips.serves(addr);
            skipped |= !serves;
            serves
        });
        let mut next: Option<SocketAddr> = usable.next();
        let mut last = None;
        let mut timed_out = false;
        while let Some(addr) = next {
            next = usable.next();
            let src = if bind {
                self.source_ips.pick(&addr)
            } else {
                None
            };
            let attempt = connect_one(addr, src);
            let result = if next.is_some() {
                match timeout(PER_ADDRESS_CONNECT_TIMEOUT, attempt).await {
                    Ok(result) => result,
                    Err(_) => {
                        timed_out = true;
                        continue;
                    }
                }
            } else {
                attempt.await
            };
            match result {
                Ok(tcp) => return Ok(tcp),
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| {
            if timed_out {
                ProxyError::timeout(Stage::Connect, Side::Backend)
            } else if skipped {
                ProxyError::no_source_ip()
            } else {
                ProxyError::no_address()
            }
        }))
    }
}

async fn connect_one(addr: SocketAddr, src: Option<IpAddr>) -> Result<TcpStream> {
    let Some(src) = src else {
        return TcpStream::connect(addr)
            .await
            .map_err(ProxyError::connect_error);
    };
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .map_err(ProxyError::connect_error)?;
    socket
        .bind(SocketAddr::new(src, 0))
        .map_err(ProxyError::connect_error)?;
    socket
        .connect(addr)
        .await
        .map_err(ProxyError::connect_error)
}

impl ProxyError {
    #[cold]
    #[inline(never)]
    fn dns_error(err: io::Error) -> ProxyError {
        ProxyError::io(Stage::Dns, Side::Backend, err)
    }

    #[cold]
    #[inline(never)]
    fn connect_error(err: io::Error) -> ProxyError {
        ProxyError::io(Stage::Connect, Side::Backend, err)
    }

    #[cold]
    #[inline(never)]
    fn no_address() -> ProxyError {
        ProxyError::io(
            Stage::Dns,
            Side::Backend,
            io::Error::other("backend host resolved to no address"),
        )
    }

    #[cold]
    #[inline(never)]
    fn no_source_ip() -> ProxyError {
        ProxyError::io(
            Stage::Connect,
            Side::Backend,
            io::Error::other("no usable source IP for backend address family"),
        )
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/net/dial/tests.rs"]
mod tests;
