/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ahash::AHashMap;
use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::config::{Config, ListenerConfig, TlsMode};
use crate::error::{ProxyError, Result};
use crate::net::proxy_protocol::InboundResolution;
use crate::proto;
use crate::runtime::metrics::{ListenerCounters, Metrics};
use crate::runtime::{ListenerId, Runtime};

const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(5);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
const LISTEN_BACKLOG: u32 = 1024;
const EPHEMERAL_PORT: u16 = 0;

struct ConnGuard<'a>(&'a Metrics);

impl<'a> ConnGuard<'a> {
    fn new(metrics: &'a Metrics) -> Self {
        metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        ConnGuard(metrics)
    }
}

impl Drop for ConnGuard<'_> {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ProxyError {
    #[cold]
    #[inline(never)]
    fn bind_failed(
        name: &str,
        addr: SocketAddr,
        err: &io::Error,
        bound: &AHashMap<SocketAddr, &Arc<TcpListener>>,
    ) -> ProxyError {
        let held = bound.keys().find(|running| {
            running.port() == addr.port()
                && (running.ip().is_unspecified() || addr.ip().is_unspecified())
        });
        match held {
            Some(running) if err.kind() == io::ErrorKind::AddrInUse => ProxyError::config(format!(
                "listener {name}: failed to bind {addr}: {err}; {running} is still bound by a running listener, apply its removal first, then add {addr} in a second apply"
            )),
            _ => ProxyError::config(format!("listener {name}: failed to bind {addr}: {err}")),
        }
    }
}

pub struct Listener {
    pub id: Arc<str>,
    pub config: Arc<ListenerConfig>,
    pub semaphore: Arc<Semaphore>,
    listener_id: ListenerId,
    metrics: Arc<Metrics>,
}

impl Listener {
    pub fn new(
        id: Arc<str>,
        config: Arc<ListenerConfig>,
        listener_id: ListenerId,
        metrics: Arc<Metrics>,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_connections));
        Listener {
            id,
            config,
            semaphore,
            listener_id,
            metrics,
        }
    }

    fn listen(addr: SocketAddr) -> io::Result<TcpListener> {
        let socket = match addr {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }?;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        socket.set_reuseaddr(true)?;
        socket.bind(addr)?;
        socket.listen(LISTEN_BACKLOG)
    }

    pub async fn run(
        self: Arc<Self>,
        sockets: Vec<Arc<TcpListener>>,
        rt: Arc<ArcSwap<Runtime>>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut loops = JoinSet::new();
        for socket in sockets {
            loops.spawn(
                self.clone()
                    .accept_loop(rt.clone(), socket, shutdown.clone()),
            );
        }
        while let Some(result) = loops.join_next().await {
            if let Err(err) = result {
                tracing::error!(listener = %self.id, error = %err, "accept loop failed");
            }
        }
    }

    async fn accept_loop(
        self: Arc<Self>,
        rt: Arc<ArcSwap<Runtime>>,
        listener: Arc<TcpListener>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut backoff = ACCEPT_BACKOFF_MIN;
        loop {
            let accepted = tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::debug!(listener = %self.id, "accept loop stopping");
                    return;
                }
                accepted = listener.accept() => accepted,
            };
            let (tcp, peer) = match accepted {
                Ok(pair) => {
                    backoff = ACCEPT_BACKOFF_MIN;
                    pair
                }
                Err(e) => {
                    tracing::warn!(listener = %self.id, error = %e, backoff = ?backoff, "accept failed");
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => return,
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                    continue;
                }
            };
            let counters = self.metrics.listener(self.listener_id);
            let permit = match self.semaphore.clone().try_acquire_owned() {
                Ok(p) => {
                    ListenerCounters::bump(&counters.accepted);
                    p
                }
                Err(_) => {
                    ListenerCounters::bump(&counters.rejected_limit);
                    tracing::warn!(listener = %self.id, "max_connections reached; dropping connection");
                    drop(tcp);
                    continue;
                }
            };
            let local = tcp.local_addr().unwrap_or(peer);
            let _ = tcp.set_nodelay(true);
            let rt = rt.load_full();
            let this = self.clone();
            let span = tracing::info_span!(
                "conn",
                listener = %this.id,
                protocol = this.config.protocol.as_str(),
                peer = %peer.ip(),
            );
            tokio::spawn(
                async move {
                    let _permit = permit;
                    let _guard = ConnGuard::new(&this.metrics);
                    if let Err(e) = this.serve(rt, tcp, peer, local).await {
                        tracing::debug!(error = %e, "connection ended");
                    }
                }
                .instrument(span),
            );
        }
    }

    async fn serve(
        &self,
        rt: Arc<Runtime>,
        tcp: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
        local: std::net::SocketAddr,
    ) -> Result<()> {
        let cfg = &self.config;
        let (preauth_timeout, mode, trusted) = match rt.listener(self.listener_id) {
            Some(settings) => (
                settings.preauth_timeout,
                settings.proxy_protocol,
                &*settings.proxy_trusted,
            ),
            None => (
                cfg.preauth_timeout,
                cfg.proxy_protocol,
                cfg.proxy_trusted.as_slice(),
            ),
        };
        let resolved = match tokio::time::timeout(
            preauth_timeout,
            InboundResolution::resolve(tcp, peer, local, mode, trusted),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                return Err(ProxyError::preauth("inbound PROXY header timeout"));
            }
        };

        let mut stream = resolved.stream;
        let peer = resolved.peer;
        let local = resolved.local;

        if cfg.tls == TlsMode::Implicit {
            let Some(acceptor) = rt.inbound_tls.as_ref() else {
                return Err(ProxyError::tls(
                    "implicit TLS listener but no TLS acceptor configured",
                ));
            };
            stream = match tokio::time::timeout(preauth_timeout, stream.accept_tls(acceptor)).await
            {
                Ok(r) => r?,
                Err(_) => {
                    return Err(ProxyError::tls("inbound TLS handshake timed out"));
                }
            };
        }

        if let Some(tls) = stream.tls_info() {
            tracing::debug!(
                listener = %self.id,
                %peer,
                version = tls.version_str(),
                cipher = tls.cipher_str(),
                "tls connection"
            );
        }

        proto::dispatch(rt, cfg.protocol, self.listener_id, stream, peer, local).await
    }
}

struct RunningListener {
    config: Arc<ListenerConfig>,
    sockets: Box<[Arc<TcpListener>]>,
    _stop: watch::Sender<bool>,
}

struct StagedListener {
    name: Box<str>,
    config: Arc<ListenerConfig>,
    sockets: Box<[Arc<TcpListener>]>,
}

#[derive(Default)]
pub struct StagedListeners(Vec<StagedListener>);

#[derive(Default)]
struct Running {
    listeners: AHashMap<Box<str>, RunningListener>,
    closed: bool,
}

#[derive(Default)]
pub struct ListenerSet {
    running: Mutex<Running>,
}

impl ListenerSet {
    pub fn stage(&self, raw: &Config) -> Result<StagedListeners> {
        let running = self.running.lock();
        let bound: AHashMap<SocketAddr, &Arc<TcpListener>> = running
            .listeners
            .values()
            .flat_map(|listener| listener.config.bind.iter().zip(&listener.sockets))
            .filter(|(addr, _)| addr.port() != EPHEMERAL_PORT)
            .map(|(addr, socket)| (*addr, socket))
            .collect();
        let mut staged = Vec::new();
        for (name, config) in &raw.listener {
            if running
                .listeners
                .get(name.as_str())
                .is_some_and(|current| current.config.same_sockets(config))
            {
                continue;
            }
            let sockets = config
                .bind
                .iter()
                .map(|addr| match bound.get(addr) {
                    Some(socket) => Ok(Arc::clone(socket)),
                    None => Listener::listen(*addr)
                        .map(Arc::new)
                        .map_err(|err| ProxyError::bind_failed(name, *addr, &err, &bound)),
                })
                .collect::<Result<Box<[_]>>>()?;
            staged.push(StagedListener {
                name: name.as_str().into(),
                config: Arc::new(config.clone()),
                sockets,
            });
        }
        Ok(StagedListeners(staged))
    }

    pub fn start(&self, staged: StagedListeners, swap: &Arc<ArcSwap<Runtime>>, rt: &Runtime) {
        let mut running = self.running.lock();
        if running.closed {
            return;
        }
        running.listeners.retain(|name, _| {
            let keep = rt.raw.listener.contains_key(&**name);
            if !keep {
                tracing::info!(listener = %name, "listener removed; live sessions continue");
            }
            keep
        });
        for listener in staged.0 {
            let Some(id) = rt.shared.ids.listener_id(&listener.name) else {
                tracing::error!(listener = %listener.name, "listener has no id; not started");
                continue;
            };
            let (stop, stopped) = watch::channel(false);
            let accept = Arc::new(Listener::new(
                Arc::from(&*listener.name),
                listener.config.clone(),
                id,
                rt.shared.metrics.clone(),
            ));
            for (addr, socket) in listener.config.bind.iter().zip(&listener.sockets) {
                let addr = socket.local_addr().unwrap_or(*addr);
                tracing::info!(listener = %listener.name, %addr, protocol = listener.config.protocol.as_str(), "listening");
            }
            tokio::spawn(accept.run(listener.sockets.to_vec(), swap.clone(), stopped));
            running.listeners.insert(
                listener.name,
                RunningListener {
                    config: listener.config,
                    sockets: listener.sockets,
                    _stop: stop,
                },
            );
        }
    }

    pub fn shutdown(&self) {
        let mut running = self.running.lock();
        running.closed = true;
        running.listeners.clear();
    }
}
