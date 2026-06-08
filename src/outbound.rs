/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout};
use tokio_rustls::TlsConnector;

use crate::config::{DestProtocol, DestinationConfig, Forwarding, TlsMode};
use crate::error::{ProxyError, Result};
use crate::net::BoxedStream;
use crate::net::proxy_protocol::build_outbound_header;

pub fn server_name(dest: &DestinationConfig) -> Result<ServerName<'static>> {
    let name = dest
        .tls_server_name
        .clone()
        .unwrap_or_else(|| dest.host.clone());
    ServerName::try_from(name).map_err(|_| {
        ProxyError::backend("destination has no valid TLS server name (set tls_server_name)")
    })
}

pub async fn dial(
    dest: &DestinationConfig,
    ep: &DestProtocol,
    forwarding: Forwarding,
    client_config: &Arc<ClientConfig>,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<BoxedStream> {
    let mut stream = connect_with_source(dest, ep).await?;
    let _ = stream.set_nodelay(true);

    if forwarding == Forwarding::Proxy {
        let header = build_outbound_header(peer, local)?;
        stream
            .write_all(&header)
            .await
            .map_err(|e| ProxyError::backend(format!("writing PROXY header: {e}")))?;
    }

    match ep.tls {
        TlsMode::Implicit => tls_connect(Box::new(stream), client_config, dest).await,
        TlsMode::Plain | TlsMode::Starttls => Ok(Box::new(stream)),
    }
}

async fn connect_with_source(dest: &DestinationConfig, ep: &DestProtocol) -> Result<TcpStream> {
    use std::net::{IpAddr, SocketAddr as StdSocketAddr};
    use tokio::net::TcpSocket;

    if dest.source_ips.is_empty() {
        return TcpStream::connect((dest.host.as_str(), ep.port))
            .await
            .map_err(|e| ProxyError::backend_connect(format!("backend connect failed: {e}")));
    }

    let addrs = tokio::net::lookup_host((dest.host.as_str(), ep.port))
        .await
        .map_err(|e| ProxyError::backend_connect(format!("backend DNS lookup failed: {e}")))?;

    let mut last_err: Option<ProxyError> = None;
    for addr in addrs {
        let Some(src) = pick_source_ip(&dest.source_ips, addr.is_ipv4()) else {
            continue;
        };
        let socket = match if addr.is_ipv4() {
            TcpSocket::new_v4()
        } else {
            TcpSocket::new_v6()
        } {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(ProxyError::backend_connect(format!("socket: {e}")));
                continue;
            }
        };
        let bind_addr = StdSocketAddr::new(src, 0);
        if let Err(e) = socket.bind(bind_addr) {
            last_err = Some(ProxyError::backend_connect(format!(
                "binding source {src}: {e}"
            )));
            continue;
        }
        match socket.connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => {
                let _: IpAddr = src;
                last_err = Some(ProxyError::backend_connect(format!(
                    "backend connect failed: {e}"
                )));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| ProxyError::backend_connect("no usable source IP for backend")))
}

fn pick_source_ip(source_ips: &[std::net::IpAddr], want_v4: bool) -> Option<std::net::IpAddr> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static RR: AtomicUsize = AtomicUsize::new(0);
    let count = source_ips
        .iter()
        .filter(|ip| ip.is_ipv4() == want_v4)
        .count();
    if count == 0 {
        return None;
    }
    let idx = RR.fetch_add(1, Ordering::Relaxed) % count;
    source_ips
        .iter()
        .copied()
        .filter(|ip| ip.is_ipv4() == want_v4)
        .nth(idx)
}

pub async fn tls_connect(
    stream: BoxedStream,
    client_config: &Arc<ClientConfig>,
    dest: &DestinationConfig,
) -> Result<BoxedStream> {
    let connector = TlsConnector::from(client_config.clone());
    let name = server_name(dest)?;
    let tls = connector
        .connect(name, stream)
        .await
        .map_err(|e| ProxyError::backend_connect(format!("backend TLS handshake failed: {e}")))?;
    Ok(Box::new(tls))
}

pub async fn read_line(
    stream: &mut BoxedStream,
    residual: &mut Vec<u8>,
    max: usize,
) -> Result<Vec<u8>> {
    let mut line = std::mem::take(residual);
    let mut search_from = 0;
    loop {
        if let Some(pos) = find_crlf(&line, search_from) {
            let rest = line.split_off(pos + 2);
            *residual = rest;
            line.truncate(pos);
            return Ok(line);
        }
        search_from = line.len().saturating_sub(1);
        if line.len() > max {
            return Err(ProxyError::backend("backend line exceeded maximum length"));
        }
        let mut buf = [0u8; 4096];
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| ProxyError::backend_connect(format!("reading backend: {e}")))?;
        if n == 0 {
            return Err(ProxyError::backend_connect(
                "backend closed before sending a complete line",
            ));
        }
        line.extend_from_slice(&buf[..n]);
    }
}

fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    if buf.len() < 2 {
        return None;
    }
    (from..buf.len() - 1).find(|&i| buf[i] == b'\r' && buf[i + 1] == b'\n')
}

pub async fn write_all(stream: &mut BoxedStream, bytes: &[u8]) -> Result<()> {
    stream
        .write_all(bytes)
        .await
        .map_err(|e| ProxyError::backend(format!("writing backend: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| ProxyError::backend(format!("flushing backend: {e}")))
}

const BRIDGE_BUF: usize = 16 * 1024;

const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

pub async fn bridge(
    mut client: BoxedStream,
    mut backend: BoxedStream,
    to_backend: &[u8],
    to_client: &[u8],
    idle: Duration,
    cancel: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<(u64, u64)> {
    if !to_backend.is_empty() {
        write_all(&mut backend, to_backend).await?;
    }
    if !to_client.is_empty() {
        client
            .write_all(to_client)
            .await
            .map_err(|e| ProxyError::backend(format!("seeding client: {e}")))?;
        let _ = client.flush().await;
    }

    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut br, mut bw) = tokio::io::split(backend);

    let base = Instant::now();
    let activity = Arc::new(AtomicU64::new(0));

    let mut c2b = std::pin::pin!(pump(&mut cr, &mut bw, base, activity.clone()));
    let mut b2c = std::pin::pin!(pump(&mut br, &mut cw, base, activity.clone()));
    let watchdog = std::pin::pin!(idle_watchdog(base, activity, idle));

    let mut c2b_done: Option<u64> = None;
    let mut b2c_done: Option<u64> = None;
    let drain = async {
        loop {
            tokio::select! {
                r = &mut c2b, if c2b_done.is_none() => c2b_done = Some(r?),
                r = &mut b2c, if b2c_done.is_none() => b2c_done = Some(r?),
            }
            if c2b_done.is_some() && b2c_done.is_some() {
                return Ok::<(u64, u64), std::io::Error>((
                    c2b_done.unwrap_or(0),
                    b2c_done.unwrap_or(0),
                ));
            }
        }
    };

    tokio::select! {
        result = drain => result.map_err(|e| ProxyError::backend(format!("bridge: {e}"))),
        _ = watchdog => Err(ProxyError::backend("bridge idle timeout")),
        _ = wait_kick(cancel) => Err(ProxyError::backend("disconnected by admin")),
    }
}

async fn wait_kick(cancel: Option<tokio::sync::watch::Receiver<bool>>) {
    match cancel {
        Some(mut rx) => {
            while rx.changed().await.is_ok() {
                if *rx.borrow() {
                    return;
                }
            }
            std::future::pending::<()>().await
        }
        None => std::future::pending::<()>().await,
    }
}

async fn pump<R, W>(
    reader: &mut R,
    writer: &mut W,
    base: Instant,
    activity: Arc<AtomicU64>,
) -> std::io::Result<u64>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = vec![0u8; BRIDGE_BUF];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            let _ = timeout(SHUTDOWN_GRACE, writer.shutdown()).await;
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await?;
        if n < buf.len() {
            let _ = writer.flush().await;
        }
        total += n as u64;
        activity.store(base.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
}

async fn idle_watchdog(base: Instant, activity: Arc<AtomicU64>, idle: Duration) {
    let idle_ms = (idle.as_millis() as u64).max(1);
    loop {
        let last = activity.load(Ordering::Relaxed);
        let now = base.elapsed().as_millis() as u64;
        let elapsed = now.saturating_sub(last);
        if elapsed >= idle_ms {
            return;
        }
        tokio::time::sleep(Duration::from_millis(idle_ms - elapsed)).await;
    }
}
