/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::config::{AdminConfig, Config};
use crate::error::{ProxyError, Result};
use crate::proto::common::Ctx;

type Shared = Arc<ArcSwap<Ctx>>;

const MAX_HEAD: usize = 16 * 1024;

const LOCKOUT_MAX_ENTRIES: usize = 16 * 1024;

struct Lockout {
    failures: HashMap<IpAddr, (u32, Instant)>,
    threshold: u32,
    duration: Duration,
}

impl Lockout {
    fn is_locked(&self, ip: &IpAddr) -> bool {
        match self.failures.get(ip) {
            Some((count, since)) => *count >= self.threshold && since.elapsed() < self.duration,
            None => false,
        }
    }

    fn record_failure(&mut self, ip: IpAddr) {
        if self.failures.len() >= LOCKOUT_MAX_ENTRIES {
            let duration = self.duration;
            self.failures
                .retain(|_, (_, since)| since.elapsed() < duration);
        }
        let entry = self.failures.entry(ip).or_insert((0, Instant::now()));
        if entry.1.elapsed() >= self.duration {
            *entry = (0, Instant::now());
        }
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    fn record_success(&mut self, ip: &IpAddr) {
        self.failures.remove(ip);
    }
}

pub fn load_token(admin: &AdminConfig) -> Result<String> {
    let token = if let Ok(env) = std::env::var("PROXY_ADMIN_TOKEN") {
        env
    } else if let Some(path) = &admin.bearer_token_file {
        std::fs::read_to_string(path)
            .map_err(|e| ProxyError::config(format!("failed to read admin token {path}: {e}")))?
            .trim()
            .to_string()
    } else if let Some(inline) = &admin.bearer_token {
        inline.clone()
    } else {
        return Err(ProxyError::config("admin token not configured"));
    };
    if token.len() < admin.min_token_len {
        return Err(ProxyError::config(format!(
            "admin token is shorter than min_token_len ({})",
            admin.min_token_len
        )));
    }
    Ok(token)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

pub async fn run(shared: Shared, config: Arc<Config>, config_path: Option<Arc<str>>) -> Result<()> {
    let admin = config
        .admin
        .as_ref()
        .ok_or_else(|| ProxyError::config("admin not configured"))?;
    let listener = TcpListener::bind(admin.bind)
        .await
        .map_err(|e| ProxyError::config(format!("admin bind {}: {e}", admin.bind)))?;
    tracing::info!(bind = %admin.bind, "admin listener started");
    serve(shared, config, config_path, listener).await
}

pub async fn serve(
    shared: Shared,
    config: Arc<Config>,
    config_path: Option<Arc<str>>,
    listener: TcpListener,
) -> Result<()> {
    let admin = config
        .admin
        .as_ref()
        .ok_or_else(|| ProxyError::config("admin not configured"))?;
    let token = Arc::new(load_token(admin)?);
    let acceptor = shared
        .load()
        .tls_acceptor
        .clone()
        .ok_or_else(|| ProxyError::tls("admin requires TLS but no acceptor available"))?;

    let lockout = Arc::new(Mutex::new(Lockout {
        failures: HashMap::new(),
        threshold: admin.lockout_threshold,
        duration: admin.lockout_duration,
    }));

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "admin accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let token = token.clone();
        let shared = shared.clone();
        let lockout = lockout.clone();
        let config_path = config_path.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(
                acceptor,
                tcp,
                peer.ip(),
                token,
                shared,
                lockout,
                config_path,
            )
            .await
            {
                tracing::debug!(error = %e, "admin request ended");
            }
        });
    }
}

async fn handle(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    ip: IpAddr,
    token: Arc<String>,
    shared: Shared,
    lockout: Arc<Mutex<Lockout>>,
    config_path: Option<Arc<str>>,
) -> Result<()> {
    let mut stream = acceptor
        .accept(tcp)
        .await
        .map_err(|e| ProxyError::tls(format!("admin TLS handshake: {e}")))?;

    if lockout.lock().is_locked(&ip) {
        let _ = write_response(&mut stream, 429, "Too Many Requests", "locked out\n").await;
        return Ok(());
    }

    let head = read_head(&mut stream).await?;
    let request = match parse_request(&head) {
        Some(r) => r,
        None => {
            write_response(&mut stream, 400, "Bad Request", "bad request\n").await?;
            return Ok(());
        }
    };

    if request.path == "/healthz" {
        match request.method.as_str() {
            "GET" => write_response(&mut stream, 200, "OK", "ok\n").await?,
            _ => {
                write_response(&mut stream, 405, "Method Not Allowed", "method not allowed\n")
                    .await?
            }
        }
        return Ok(());
    }

    if !authorized(&request, &token) {
        lockout.lock().record_failure(ip);
        tracing::warn!(%ip, path = %request.path, "admin 401 unauthorized");
        write_response(&mut stream, 401, "Unauthorized", "unauthorized\n").await?;
        return Ok(());
    }
    lockout.lock().record_success(&ip);

    let ctx = shared.load_full();

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/stats") => {
            let hits = ctx.router.stats.hits.load(Relaxed);
            let misses = ctx.router.stats.misses.load(Relaxed);
            let total = hits + misses;
            let hit_rate = if total > 0 {
                (hits as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let body = serde_json::json!({
                "cache_hits": hits,
                "cache_misses": misses,
                "hit_rate_pct": hit_rate,
                "cache_entries": ctx.router.cache_entries(),
                "active_connections": ctx.metrics.active_connections.load(Relaxed),
            })
            .to_string();
            write_json(&mut stream, 200, &body).await?;
        }
        ("GET", "/destinations") => {
            let list: Vec<_> = ctx
                .dest_health
                .iter()
                .map(|(id, health)| {
                    let s = health.snapshot();
                    serde_json::json!({
                        "destination": id,
                        "consecutive_failures": s.consecutive_failures,
                        "down": s.down,
                    })
                })
                .collect();
            let body = serde_json::json!({ "destinations": list }).to_string();
            write_json(&mut stream, 200, &body).await?;
        }
        ("POST", "/destinations/reset") => match request.query_param("destination") {
            Some(dest) => match ctx.dest_health.get(&dest) {
                Some(health) => {
                    health.reset();
                    tracing::info!(destination = %dest, "admin reset destination health");
                    write_response(&mut stream, 200, "OK", "ok\n").await?;
                }
                None => {
                    write_response(&mut stream, 404, "Not Found", "unknown destination\n").await?;
                }
            },
            None => {
                write_response(&mut stream, 400, "Bad Request", "destination required\n").await?;
            }
        },
        ("GET", "/mappings") => match request.query_param("identifier") {
            Some(id) => {
                let d = ctx.router.diagnose(&id).await;
                let body = serde_json::json!({
                    "identifier": id,
                    "normalized": d.normalized,
                    "destination": d.destination,
                    "routed_to_default": d.routed_to_default,
                    "cached": d.cached,
                })
                .to_string();
                write_json(&mut stream, 200, &body).await?;
            }
            None => {
                write_response(&mut stream, 400, "Bad Request", "identifier required\n").await?;
            }
        },
        ("PUT", "/mappings") => {
            match (
                request.query_param("identifier"),
                request.query_param("destination"),
            ) {
                (Some(id), Some(dest)) => {
                    if !ctx.router.store_writable() {
                        write_response(
                            &mut stream,
                            501,
                            "Not Implemented",
                            "mapping store is read-only\n",
                        )
                        .await?;
                    } else if !ctx.router.is_valid_destination(&dest) {
                        write_response(&mut stream, 400, "Bad Request", "unknown destination\n")
                            .await?;
                    } else {
                        match ctx.router.upsert(&id, &dest).await {
                            Ok(()) => {
                                tracing::info!(identifier = %crate::observe::redact(&id), %dest, "admin upserted mapping");
                                write_response(&mut stream, 200, "OK", "ok\n").await?;
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "admin mapping upsert failed");
                                write_response(
                                    &mut stream,
                                    500,
                                    "Internal Server Error",
                                    "upsert failed\n",
                                )
                                .await?;
                            }
                        }
                    }
                }
                _ => {
                    write_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        "identifier and destination required\n",
                    )
                    .await?;
                }
            }
        }
        ("DELETE", "/mappings") => match request.query_param("identifier") {
            Some(id) => {
                if !ctx.router.store_writable() {
                    write_response(
                        &mut stream,
                        501,
                        "Not Implemented",
                        "mapping store is read-only\n",
                    )
                    .await?;
                } else {
                    match ctx.router.remove(&id).await {
                        Ok(existed) => {
                            tracing::info!(identifier = %crate::observe::redact(&id), existed, "admin removed mapping");
                            let body = if existed { "removed\n" } else { "absent\n" };
                            write_response(&mut stream, 200, "OK", body).await?;
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "admin mapping remove failed");
                            write_response(
                                &mut stream,
                                500,
                                "Internal Server Error",
                                "remove failed\n",
                            )
                            .await?;
                        }
                    }
                }
            }
            None => {
                write_response(&mut stream, 400, "Bad Request", "identifier required\n").await?;
            }
        },
        ("POST", "/config/reload") => match &config_path {
            None => {
                write_response(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    "config reload not available\n",
                )
                .await?;
            }
            Some(path) => match reload_config(&shared, path).await {
                Ok(()) => {
                    tracing::info!("admin reloaded configuration");
                    let body = serde_json::json!({
                        "reloaded": true,
                        "note": "listener binds/protocols, admin bind/token, and cache capacity/TTLs require a restart to change",
                    })
                    .to_string();
                    write_json(&mut stream, 200, &body).await?;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "admin config reload failed");
                    write_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        &format!("reload failed: {e}\n"),
                    )
                    .await?;
                }
            },
        },
        ("POST", "/cache/invalidate") => {
            match request.query_param("identifier") {
                Some(id) => {
                    ctx.router.invalidate(&id).await;
                    tracing::info!(identifier = %crate::observe::redact(&id), "admin invalidated entry");
                }
                None => {
                    ctx.router.invalidate_all();
                    tracing::info!("admin invalidated entire cache");
                }
            }
            write_response(&mut stream, 200, "OK", "ok\n").await?;
        }
        ("POST", "/mappings/reload") => match ctx.router.reload().await {
            Ok(()) => {
                tracing::info!("admin reloaded mappings");
                write_response(&mut stream, 200, "OK", "reloaded\n").await?;
            }
            Err(e) => {
                tracing::warn!(error = %e, "admin reload failed");
                write_response(&mut stream, 500, "Internal Server Error", "reload failed\n")
                    .await?;
            }
        },
        ("POST", "/connections/kick") => match request.query_param("identifier") {
            Some(id) => {
                let count = ctx.conns.kick(&ctx.router.normalize(&id));
                tracing::info!(identifier = %crate::observe::redact(&id), count, "admin kicked connections");
                write_response(&mut stream, 200, "OK", &format!("kicked {count}\n")).await?;
            }
            None => {
                write_response(&mut stream, 400, "Bad Request", "identifier required\n").await?;
            }
        },
        ("POST", "/connections/delay") => {
            match (
                request.query_param("identifier"),
                request.query_param("seconds"),
            ) {
                (Some(id), Some(secs)) => match secs.parse::<u64>() {
                    Ok(seconds) => {
                        let until =
                            std::time::Instant::now() + std::time::Duration::from_secs(seconds);
                        ctx.conns.set_delay(&ctx.router.normalize(&id), until);
                        tracing::info!(identifier = %crate::observe::redact(&id), seconds, "admin set login delay");
                        write_response(&mut stream, 200, "OK", "ok\n").await?;
                    }
                    Err(_) => {
                        write_response(&mut stream, 400, "Bad Request", "invalid seconds\n")
                            .await?;
                    }
                },
                _ => {
                    write_response(
                        &mut stream,
                        400,
                        "Bad Request",
                        "identifier and seconds required\n",
                    )
                    .await?;
                }
            }
        }
        (_, "/stats")
        | (_, "/destinations")
        | (_, "/destinations/reset")
        | (_, "/mappings")
        | (_, "/cache/invalidate")
        | (_, "/mappings/reload")
        | (_, "/connections/kick")
        | (_, "/connections/delay")
        | (_, "/config/reload") => {
            write_response(
                &mut stream,
                405,
                "Method Not Allowed",
                "method not allowed\n",
            )
            .await?;
        }
        _ => {
            write_response(&mut stream, 404, "Not Found", "not found\n").await?;
        }
    }
    Ok(())
}

struct AdminRequest {
    method: String,
    path: String,
    query: String,
    auth: Option<String>,
}

impl AdminRequest {
    fn query_param(&self, key: &str) -> Option<String> {
        for pair in self.query.split('&') {
            if let Some((k, v)) = pair.split_once('=')
                && k == key
            {
                return Some(
                    percent_encoding::percent_decode_str(v)
                        .decode_utf8_lossy()
                        .into_owned(),
                );
            }
        }
        None
    }
}

fn authorized(request: &AdminRequest, token: &str) -> bool {
    match &request.auth {
        Some(value) => value
            .strip_prefix("Bearer ")
            .map(|t| ct_eq(t.trim().as_bytes(), token.as_bytes()))
            .unwrap_or(false),
        None => false,
    }
}

fn parse_request(head: &[u8]) -> Option<AdminRequest> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let (raw_path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q.to_string()),
        None => (target, String::new()),
    };
    let trimmed = raw_path.trim_end_matches('/');
    let path = if trimmed.is_empty() {
        "/".to_string()
    } else {
        trimmed.to_string()
    };
    let mut auth = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("authorization")
        {
            auth = Some(value.trim().to_string());
        }
    }
    Some(AdminRequest {
        method,
        path,
        query,
        auth,
    })
}

async fn read_head<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut scratch = [0u8; 1024];
    loop {
        if let Some(pos) = find_double_crlf(&buf) {
            buf.truncate(pos);
            return Ok(buf);
        }
        if buf.len() > MAX_HEAD {
            return Err(ProxyError::protocol("admin request head too large"));
        }
        let n = stream
            .read(&mut scratch)
            .await
            .map_err(|e| ProxyError::protocol(format!("admin read: {e}")))?;
        if n == 0 {
            return Err(ProxyError::Closed);
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

async fn write_response<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    code: u16,
    reason: &str,
    body: &str,
) -> Result<()> {
    write_body(stream, code, reason, "text/plain", body).await
}

async fn write_json<S: AsyncWriteExt + Unpin>(stream: &mut S, code: u16, body: &str) -> Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    write_body(stream, code, reason, "application/json", body).await
}

async fn write_body<S: AsyncWriteExt + Unpin>(
    stream: &mut S,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: {content_type}\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| ProxyError::protocol(format!("admin write: {e}")))?;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
    Ok(())
}

async fn reload_config(shared: &Shared, path: &str) -> Result<()> {
    let raw = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| ProxyError::config(format!("read config {path}: {e}")))?;
    let config = Arc::new(Config::parse_and_validate(&raw)?);
    let provider = crate::net::tls::provider();
    let current = shared.load_full();
    let conns = current.conns.clone();
    let metrics = current.metrics.clone();
    let ctx = crate::server::build_ctx(config, &provider, conns, metrics).await?;
    shared.store(Arc::new(ctx));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn parse_basic_request() {
        let head = b"POST /cache/invalidate?identifier=user%40example.com HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer secret\r\n";
        let req = parse_request(head).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/cache/invalidate");
        assert_eq!(
            req.query_param("identifier").as_deref(),
            Some("user@example.com")
        );
        assert_eq!(req.auth.as_deref(), Some("Bearer secret"));
    }

    #[test]
    fn parse_trims_trailing_slash() {
        let req = parse_request(b"GET /stats/ HTTP/1.1\r\nHost: x\r\n").unwrap();
        assert_eq!(req.path, "/stats");
        let req = parse_request(b"GET /cache/invalidate/?identifier=a HTTP/1.1\r\nHost: x\r\n")
            .unwrap();
        assert_eq!(req.path, "/cache/invalidate");
        assert_eq!(req.query_param("identifier").as_deref(), Some("a"));
        let req = parse_request(b"GET / HTTP/1.1\r\nHost: x\r\n").unwrap();
        assert_eq!(req.path, "/");
    }

    #[test]
    fn lockout_after_threshold() {
        let mut l = Lockout {
            failures: HashMap::new(),
            threshold: 2,
            duration: Duration::from_secs(60),
        };
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(!l.is_locked(&ip));
        l.record_failure(ip);
        assert!(!l.is_locked(&ip));
        l.record_failure(ip);
        assert!(l.is_locked(&ip));
        l.record_success(&ip);
        assert!(!l.is_locked(&ip));
    }
}
