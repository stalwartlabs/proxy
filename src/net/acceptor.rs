/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;
use std::sync::atomic::Ordering;

use arc_swap::ArcSwap;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::Instrument;

use crate::config::{ListenerConfig, TlsMode};
use crate::net::proxy_protocol::resolve_inbound;
use crate::proto::common::Ctx;
use crate::proto::{self};

struct ConnGuard {
    ctx: Arc<Ctx>,
}

impl ConnGuard {
    fn new(ctx: &Arc<Ctx>) -> Self {
        ctx.metrics
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
        ConnGuard { ctx: ctx.clone() }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.ctx
            .metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

pub struct Listener {
    pub id: Arc<str>,
    pub config: Arc<ListenerConfig>,
    pub semaphore: Arc<Semaphore>,
}

impl Listener {
    pub fn new(id: Arc<str>, config: Arc<ListenerConfig>) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_connections));
        Listener {
            id,
            config,
            semaphore,
        }
    }

    pub async fn run(
        self: Arc<Self>,
        ctx: Arc<ArcSwap<Ctx>>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut handles = Vec::new();
        for &addr in &self.config.bind {
            let listener = match TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(listener = %self.id, %addr, error = %e, "failed to bind");
                    continue;
                }
            };
            tracing::info!(listener = %self.id, %addr, protocol = self.config.protocol.as_str(), "listening");
            let this = self.clone();
            let ctx = ctx.clone();
            let shutdown = shutdown.clone();
            handles.push(tokio::spawn(async move {
                this.accept_loop(ctx, listener, shutdown).await;
            }));
        }
        for h in handles {
            let _ = h.await;
        }
    }

    async fn accept_loop(
        self: Arc<Self>,
        ctx: Arc<ArcSwap<Ctx>>,
        listener: TcpListener,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) {
        loop {
            let (tcp, peer) = tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    tracing::debug!(listener = %self.id, "accept loop stopping");
                    return;
                }
                accepted = listener.accept() => match accepted {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(listener = %self.id, error = %e, "accept failed");
                        continue;
                    }
                },
            };
            let permit = match self.semaphore.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    tracing::warn!(listener = %self.id, "max_connections reached; dropping connection");
                    drop(tcp);
                    continue;
                }
            };
            let local = tcp.local_addr().unwrap_or(peer);
            let _ = tcp.set_nodelay(true);
            let ctx = ctx.load_full();
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
                    let _guard = ConnGuard::new(&ctx);
                    if let Err(e) = this.serve(ctx.clone(), tcp, peer, local).await {
                        tracing::debug!(error = %e, "connection ended");
                    }
                }
                .instrument(span),
            );
        }
    }

    async fn serve(
        &self,
        ctx: Arc<Ctx>,
        tcp: tokio::net::TcpStream,
        peer: std::net::SocketAddr,
        local: std::net::SocketAddr,
    ) -> crate::error::Result<()> {
        let cfg = &self.config;
        let resolved = match tokio::time::timeout(
            cfg.preauth_timeout,
            resolve_inbound(tcp, peer, local, cfg.proxy_protocol, &cfg.proxy_trusted),
        )
        .await
        {
            Ok(r) => r?,
            Err(_) => {
                return Err(crate::error::ProxyError::preauth(
                    "inbound PROXY header timeout",
                ));
            }
        };

        let mut stream = resolved.stream;
        let peer = resolved.peer;
        let local = resolved.local;

        if cfg.tls == TlsMode::Implicit {
            let Some(acceptor) = ctx.tls_acceptor.as_ref() else {
                return Err(crate::error::ProxyError::tls(
                    "implicit TLS listener but no TLS acceptor configured",
                ));
            };
            stream = match tokio::time::timeout(
                cfg.preauth_timeout,
                crate::proto::common::upgrade_tls_inbound(stream, acceptor),
            )
            .await
            {
                Ok(r) => r?,
                Err(_) => {
                    return Err(crate::error::ProxyError::tls(
                        "inbound TLS handshake timed out",
                    ));
                }
            };
        }

        if stream.is_tls() {
            let (version, cipher) = stream.tls_version_and_cipher();
            tracing::debug!(listener = %self.id, %peer, %version, %cipher, "tls connection");
        }

        proto::dispatch(&ctx, cfg, stream, peer, local).await
    }
}
