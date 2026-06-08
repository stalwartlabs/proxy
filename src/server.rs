/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use arc_swap::ArcSwap;
use rustls::crypto::CryptoProvider;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::error::Result;
use crate::net::acceptor::Listener;
use crate::net::tls;
use crate::proto::common::{ConnRegistry, Ctx, Metrics};
use crate::route::Router;

pub async fn run(config: Arc<Config>, config_path: Arc<str>) -> Result<()> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let provider = tls::provider();

    if let Some(admin) = &config.admin {
        crate::admin::load_token(admin)?;
    }

    let conns = Arc::new(ConnRegistry::default());
    let metrics = Arc::new(Metrics::default());
    let ctx = build_ctx(config.clone(), &provider, conns, metrics).await?;
    let shared = Arc::new(ArcSwap::from_pointee(ctx));

    spawn_metrics_logger(shared.clone());

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut tasks = Vec::new();

    for (id, listener_cfg) in &config.listener {
        let listener = Arc::new(Listener::new(
            id.as_str().into(),
            Arc::new(listener_cfg.clone()),
        ));
        let shared = shared.clone();
        let shutdown_rx = shutdown_rx.clone();
        tasks.push(tokio::spawn(async move {
            listener.run(shared, shutdown_rx).await;
        }));
    }

    if config.admin.is_some() {
        let shared = shared.clone();
        let config = config.clone();
        let config_path = config_path.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(e) = crate::admin::run(shared, config, Some(config_path)).await {
                tracing::error!(error = %e, "admin listener exited");
            }
        }));
    }

    if tasks.is_empty() {
        return Err(crate::error::ProxyError::config("no listeners configured"));
    }

    tracing::info!("proxy started");
    shutdown_signal().await;
    let grace = config.server.shutdown_grace;
    tracing::info!(grace = ?grace, "shutdown signal received; draining");
    let _ = shutdown_tx.send(true);
    drain(&shared, grace).await;
    Ok(())
}

pub(crate) async fn build_ctx(
    config: Arc<Config>,
    provider: &Arc<CryptoProvider>,
    conns: Arc<ConnRegistry>,
    metrics: Arc<Metrics>,
) -> Result<Ctx> {
    let server_config = tls::build_server_config(&config, provider.clone())?;
    let tls_acceptor = Some(TlsAcceptor::from(server_config));

    let valid_destinations: Vec<String> = config.destination.keys().cloned().collect();
    let router = Arc::new(Router::build(&config, valid_destinations).await?);
    validate_mapped_destinations(&config, &router)?;
    let http_router = Arc::new(crate::http::router::HttpRouter::build(
        &config.http,
        config.oauth.jwt_username_claim.clone(),
    )?);
    let dests = Ctx::build_dest_runtimes(&config, provider)?;
    let dest_health = Ctx::build_dest_health(&config);
    let self_binds = Ctx::build_self_binds(&config);

    for dest in config.destination.values() {
        if dest.tls_allow_invalid_certs {
            tracing::warn!(
                host = %dest.host,
                "tls_allow_invalid_certs is enabled: the proxy->backend leg is UNAUTHENTICATED and forwards real credentials"
            );
        }
    }

    let greetings = crate::proto::common::build_greetings(&config);
    Ok(Ctx {
        config,
        router,
        http_router,
        tls_acceptor,
        dests,
        dest_health,
        self_binds,
        conns,
        metrics,
        greetings,
    })
}

fn validate_mapped_destinations(config: &Config, router: &Router) -> Result<()> {
    use crate::config::{MappingSource, Protocol};
    if matches!(
        config.mapping.source,
        MappingSource::Redis | MappingSource::Sql
    ) {
        tracing::info!(
            "dynamic mapping store: per-destination protocol support is validated at connection time, not at boot"
        );
    }
    let routed: Vec<Protocol> = config
        .listener
        .values()
        .map(|l| l.protocol)
        .filter(|p| !p.is_passthrough() && *p != Protocol::Http)
        .collect();
    for dest_id in router.mapped_destinations() {
        let Some(dest) = config.destination.get(&dest_id) else {
            continue;
        };
        for proto in &routed {
            if !dest.protocol.contains_key(proto) {
                return Err(crate::error::ProxyError::config(format!(
                    "mapped destination {dest_id:?} does not declare protocol {} required by a listener",
                    proto.as_str()
                )));
            }
        }
    }
    Ok(())
}

async fn drain(shared: &Arc<ArcSwap<Ctx>>, grace: std::time::Duration) {
    use std::sync::atomic::Ordering::Relaxed;
    let deadline = tokio::time::sleep(grace);
    tokio::pin!(deadline);
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        tokio::select! {
            _ = &mut deadline => {
                let active = shared.load().metrics.active_connections.load(Relaxed);
                if active > 0 {
                    tracing::warn!(active, "grace elapsed; forcing shutdown with live connections");
                }
                return;
            }
            _ = tick.tick() => {
                if shared.load().metrics.active_connections.load(Relaxed) <= 0 {
                    tracing::info!("all connections drained");
                    return;
                }
            }
        }
    }
}

fn spawn_metrics_logger(shared: Arc<ArcSwap<Ctx>>) {
    use std::sync::atomic::Ordering::Relaxed;
    use std::time::Duration;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            let ctx = shared.load();
            let hits = ctx.router.stats.hits.load(Relaxed);
            let misses = ctx.router.stats.misses.load(Relaxed);
            let total = hits + misses;
            let hit_rate = if total > 0 {
                (hits as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let active = ctx.metrics.active_connections.load(Relaxed);
            tracing::info!(
                cache_hits = hits,
                cache_misses = misses,
                hit_rate_pct = hit_rate,
                active_connections = active,
                "metrics"
            );
        }
    });
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
