/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use crate::admin;
use crate::config::{Config, Revision};
use crate::error::{ProxyError, Result, Stage};
use crate::net::tls;
use crate::runtime::metrics::SAMPLE_INTERVAL;
use crate::runtime::{Runtime, Shared};

const SAMPLES_PER_LOG: u32 = 6;
const DRAIN_POLL: Duration = Duration::from_millis(100);

pub struct Server {
    swap: Arc<ArcSwap<Runtime>>,
}

impl Server {
    pub async fn run(config: Arc<Config>, revision: Revision, config_path: Arc<str>) -> Result<()> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let provider = tls::provider();

        if let Some(admin) = &config.admin {
            admin.load_token()?;
        }
        if config.listener.is_empty() && config.admin.is_none() {
            return Err(ProxyError::config("no listeners configured"));
        }

        let shared_state = Shared::new(&config)?;
        let rt = Runtime::build(config.clone(), revision, shared_state, &provider).await?;
        let server = Server { swap: rt.launch()? };
        server.spawn_sampler();

        let mut tasks = JoinSet::new();
        if config.admin.is_some() {
            let swap = server.swap.clone();
            tasks.spawn(async move {
                if let Err(e) = admin::run(swap, config, Some(config_path)).await {
                    tracing::error!(error = %e, "admin listener exited");
                }
            });
        }

        tracing::info!("proxy started");
        let exited = tokio::select! {
            _ = shutdown_signal() => None,
            exited = tasks.join_next(), if !tasks.is_empty() => Some(exited),
        };
        let rt = server.swap.load_full();
        rt.shared.listeners.shutdown();
        if let Some(exited) = exited {
            let reason = match exited {
                Some(Err(err)) => format!("the admin task failed: {err}"),
                _ => "the admin task exited unexpectedly".to_string(),
            };
            tracing::error!(reason = %reason, "shutting down");
            return Err(ProxyError::unavailable(Stage::Accept, reason));
        }
        let grace = rt.raw.server.shutdown_grace;
        tracing::info!(grace = ?grace, "shutdown signal received; draining");
        rt.shared.drain(grace).await;
        Ok(())
    }

    fn spawn_sampler(&self) {
        let swap = self.swap.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SAMPLE_INTERVAL);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            interval.tick().await;
            let mut previous = swap.load().reading();
            let mut since_log = 0u32;
            loop {
                interval.tick().await;
                let rt = swap.load();
                let current = rt.reading();
                rt.shared
                    .metrics
                    .push_sample(current.delta_since(&previous));
                previous = current;
                since_log += 1;
                if since_log == SAMPLES_PER_LOG {
                    since_log = 0;
                    tracing::info!(
                        cache_hits = current.cache.hits,
                        cache_misses = current.cache.misses,
                        hit_rate_pct = current.cache.hit_rate_pct(),
                        active_connections = current.active_connections,
                        "metrics"
                    );
                }
            }
        });
    }
}

impl Shared {
    async fn drain(&self, grace: Duration) {
        let deadline = tokio::time::sleep(grace);
        tokio::pin!(deadline);
        let mut tick = tokio::time::interval(DRAIN_POLL);
        loop {
            tokio::select! {
                _ = &mut deadline => {
                    let active = self.metrics.active_connections.load(Ordering::Relaxed);
                    if active > 0 {
                        tracing::warn!(active, "grace elapsed; forcing shutdown with live connections");
                    }
                    return;
                }
                _ = tick.tick() => {
                    if self.metrics.active_connections.load(Ordering::Relaxed) <= 0 {
                        tracing::info!("all connections drained");
                        return;
                    }
                }
            }
        }
    }
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
