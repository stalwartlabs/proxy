/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod store;

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ahash::AHashSet;
use moka::future::Cache;
use moka::policy::Expiry;

use crate::config::{Config, MappingConfig, MappingSource, Normalize};
use crate::error::{ProxyError, Result};
use store::MappingStore;
use store::file::FileStore;
use store::redis::RedisStore;
use store::sql::SqlStore;

type Store = Arc<MappingStore>;

pub fn normalize_key(id: &str, normalize: Normalize) -> String {
    match normalize {
        Normalize::None => id.to_string(),
        Normalize::Lowercase => id.to_lowercase(),
    }
}

pub fn master_account<'a>(id: &'a str, separators: &[String]) -> &'a str {
    let mut cut = id.len();
    for sep in separators {
        if sep.is_empty() {
            continue;
        }
        if let Some(pos) = id.find(sep.as_str()) {
            cut = cut.min(pos);
        }
    }
    &id[..cut]
}

#[derive(Clone)]
enum Route {
    Mapped(Arc<str>),
    Default,
    Transient,
}

impl Route {
    fn dest(&self, default: &Arc<str>) -> Arc<str> {
        match self {
            Route::Mapped(d) => d.clone(),
            Route::Default | Route::Transient => default.clone(),
        }
    }
}

const TRANSIENT_TTL: Duration = Duration::from_secs(5);

struct TtlExpiry {
    positive: Duration,
    negative: Duration,
    transient: Duration,
}

impl TtlExpiry {
    fn ttl(&self, value: &Route) -> Duration {
        match value {
            Route::Mapped(_) => self.positive,
            Route::Default => self.negative,
            Route::Transient => self.transient,
        }
    }
}

impl Expiry<Box<str>, Route> for TtlExpiry {
    fn expire_after_create(
        &self,
        _key: &Box<str>,
        value: &Route,
        _created_at: std::time::Instant,
    ) -> Option<Duration> {
        Some(self.ttl(value))
    }

    fn expire_after_update(
        &self,
        _key: &Box<str>,
        value: &Route,
        _updated_at: std::time::Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(self.ttl(value))
    }
}

#[derive(Default)]
pub struct RouterStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

pub struct MappingDiagnosis {
    pub normalized: String,
    pub destination: String,
    pub routed_to_default: bool,
    pub cached: bool,
}

pub struct Router {
    cache: Cache<Box<str>, Route>,
    store: Store,
    default_destination: Arc<str>,
    valid_destinations: AHashSet<Box<str>>,
    normalize: Normalize,
    lookup_timeout: Duration,
    pub stats: RouterStats,
}

impl Router {
    pub async fn build(config: &Config, valid_destinations: Vec<String>) -> Result<Self> {
        let valid: AHashSet<Box<str>> = valid_destinations
            .iter()
            .map(|s| s.as_str().into())
            .collect();
        let store = build_store(&config.mapping, valid_destinations).await?;
        Ok(Self::with_store(
            &config.mapping,
            store,
            config.routing.default_destination.as_str().into(),
            valid,
        ))
    }

    pub fn with_store(
        mapping: &MappingConfig,
        store: Store,
        default_destination: Arc<str>,
        valid_destinations: AHashSet<Box<str>>,
    ) -> Self {
        let expiry = TtlExpiry {
            positive: mapping.positive_ttl,
            negative: mapping.negative_ttl,
            transient: TRANSIENT_TTL.min(mapping.negative_ttl),
        };
        let cache = Cache::builder()
            .max_capacity(mapping.cache_max_entries)
            .expire_after(expiry)
            .build();
        Router {
            cache,
            store,
            default_destination,
            valid_destinations,
            normalize: mapping.normalize,
            lookup_timeout: mapping.lookup_timeout,
            stats: RouterStats::default(),
        }
    }

    pub async fn resolve(&self, identifier: Option<&str>) -> Arc<str> {
        let key: Cow<'_, str> = match identifier {
            Some(id) => match self.normalize {
                Normalize::None => Cow::Borrowed(id),
                Normalize::Lowercase => Cow::Owned(id.to_lowercase()),
            },
            None => return self.default_destination.clone(),
        };

        if let Some(hit) = self.cache.get(key.as_ref()).await {
            self.stats.hits.fetch_add(1, Ordering::Relaxed);
            return hit.dest(&self.default_destination);
        }
        self.stats.misses.fetch_add(1, Ordering::Relaxed);

        let key = key.into_owned();
        let store = self.store.clone();
        let valid = &self.valid_destinations;
        let lookup_timeout = self.lookup_timeout;
        let lookup_key = key.clone();
        let init = async move {
            let route = match tokio::time::timeout(lookup_timeout, store.lookup(&lookup_key)).await
            {
                Ok(Ok(Some(dest))) => {
                    if !valid.is_empty() && !valid.contains(dest.as_str()) {
                        tracing::warn!(
                            destination = %dest,
                            "mapping store returned an undeclared destination; routing to default"
                        );
                        Route::Default
                    } else {
                        Route::Mapped(Arc::from(dest))
                    }
                }
                Ok(Ok(None)) => Route::Default,
                Ok(Err(e)) => {
                    tracing::warn!(error = %e, "mapping store lookup failed; routing to default");
                    Route::Transient
                }
                Err(_) => {
                    tracing::warn!("mapping store lookup timed out; routing to default");
                    Route::Transient
                }
            };
            Ok::<Route, std::convert::Infallible>(route)
        };

        let route = self
            .cache
            .try_get_with(key.into_boxed_str(), init)
            .await
            .unwrap_or(Route::Transient);
        route.dest(&self.default_destination)
    }

    pub fn normalize(&self, identifier: &str) -> String {
        normalize_key(identifier, self.normalize)
    }

    pub async fn invalidate(&self, identifier: &str) {
        let key = normalize_key(identifier, self.normalize);
        self.cache.invalidate(key.as_str()).await;
    }

    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    pub async fn reload(&self) -> Result<()> {
        self.store.reload().await
    }

    pub fn mapped_destinations(&self) -> Vec<String> {
        self.store.mapped_destinations()
    }

    pub fn store_writable(&self) -> bool {
        self.store.writable()
    }

    pub fn is_valid_destination(&self, dest: &str) -> bool {
        self.valid_destinations.is_empty() || self.valid_destinations.contains(dest)
    }

    pub async fn upsert(&self, identifier: &str, dest: &str) -> Result<()> {
        if !self.is_valid_destination(dest) {
            return Err(ProxyError::config(format!("unknown destination {dest:?}")));
        }
        let key = normalize_key(identifier, self.normalize);
        self.store.upsert(&key, dest).await?;
        self.cache.invalidate(key.as_str()).await;
        Ok(())
    }

    pub async fn remove(&self, identifier: &str) -> Result<bool> {
        let key = normalize_key(identifier, self.normalize);
        let existed = self.store.remove(&key).await?;
        self.cache.invalidate(key.as_str()).await;
        Ok(existed)
    }

    pub async fn diagnose(&self, identifier: &str) -> MappingDiagnosis {
        let key = normalize_key(identifier, self.normalize);
        let cached = self.cache.get(key.as_str()).await.is_some();
        let destination = self.resolve(Some(identifier)).await;
        let routed_to_default = destination == self.default_destination;
        MappingDiagnosis {
            normalized: key,
            destination: destination.to_string(),
            routed_to_default,
            cached,
        }
    }

    pub fn cache_entries(&self) -> u64 {
        self.cache.entry_count()
    }

    #[cfg(test)]
    pub async fn cache_entry_count(&self) -> u64 {
        self.cache.run_pending_tasks().await;
        self.cache.entry_count()
    }
}

async fn build_store(mapping: &MappingConfig, valid_destinations: Vec<String>) -> Result<Store> {
    let valid = valid_destinations.into_iter().collect();
    let store =
        match mapping.source {
            MappingSource::File => {
                let cfg = mapping.file.as_ref().ok_or_else(|| {
                    ProxyError::config("mapping.source=file requires [mapping.file]")
                })?;
                MappingStore::File(FileStore::open(cfg.path.clone(), mapping.normalize, valid)?)
            }
            MappingSource::Redis => {
                let cfg = mapping.redis.as_ref().ok_or_else(|| {
                    ProxyError::config("mapping.source=redis requires [mapping.redis]")
                })?;
                MappingStore::Redis(RedisStore::connect(cfg).await?)
            }
            MappingSource::Sql => {
                let cfg = mapping.sql.as_ref().ok_or_else(|| {
                    ProxyError::config("mapping.source=sql requires [mapping.sql]")
                })?;
                MappingStore::Sql(SqlStore::connect(cfg).await?)
            }
        };
    Ok(Arc::new(store))
}

#[cfg(test)]
mod tests {
    use super::master_account;

    #[test]
    fn master_account_splits_on_first_separator() {
        let seps = vec!["%".to_string()];
        assert_eq!(
            master_account("user@example.com%admin", &seps),
            "user@example.com"
        );
        assert_eq!(
            master_account("user@example.com", &seps),
            "user@example.com"
        );
    }

    #[test]
    fn master_account_tries_multiple_separators() {
        let seps = vec!["%".to_string(), "*".to_string()];
        assert_eq!(master_account("alice*master", &seps), "alice");
        assert_eq!(master_account("bob%root", &seps), "bob");
        assert_eq!(master_account("a%b*c", &seps), "a");
    }

    #[test]
    fn master_account_ignores_empty_separator() {
        let seps = vec![String::new()];
        assert_eq!(
            master_account("user@example.com", &seps),
            "user@example.com"
        );
    }
}
