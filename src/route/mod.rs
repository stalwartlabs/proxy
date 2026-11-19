/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod key;
pub mod store;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ahash::{AHashMap, AHashSet};
use quick_cache::sync::{Cache, DefaultLifecycle};
use quick_cache::{DefaultHashBuilder, Weighter};

#[cfg(all(test, proxy_tests))]
use crate::config::Normalize;
use crate::config::{Config, MappingConfig};
use crate::error::{ProxyError, Result, Side, Stage};
use crate::runtime::health::{Clock, Millis};
use crate::runtime::metrics::CacheCounters;
use crate::runtime::{DestId, IdTable};
use key::RoutingKey;
use store::file::PendingMappings;
use store::{DestCounts, MappingStore, Page, Stored, Upsert};

type Store = Arc<MappingStore>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Route {
    Mapped(DestId),
    Default,
    Transient,
}

const _: () = assert!(size_of::<Route>() <= 4);

pub const TRANSIENT_TTL: Duration = Duration::from_secs(5);
pub const MAX_PAGE_SIZE: usize = 1000;
const CACHE_ENTRY_OVERHEAD: u64 = 192;
const CACHE_KEY_ESTIMATE: u64 = 64;

#[derive(Clone, Copy, Debug)]
struct Cached {
    route: Route,
    deadline: Millis,
}

const _: () = assert!(size_of::<Cached>() <= 16);

impl Cached {
    fn live(&self, now: Millis) -> bool {
        self.deadline > now
    }
}

#[derive(Clone, Copy)]
enum CacheWeight {
    Entries,
    Bytes,
}

#[derive(Clone, Copy)]
struct CacheBounds {
    items: u64,
    weight: u64,
    weighter: CacheWeight,
}

impl CacheBounds {
    const NONE: CacheBounds = CacheBounds {
        items: 0,
        weight: 0,
        weighter: CacheWeight::Entries,
    };

    fn for_mapping(mapping: &MappingConfig) -> Self {
        match mapping.cache_max_bytes {
            Some(bytes) => CacheBounds {
                items: bytes / (CACHE_ENTRY_OVERHEAD + CACHE_KEY_ESTIMATE),
                weight: bytes,
                weighter: CacheWeight::Bytes,
            },
            None => CacheBounds {
                items: mapping.cache_max_entries,
                weight: mapping.cache_max_entries,
                weighter: CacheWeight::Entries,
            },
        }
    }
}

impl Weighter<Arc<str>, Cached> for CacheWeight {
    fn weight(&self, key: &Arc<str>, _: &Cached) -> u64 {
        match self {
            CacheWeight::Entries => 1,
            CacheWeight::Bytes => u64::try_from(key.len())
                .unwrap_or(u64::MAX)
                .saturating_add(CACHE_ENTRY_OVERHEAD),
        }
    }
}

type RouteCache = Cache<Arc<str>, Cached, CacheWeight>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CacheState {
    Miss,
    Positive,
    Negative,
    Transient,
}

pub struct Inspection {
    pub store: Result<Option<Arc<str>>>,
    pub route: Route,
    pub cache: CacheState,
    pub ttl_remaining: Option<Duration>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Upserted {
    pub created: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BatchResult {
    pub upserted: usize,
    pub created: u64,
}

#[derive(Clone, Copy)]
struct TtlExpiry {
    positive: Duration,
    negative: Duration,
    transient: Duration,
}

impl TtlExpiry {
    const NONE: TtlExpiry = TtlExpiry {
        positive: Duration::ZERO,
        negative: Duration::ZERO,
        transient: Duration::ZERO,
    };

    fn for_mapping(mapping: &MappingConfig) -> Self {
        TtlExpiry {
            positive: mapping.positive_ttl,
            negative: mapping.negative_ttl,
            transient: TRANSIENT_TTL.min(mapping.negative_ttl),
        }
    }

    fn ttl(&self, value: &Route) -> Duration {
        match value {
            Route::Mapped(_) => self.positive,
            Route::Default => self.negative,
            Route::Transient => self.transient,
        }
    }
}

#[derive(Default)]
pub struct RouterStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl RouterStats {
    pub fn snapshot(&self) -> CacheCounters {
        CacheCounters {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
}

pub struct Router {
    cache: RouteCache,
    expiry: TtlExpiry,
    clock: Clock,
    store: Store,
    ids: Arc<IdTable>,
    #[cfg(all(test, proxy_tests))]
    default_destination: Arc<str>,
    valid_destinations: AHashSet<Box<str>>,
    #[cfg(all(test, proxy_tests))]
    normalize: Normalize,
    lookup_timeout: Duration,
    pub stats: RouterStats,
}

impl Router {
    pub async fn build(
        config: &Config,
        dest_names: &AHashMap<Box<str>, DestId>,
        ids: Arc<IdTable>,
        clock: Clock,
    ) -> Result<Self> {
        let valid: AHashSet<Box<str>> = dest_names.keys().cloned().collect();
        let (store, expiry, bounds, lookup_timeout) = match &config.mapping {
            Some(mapping) => (
                Arc::new(MappingStore::build(mapping, dest_names).await?),
                TtlExpiry::for_mapping(mapping),
                CacheBounds::for_mapping(mapping),
                mapping.lookup_timeout,
            ),
            None => (
                Arc::new(MappingStore::Empty),
                TtlExpiry::NONE,
                CacheBounds::NONE,
                TRANSIENT_TTL,
            ),
        };
        let cache = RouteCache::with(
            usize::try_from(bounds.items).unwrap_or(usize::MAX),
            bounds.weight,
            bounds.weighter,
            DefaultHashBuilder::default(),
            DefaultLifecycle::default(),
        );
        Ok(Router {
            cache,
            expiry,
            clock,
            store,
            ids,
            #[cfg(all(test, proxy_tests))]
            default_destination: config
                .routing
                .as_ref()
                .map_or("", |routing| routing.default_destination.as_str())
                .into(),
            valid_destinations: valid,
            #[cfg(all(test, proxy_tests))]
            normalize: config
                .mapping
                .as_ref()
                .map_or(Normalize::None, |mapping| mapping.normalize),
            lookup_timeout,
            stats: RouterStats::default(),
        })
    }

    pub async fn route(&self, key: &RoutingKey) -> Route {
        self.lookup(key, self.route_from_store(key)).await
    }

    async fn lookup(&self, key: &RoutingKey, load: impl Future<Output = Route>) -> Route {
        let now = self.clock.now();
        match self.cache.get(key.as_str()) {
            Some(hit) if hit.live(now) => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return hit.route;
            }
            Some(_) => {
                self.cache
                    .remove_if(key.as_str(), |cached| !cached.live(now));
            }
            None => {}
        }
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        let guard = match self.cache.get_value_or_guard_async(key.shared()).await {
            Ok(cached) => return cached.route,
            Err(guard) => guard,
        };
        let route = load.await;
        let deadline = self.clock.now().saturating_add(self.expiry.ttl(&route));
        let _ = guard.insert(Cached { route, deadline });
        route
    }

    async fn bounded<T>(&self, op: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::time::timeout(self.lookup_timeout, op)
            .await
            .map_err(|_| ProxyError::timeout(Stage::Store, Side::Backend))?
    }

    async fn route_from_store(&self, key: &RoutingKey) -> Route {
        match self.bounded(self.store.lookup(key.as_str())).await {
            Ok(Some(stored)) => self.mapped(&stored),
            Ok(None) => Route::Default,
            Err(e) => {
                tracing::warn!(error = %e, "mapping store lookup failed; routing to default");
                Route::Transient
            }
        }
    }

    fn mapped(&self, stored: &Stored) -> Route {
        let dest = match stored {
            Stored::Dest(id) => return Route::Mapped(*id),
            Stored::Name(dest) => &**dest,
        };
        let declared = self.is_valid_destination(dest);
        match self.ids.dest_id(dest) {
            Some(id) if declared => Route::Mapped(id),
            _ => {
                tracing::warn!(
                    destination = %dest,
                    "mapping store returned an undeclared destination; routing to default"
                );
                Route::Default
            }
        }
    }

    pub async fn inspect(&self, key: &RoutingKey) -> Inspection {
        let now = self.clock.now();
        let cached = self
            .cache
            .peek(key.as_str())
            .filter(|cached| cached.live(now));
        let stored = self.bounded(self.store.lookup(key.as_str())).await;
        let fresh = match &stored {
            Ok(Some(stored)) => self.mapped(stored),
            Ok(None) => Route::Default,
            Err(_) => Route::Transient,
        };
        let store = stored.map(|stored| {
            stored.and_then(|stored| match stored {
                Stored::Dest(id) => self.ids.dest_name(id),
                Stored::Name(name) => Some(Arc::from(name)),
            })
        });
        let Some(cached) = cached else {
            return Inspection {
                store,
                route: fresh,
                cache: CacheState::Miss,
                ttl_remaining: None,
            };
        };
        Inspection {
            store,
            route: cached.route,
            cache: match cached.route {
                Route::Mapped(_) => CacheState::Positive,
                Route::Default => CacheState::Negative,
                Route::Transient => CacheState::Transient,
            },
            ttl_remaining: Some(Duration::from_millis(
                cached.deadline.0.saturating_sub(now.0),
            )),
        }
    }

    fn declared_name(&self, dest: DestId) -> Result<Arc<str>> {
        self.ids
            .dest_name(dest)
            .filter(|name| self.is_valid_destination(name))
            .ok_or_else(|| ProxyError::config("unknown destination"))
    }

    pub async fn upsert(&self, key: &RoutingKey, dest: DestId) -> Result<Upserted> {
        let entry = Upsert {
            key: key.as_str(),
            dest,
            name: self.declared_name(dest)?,
        };
        let created = self.store.upsert_many(std::slice::from_ref(&entry)).await?;
        self.cache.remove(key.as_str());
        Ok(Upserted {
            created: created > 0,
        })
    }

    pub async fn upsert_many(&self, entries: &[(RoutingKey, DestId)]) -> Result<BatchResult> {
        let mut names: AHashMap<DestId, Arc<str>> = AHashMap::new();
        let mut batch = Vec::with_capacity(entries.len());
        for (key, dest) in entries {
            let name = match names.get(dest) {
                Some(name) => name.clone(),
                None => {
                    let name = self.declared_name(*dest)?;
                    names.insert(*dest, name.clone());
                    name
                }
            };
            batch.push(Upsert {
                key: key.as_str(),
                dest: *dest,
                name,
            });
        }
        let created = self.store.upsert_many(&batch).await?;
        for (key, _) in entries {
            self.cache.remove(key.as_str());
        }
        Ok(BatchResult {
            upserted: entries.len(),
            created,
        })
    }

    pub async fn remove(&self, key: &RoutingKey) -> Result<bool> {
        let existed = self.store.remove(key.as_str()).await?;
        self.cache.remove(key.as_str());
        Ok(existed)
    }

    pub fn invalidate(&self, key: &RoutingKey) {
        self.cache.remove(key.as_str());
    }

    pub fn store_listable(&self) -> bool {
        self.store.listable()
    }

    pub async fn list(&self, prefix: &str, cursor: Option<&str>, limit: usize) -> Result<Page> {
        let limit = limit.clamp(1, MAX_PAGE_SIZE);
        self.bounded(self.store.list(prefix, cursor, limit)).await
    }

    pub async fn count(&self) -> Result<Option<u64>> {
        self.bounded(self.store.count()).await
    }

    pub async fn count_by_destination(&self) -> Result<Option<DestCounts>> {
        self.bounded(self.store.count_by_destination(&self.ids))
            .await
    }

    pub fn invalidate_all(&self) {
        self.cache.clear();
    }

    pub async fn reload(&self) -> Result<()> {
        self.store.reload().await
    }

    pub async fn prepare_reload(&self) -> Result<Option<PendingMappings>> {
        self.store.prepare_reload().await
    }

    pub fn install(&self, pending: PendingMappings) {
        if self.store.install(pending) {
            self.cache.clear();
        }
    }

    pub fn mapped_destinations(&self) -> Vec<Arc<str>> {
        self.store.mapped_destinations()
    }

    pub fn store_writable(&self) -> bool {
        self.store.writable()
    }

    pub fn is_valid_destination(&self, dest: &str) -> bool {
        self.valid_destinations.is_empty() || self.valid_destinations.contains(dest)
    }

    pub fn cache_entries(&self) -> u64 {
        u64::try_from(self.cache.len()).unwrap_or(u64::MAX)
    }
}


#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/route/tests.rs"]
mod tests;

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/route/test_support.rs"]
mod test_support;
