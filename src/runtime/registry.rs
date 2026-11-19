/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::cmp::{Ordering as CmpOrdering, Reverse};
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::slice;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime};

use ahash::{AHashMap, RandomState};
use parking_lot::Mutex;
use tokio::sync::watch;

use crate::config::Protocol;
use crate::net::stream::TlsInfo;
use crate::route::key::RoutingKey;
use crate::runtime::{DestId, ListenerId};

const REGISTRY_SHARDS: usize = 32;
const MAX_LOGIN_HOLD: Duration = Duration::from_secs(120);

pub type Kick = watch::Receiver<bool>;

pub struct NewConn {
    pub key: Option<RoutingKey>,
    pub protocol: Protocol,
    pub listener: ListenerId,
    pub client: SocketAddr,
    pub dest: DestId,
    pub backend: SocketAddr,
    pub client_tls: Option<TlsInfo>,
    pub backend_tls: Option<TlsInfo>,
}

pub struct ConnInfo {
    pub id: u64,
    pub key: Option<RoutingKey>,
    pub protocol: Protocol,
    pub listener: ListenerId,
    pub client: SocketAddr,
    pub dest: DestId,
    pub backend: SocketAddr,
    pub client_tls: Option<TlsInfo>,
    pub backend_tls: Option<TlsInfo>,
    pub started_at: SystemTime,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
}

#[derive(Default, Clone, Copy)]
pub struct ConnFilter<'a> {
    pub identifier_prefix: Option<&'a str>,
    pub protocol: Option<Protocol>,
    pub dest: Option<DestId>,
    pub listener: Option<ListenerId>,
}

impl ConnFilter<'_> {
    fn matches_key(&self, key: Option<&str>) -> bool {
        match (self.identifier_prefix, key) {
            (None, _) => true,
            (Some(prefix), Some(key)) => key.starts_with(prefix),
            (Some(_), None) => false,
        }
    }

    fn matches_info(&self, info: &ConnInfo) -> bool {
        self.protocol.is_none_or(|p| p == info.protocol)
            && self.dest.is_none_or(|d| d == info.dest)
            && self.listener.is_none_or(|l| l == info.listener)
    }
}

pub struct ConnPage {
    pub total: usize,
    pub items: Vec<Arc<ConnInfo>>,
    pub next_cursor: Option<u64>,
}

pub struct TopIdentifier {
    pub identifier: Arc<str>,
    pub sessions: usize,
}

#[derive(Default)]
pub struct SessionSummary {
    pub total: usize,
    pub by_protocol: [usize; Protocol::COUNT],
    pub by_listener: Vec<usize>,
    pub by_dest: Vec<usize>,
    pub top_identifiers: Vec<TopIdentifier>,
}

impl SessionSummary {
    pub fn listener(&self, id: ListenerId) -> usize {
        self.by_listener.get(id.index()).copied().unwrap_or(0)
    }

    pub fn dest(&self, id: DestId) -> usize {
        self.by_dest.get(id.index()).copied().unwrap_or(0)
    }

    fn count(&mut self, info: &ConnInfo) {
        self.total += 1;
        if let Some(n) = self.by_protocol.get_mut(info.protocol.index()) {
            *n += 1;
        }
        bump_slot(&mut self.by_listener, info.listener.index());
        bump_slot(&mut self.by_dest, info.dest.index());
    }
}

fn bump_slot(slots: &mut Vec<usize>, index: usize) {
    if slots.len() <= index {
        slots.resize(index + 1, 0);
    }
    if let Some(n) = slots.get_mut(index) {
        *n += 1;
    }
}

pub struct DelayInfo {
    pub identifier: Arc<str>,
    pub until: Instant,
    pub waiting: usize,
}

struct LiveConn {
    id: u64,
    cancel: watch::Sender<bool>,
    info: Arc<ConnInfo>,
}

impl LiveConn {
    fn kick(&self) {
        let _ = self.cancel.send(true);
    }
}

struct LoginDelay {
    until: Instant,
    changed: watch::Sender<()>,
}

impl LoginDelay {
    fn info(&self, identifier: &Arc<str>) -> DelayInfo {
        DelayInfo {
            identifier: identifier.clone(),
            until: self.until,
            waiting: self.changed.receiver_count(),
        }
    }
}

#[derive(Default)]
struct Shard {
    live: HashMap<Arc<str>, Vec<LiveConn>>,
    anonymous: AHashMap<u64, LiveConn>,
    delays: HashMap<Arc<str>, LoginDelay>,
}

impl Shard {
    fn buckets(&self) -> impl Iterator<Item = (Option<&Arc<str>>, &[LiveConn])> {
        self.live
            .iter()
            .map(|(key, conns)| (Some(key), conns.as_slice()))
            .chain(
                self.anonymous
                    .values()
                    .map(|conn| (None, slice::from_ref(conn))),
            )
    }
}

struct Inner {
    shards: Box<[Mutex<Shard>]>,
    hasher: RandomState,
    seq: AtomicU64,
    live: AtomicUsize,
}

impl Inner {
    fn shard(&self, idx: usize) -> &Mutex<Shard> {
        &self.shards[idx % self.shards.len()]
    }

    fn key_shard(&self, identifier: &str) -> usize {
        let hash = self.hasher.hash_one(identifier);
        (hash % self.shards.len() as u64) as usize
    }

    fn id_shard(&self, id: u64) -> usize {
        (id % self.shards.len() as u64) as usize
    }
}

#[derive(Clone)]
pub struct ConnRegistry {
    inner: Arc<Inner>,
}

impl Default for ConnRegistry {
    fn default() -> Self {
        ConnRegistry {
            inner: Arc::new(Inner {
                shards: (0..REGISTRY_SHARDS)
                    .map(|_| Mutex::new(Shard::default()))
                    .collect(),
                hasher: RandomState::new(),
                seq: AtomicU64::new(0),
                live: AtomicUsize::new(0),
            }),
        }
    }
}

pub struct ConnGuard {
    inner: Arc<Inner>,
    shard_idx: usize,
    rx: Kick,
    info: Arc<ConnInfo>,
}

struct OldestFirst(Arc<ConnInfo>);

impl PartialEq for OldestFirst {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

impl Eq for OldestFirst {}

impl PartialOrd for OldestFirst {
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

impl Ord for OldestFirst {
    fn cmp(&self, other: &Self) -> CmpOrdering {
        other.0.id.cmp(&self.0.id)
    }
}

impl ConnRegistry {
    pub fn register(&self, conn: NewConn) -> ConnGuard {
        let (cancel, _) = watch::channel(false);
        self.register_with(conn, cancel)
    }

    pub fn register_with(&self, conn: NewConn, cancel: watch::Sender<bool>) -> ConnGuard {
        let id = self.inner.seq.fetch_add(1, Ordering::Relaxed);
        let info = Arc::new(ConnInfo {
            id,
            key: conn.key,
            protocol: conn.protocol,
            listener: conn.listener,
            client: conn.client,
            dest: conn.dest,
            backend: conn.backend,
            client_tls: conn.client_tls,
            backend_tls: conn.backend_tls,
            started_at: SystemTime::now(),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
        });
        let rx = cancel.subscribe();
        let conn = LiveConn {
            id,
            cancel,
            info: info.clone(),
        };
        let shard_idx = match &info.key {
            Some(key) => {
                let idx = self.inner.key_shard(key.as_str());
                self.inner
                    .shard(idx)
                    .lock()
                    .live
                    .entry(key.shared().clone())
                    .or_default()
                    .push(conn);
                idx
            }
            None => {
                let idx = self.inner.id_shard(id);
                self.inner.shard(idx).lock().anonymous.insert(id, conn);
                idx
            }
        };
        self.inner.live.fetch_add(1, Ordering::Relaxed);
        ConnGuard {
            inner: self.inner.clone(),
            shard_idx,
            rx,
            info,
        }
    }

    pub fn session_count(&self) -> usize {
        self.inner.live.load(Ordering::Relaxed)
    }

    pub fn kick(&self, identifier: &str) -> usize {
        let shard = self.inner.shard(self.inner.key_shard(identifier)).lock();
        let Some(conns) = shard.live.get(identifier) else {
            return 0;
        };
        conns.iter().for_each(LiveConn::kick);
        conns.len()
    }

    pub fn kick_ids(&self, ids: &[u64]) -> usize {
        let mut wanted = ids.to_vec();
        wanted.sort_unstable();
        wanted.dedup();
        let mut kicked = 0;
        for shard in self.inner.shards.iter() {
            let shard = shard.lock();
            for conn in shard.buckets().flat_map(|(_, conns)| conns) {
                if wanted.binary_search(&conn.id).is_ok() {
                    conn.kick();
                    kicked += 1;
                }
            }
        }
        kicked
    }

    pub fn list(&self, filter: &ConnFilter<'_>, cursor: Option<u64>, limit: usize) -> ConnPage {
        let mut total = 0;
        let mut older = 0;
        let mut page: BinaryHeap<OldestFirst> = BinaryHeap::new();
        for shard in self.inner.shards.iter() {
            let shard = shard.lock();
            let matching = shard
                .buckets()
                .filter(|(key, _)| filter.matches_key(key.map(|k| &**k)))
                .flat_map(|(_, conns)| conns)
                .map(|conn| &conn.info)
                .filter(|info| filter.matches_info(info));
            for info in matching {
                total += 1;
                if cursor.is_some_and(|c| info.id >= c) {
                    continue;
                }
                older += 1;
                if page.len() < limit {
                    page.push(OldestFirst(info.clone()));
                } else if let Some(mut oldest) = page.peek_mut()
                    && oldest.0.id < info.id
                {
                    *oldest = OldestFirst(info.clone());
                }
            }
        }
        let items: Vec<Arc<ConnInfo>> = page
            .into_sorted_vec()
            .into_iter()
            .map(|entry| entry.0)
            .collect();
        let next_cursor = (older > items.len())
            .then(|| items.last().map(|info| info.id))
            .flatten();
        ConnPage {
            total,
            items,
            next_cursor,
        }
    }

    pub fn summary(&self, filter: &ConnFilter<'_>, top: usize) -> SessionSummary {
        let mut summary = SessionSummary::default();
        let mut ranking: BinaryHeap<Reverse<(usize, Arc<str>)>> = BinaryHeap::new();
        for shard in self.inner.shards.iter() {
            let shard = shard.lock();
            for (key, conns) in shard.buckets() {
                if !filter.matches_key(key.map(|k| &**k)) {
                    continue;
                }
                let mut sessions = 0;
                for info in conns.iter().map(|conn| &*conn.info) {
                    if filter.matches_info(info) {
                        summary.count(info);
                        sessions += 1;
                    }
                }
                let Some(key) = key else {
                    continue;
                };
                if sessions == 0 || top == 0 {
                    continue;
                }
                if ranking.len() < top {
                    ranking.push(Reverse((sessions, key.clone())));
                } else if let Some(mut lowest) = ranking.peek_mut()
                    && lowest.0.0 < sessions
                {
                    *lowest = Reverse((sessions, key.clone()));
                }
            }
        }
        summary.top_identifiers = ranking
            .into_sorted_vec()
            .into_iter()
            .map(|Reverse((sessions, identifier))| TopIdentifier {
                identifier,
                sessions,
            })
            .collect();
        summary
    }

    pub fn set_delay(&self, identifier: &str, until: Instant) {
        let mut shard = self.inner.shard(self.inner.key_shard(identifier)).lock();
        let now = Instant::now();
        shard.delays.retain(|_, delay| delay.until > now);
        match shard.delays.get_mut(identifier) {
            Some(delay) => {
                delay.until = until;
                delay.changed.send_replace(());
            }
            None => {
                shard.delays.insert(
                    Arc::from(identifier),
                    LoginDelay {
                        until,
                        changed: watch::Sender::new(()),
                    },
                );
            }
        }
    }

    fn delay(&self, identifier: &str) -> Option<(Instant, watch::Receiver<()>)> {
        let mut shard = self.inner.shard(self.inner.key_shard(identifier)).lock();
        let delay = shard.delays.get(identifier)?;
        if Instant::now() < delay.until {
            return Some((delay.until, delay.changed.subscribe()));
        }
        shard.delays.remove(identifier);
        None
    }

    pub fn delay_info(&self, identifier: &str) -> Option<DelayInfo> {
        let shard = self.inner.shard(self.inner.key_shard(identifier)).lock();
        let (key, delay) = shard.delays.get_key_value(identifier)?;
        (delay.until > Instant::now()).then(|| delay.info(key))
    }

    pub fn delays(&self) -> Vec<DelayInfo> {
        let now = Instant::now();
        let mut out = Vec::new();
        for shard in self.inner.shards.iter() {
            let shard = shard.lock();
            out.extend(
                shard
                    .delays
                    .iter()
                    .filter(|(_, delay)| delay.until > now)
                    .map(|(key, delay)| delay.info(key)),
            );
        }
        out
    }

    pub fn release_delay(&self, identifier: &str) -> bool {
        self.inner
            .shard(self.inner.key_shard(identifier))
            .lock()
            .delays
            .remove(identifier)
            .is_some_and(|delay| delay.until > Instant::now())
    }

    pub fn release_all_delays(&self) {
        for shard in self.inner.shards.iter() {
            shard.lock().delays.clear();
        }
    }

    pub async fn hold_login(&self, identifier: &str) {
        let deadline = Instant::now() + MAX_LOGIN_HOLD;
        while let Some((until, mut changed)) = self.delay(identifier) {
            let wake = until.min(deadline);
            if Instant::now() >= wake {
                break;
            }
            tracing::debug!(
                hold_ms = wake.saturating_duration_since(Instant::now()).as_millis() as u64,
                "holding login (delay_until)"
            );
            tokio::select! {
                _ = tokio::time::sleep_until(wake.into()) => {}
                _ = changed.changed() => {}
            }
        }
    }
}

impl ConnGuard {
    pub fn cancel(&self) -> Kick {
        self.rx.clone()
    }

    pub fn info(&self) -> &Arc<ConnInfo> {
        &self.info
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let id = self.info.id;
        let mut shard = self.inner.shard(self.shard_idx).lock();
        match &self.info.key {
            Some(key) => {
                if let Some(conns) = shard.live.get_mut(key.as_str()) {
                    conns.retain(|c| c.id != id);
                    if conns.is_empty() {
                        shard.live.remove(key.as_str());
                    }
                }
            }
            None => {
                shard.anonymous.remove(&id);
            }
        }
        drop(shard);
        self.inner.live.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/runtime/registry/tests.rs"]
mod tests;
