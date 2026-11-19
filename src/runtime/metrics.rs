/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

use crate::runtime::ListenerId;
use crate::runtime::health::Millis;

pub const SERIES_LEN: usize = 360;
pub const EVENTS_LEN: usize = 512;
pub const SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
const COUNTER_CHUNK: usize = 64;
const COUNTER_CHUNKS: usize = (u16::MAX as usize + 1) / COUNTER_CHUNK;

type CounterChunk = [ListenerCounters; COUNTER_CHUNK];

#[derive(Default)]
#[repr(align(64))]
pub struct ListenerCounters {
    pub accepted: AtomicU64,
    pub rejected_limit: AtomicU64,
    pub auth_ok: AtomicU64,
    pub auth_rejected: AtomicU64,
    pub backend_failures: AtomicU64,
}

impl ListenerCounters {
    pub fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn add_to(&self, totals: &mut Totals) {
        totals.accepted += self.accepted.load(Ordering::Relaxed);
        totals.rejected_limit += self.rejected_limit.load(Ordering::Relaxed);
        totals.auth_ok += self.auth_ok.load(Ordering::Relaxed);
        totals.auth_rejected += self.auth_rejected.load(Ordering::Relaxed);
        totals.backend_failures += self.backend_failures.load(Ordering::Relaxed);
    }

    pub fn totals(&self) -> Totals {
        let mut totals = Totals::default();
        self.add_to(&mut totals);
        totals
    }
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Totals {
    pub accepted: u64,
    pub rejected_limit: u64,
    pub auth_ok: u64,
    pub auth_rejected: u64,
    pub backend_failures: u64,
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct CacheCounters {
    pub hits: u64,
    pub misses: u64,
}

impl CacheCounters {
    pub fn hit_rate_pct(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 * 100.0 / total as f64
        }
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub struct Reading {
    pub at: Millis,
    pub active_connections: i64,
    pub sessions: u64,
    pub totals: Totals,
    pub cache: CacheCounters,
}

impl Reading {
    pub fn delta_since(&self, previous: &Reading) -> Sample {
        Sample {
            at: self.at,
            active_connections: self.active_connections,
            sessions: self.sessions,
            accepted: delta(self.totals.accepted, previous.totals.accepted),
            auth_ok: delta(self.totals.auth_ok, previous.totals.auth_ok),
            auth_rejected: delta(self.totals.auth_rejected, previous.totals.auth_rejected),
            backend_failures: delta(
                self.totals.backend_failures,
                previous.totals.backend_failures,
            ),
            cache_hits: delta(self.cache.hits, previous.cache.hits),
            cache_misses: delta(self.cache.misses, previous.cache.misses),
        }
    }
}

fn delta(current: u64, previous: u64) -> u64 {
    current.checked_sub(previous).unwrap_or(current)
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct Sample {
    pub at: Millis,
    pub active_connections: i64,
    pub sessions: u64,
    pub accepted: u64,
    pub auth_ok: u64,
    pub auth_rejected: u64,
    pub backend_failures: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

pub struct Metrics {
    pub active_connections: AtomicI64,
    listeners: Box<[OnceLock<Box<CounterChunk>>]>,
    unknown_listener: ListenerCounters,
    series: Mutex<VecDeque<Sample>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new(0)
    }
}

impl Metrics {
    pub fn new(listener_count: usize) -> Self {
        Metrics {
            active_connections: AtomicI64::new(0),
            listeners: (0..COUNTER_CHUNKS).map(|_| OnceLock::new()).collect(),
            unknown_listener: ListenerCounters::default(),
            series: Mutex::new(VecDeque::with_capacity(SERIES_LEN)),
        }
        .with_listeners(listener_count)
    }

    fn with_listeners(self, listener_count: usize) -> Self {
        for chunk in self
            .listeners
            .iter()
            .take(listener_count.div_ceil(COUNTER_CHUNK))
        {
            chunk.get_or_init(Self::new_chunk);
        }
        self
    }

    fn new_chunk() -> Box<CounterChunk> {
        Box::new(std::array::from_fn(|_| ListenerCounters::default()))
    }

    pub fn listener(&self, id: ListenerId) -> &ListenerCounters {
        let index = id.index();
        self.listeners
            .get(index / COUNTER_CHUNK)
            .and_then(|chunk| {
                chunk
                    .get_or_init(Self::new_chunk)
                    .get(index % COUNTER_CHUNK)
            })
            .unwrap_or(&self.unknown_listener)
    }

    pub fn totals(&self) -> Totals {
        let mut totals = Totals::default();
        for counters in self
            .listeners
            .iter()
            .filter_map(OnceLock::get)
            .flat_map(|chunk| chunk.iter())
            .chain([&self.unknown_listener])
        {
            counters.add_to(&mut totals);
        }
        totals
    }

    pub fn push_sample(&self, sample: Sample) {
        let mut series = self.series.lock();
        if series.len() == SERIES_LEN {
            series.pop_front();
        }
        series.push_back(sample);
    }

    pub fn series(&self, max: usize) -> Vec<Sample> {
        let series = self.series.lock();
        let skip = series.len().saturating_sub(max);
        series.range(skip..).copied().collect()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventKind {
    Admin,
    Health,
    Config,
    Mapping,
}

impl EventKind {
    pub fn parse(name: &[u8]) -> Option<Self> {
        hashify::map!(
            name,
            EventKind,
            "admin" => EventKind::Admin,
            "health" => EventKind::Health,
            "config" => EventKind::Config,
            "mapping" => EventKind::Mapping,
        )
        .copied()
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            EventKind::Admin => "admin",
            EventKind::Health => "health",
            EventKind::Config => "config",
            EventKind::Mapping => "mapping",
        }
    }
}

#[derive(Clone, Debug)]
pub struct EventBody {
    pub kind: EventKind,
    pub message: Box<str>,
    pub target: Option<Box<str>>,
    pub actor: Option<Box<str>>,
    pub ip: Option<IpAddr>,
}

impl EventBody {
    pub fn new(kind: EventKind, message: impl Into<Box<str>>) -> Self {
        EventBody {
            kind,
            message: message.into(),
            target: None,
            actor: None,
            ip: None,
        }
    }

    pub fn target(mut self, target: impl Into<Box<str>>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn actor(mut self, actor: impl Into<Box<str>>, ip: Option<IpAddr>) -> Self {
        self.actor = Some(actor.into());
        self.ip = ip;
        self
    }
}

#[derive(Clone, Debug)]
pub struct Event {
    pub seq: u64,
    pub at: Millis,
    pub body: EventBody,
}

pub struct EventPage {
    pub last_seq: u64,
    pub items: Vec<Event>,
}

#[derive(Default)]
struct Ring {
    events: VecDeque<Event>,
    last_seq: u64,
}

#[derive(Default)]
pub struct Events {
    ring: Mutex<Ring>,
}

impl Events {
    pub fn push(&self, at: Millis, body: EventBody) -> u64 {
        let mut ring = self.ring.lock();
        if ring.events.len() == EVENTS_LEN {
            ring.events.pop_front();
        }
        ring.last_seq += 1;
        let seq = ring.last_seq;
        ring.events.push_back(Event { seq, at, body });
        seq
    }

    pub fn since(&self, after: u64, kind: Option<EventKind>) -> EventPage {
        let ring = self.ring.lock();
        let start = ring.events.partition_point(|event| event.seq <= after);
        EventPage {
            last_seq: ring.last_seq,
            items: ring
                .events
                .range(start..)
                .filter(|event| kind.is_none_or(|k| k == event.body.kind))
                .cloned()
                .collect(),
        }
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/runtime/metrics/tests.rs"]
mod tests;
