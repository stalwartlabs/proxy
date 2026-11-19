/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::mem;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use ahash::AHashMap;
use parking_lot::Mutex;

use crate::config::ServerConfig;
use crate::error::{ProxyError, Result, Stage};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct Millis(pub u64);

impl Millis {
    pub fn saturating_add(self, d: Duration) -> Millis {
        Millis(
            self.0
                .saturating_add(u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        )
    }
}

#[derive(Clone, Copy)]
pub struct Clock {
    origin: Instant,
    started_at: SystemTime,
}

impl Default for Clock {
    fn default() -> Self {
        Clock {
            origin: Instant::now(),
            started_at: SystemTime::now(),
        }
    }
}

impl Clock {
    pub fn started_at(&self) -> SystemTime {
        self.started_at
    }

    pub fn wall(&self, at: Millis) -> SystemTime {
        self.started_at + Duration::from_millis(at.0)
    }

    pub fn now(&self) -> Millis {
        Millis(
            u64::try_from(self.origin.elapsed().as_millis())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attribution {
    Host,
    Client(IpAddr),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FailureClass {
    Connect,
    Session,
}

impl FailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            FailureClass::Connect => "connect",
            FailureClass::Session => "session",
        }
    }
}

#[derive(Clone, Debug)]
pub struct LastFailure {
    pub at: Millis,
    pub stage: Stage,
    pub class: FailureClass,
    pub error: Box<str>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HealthState {
    Up,
    Degraded,
    Down,
}

impl HealthState {
    pub const fn as_str(self) -> &'static str {
        match self {
            HealthState::Up => "up",
            HealthState::Degraded => "degraded",
            HealthState::Down => "down",
        }
    }
}

#[derive(Clone, Debug)]
pub struct HealthSnapshot {
    pub state: HealthState,
    pub consecutive_failures: u32,
    pub failure_sources: u32,
    pub host_level_failure: bool,
    pub down_until: Option<Millis>,
    pub last_failure: Option<LastFailure>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HealthChange {
    Unchanged,
    Down,
    Recovered,
}

impl HealthChange {
    pub const fn message(self) -> Option<&'static str> {
        match self {
            HealthChange::Unchanged => None,
            HealthChange::Down => Some("destination marked down"),
            HealthChange::Recovered => Some("destination recovered"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HealthLimits {
    pub threshold: u32,
    pub min_clients: u32,
    pub cooldown: Duration,
}

impl HealthLimits {
    pub fn for_server(server: &ServerConfig) -> Self {
        HealthLimits {
            threshold: server.host_down_threshold,
            min_clients: server.host_down_min_clients,
            cooldown: server.host_down_cooldown,
        }
    }
}

const MAX_TRACKED_FAILURE_SOURCES: usize = 64;
const UP: u64 = 0;

#[derive(Default)]
struct Evidence {
    sources: Vec<IpAddr>,
    host: bool,
    tripped: bool,
    last_failure: Option<LastFailure>,
}

impl Evidence {
    fn clear(&mut self) {
        self.sources.clear();
        self.host = false;
    }
}

#[derive(Default)]
pub struct DestHealth {
    failures: AtomicU32,
    down_until: AtomicU64,
    evidence: Mutex<Evidence>,
}

impl DestHealth {
    #[cold]
    fn down_error() -> ProxyError {
        ProxyError::unavailable(
            Stage::Connect,
            "destination temporarily marked down after repeated failures",
        )
    }

    pub fn gate(&self, clock: &Clock) -> Result<()> {
        let until = self.down_until.load(Ordering::Acquire);
        if until == UP {
            return Ok(());
        }
        if clock.now().0 < until {
            return Err(Self::down_error());
        }
        let mut evidence = self.evidence.lock();
        match self
            .down_until
            .compare_exchange(until, UP, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => evidence.clear(),
            Err(current) if current != UP && clock.now().0 < current => {
                return Err(Self::down_error());
            }
            Err(_) => {}
        }
        Ok(())
    }

    pub fn record_success(&self) -> HealthChange {
        if self.failures.load(Ordering::Relaxed) == 0
            && self.down_until.load(Ordering::Relaxed) == UP
        {
            return HealthChange::Unchanged;
        }
        let mut evidence = self.evidence.lock();
        self.failures.store(0, Ordering::Relaxed);
        self.down_until.store(UP, Ordering::Release);
        evidence.clear();
        if mem::take(&mut evidence.tripped) {
            HealthChange::Recovered
        } else {
            HealthChange::Unchanged
        }
    }

    pub fn record_failure(
        &self,
        at: Attribution,
        err: &ProxyError,
        limits: &HealthLimits,
        now: Millis,
    ) -> HealthChange {
        let error = err.to_string().into_boxed_str();
        let mut evidence = self.evidence.lock();
        let failures = self.failures.load(Ordering::Relaxed).saturating_add(1);
        self.failures.store(failures, Ordering::Relaxed);
        let class = match at {
            Attribution::Host => {
                evidence.host = true;
                FailureClass::Connect
            }
            Attribution::Client(ip) => {
                if evidence.sources.len() < MAX_TRACKED_FAILURE_SOURCES
                    && !evidence.sources.contains(&ip)
                {
                    evidence.sources.push(ip);
                }
                FailureClass::Session
            }
        };
        evidence.last_failure = Some(LastFailure {
            at: now,
            stage: err.stage,
            class,
            error,
        });
        let sources = u32::try_from(evidence.sources.len()).unwrap_or(u32::MAX);
        let broad = evidence.host || sources >= limits.min_clients;
        if limits.threshold > 0 && failures >= limits.threshold && broad {
            let previous = self.down_until.load(Ordering::Relaxed);
            let until = now.saturating_add(limits.cooldown).0;
            self.down_until.store(until, Ordering::Release);
            if previous == UP || now.0 >= previous {
                evidence.tripped = true;
                return HealthChange::Down;
            }
        }
        HealthChange::Unchanged
    }

    pub fn reset(&self) {
        let mut evidence = self.evidence.lock();
        self.failures.store(0, Ordering::Relaxed);
        self.down_until.store(UP, Ordering::Release);
        evidence.clear();
        evidence.tripped = false;
    }

    pub fn snapshot(&self, now: Millis) -> HealthSnapshot {
        let evidence = self.evidence.lock();
        let failures = self.failures.load(Ordering::Relaxed);
        let until = self.down_until.load(Ordering::Acquire);
        let down_until = (until != UP && now.0 < until).then_some(Millis(until));
        let state = match (down_until, failures) {
            (Some(_), _) => HealthState::Down,
            (None, 0) => HealthState::Up,
            (None, _) => HealthState::Degraded,
        };
        HealthSnapshot {
            state,
            consecutive_failures: failures,
            failure_sources: u32::try_from(evidence.sources.len()).unwrap_or(u32::MAX),
            host_level_failure: evidence.host,
            down_until,
            last_failure: evidence.last_failure.clone(),
        }
    }
}

#[derive(Default)]
pub struct HealthTable {
    entries: Mutex<AHashMap<Box<str>, HealthEntry>>,
}

struct HealthEntry {
    target: u64,
    health: Arc<DestHealth>,
}

impl HealthTable {
    pub fn carry_over(&self, name: &str, target: u64) -> Arc<DestHealth> {
        match self.entries.lock().get(name) {
            Some(entry) if entry.target == target => entry.health.clone(),
            _ => Arc::default(),
        }
    }

    pub fn commit<'a>(&self, live: impl Iterator<Item = (&'a str, u64, &'a Arc<DestHealth>)>) {
        let entries = live
            .map(|(name, target, health)| {
                (
                    Box::from(name),
                    HealthEntry {
                        target,
                        health: health.clone(),
                    },
                )
            })
            .collect();
        *self.entries.lock() = entries;
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/runtime/health/tests.rs"]
mod tests;

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/runtime/health/test_support.rs"]
mod test_support;
