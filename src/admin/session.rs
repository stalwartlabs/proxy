/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime};

use encodify::base64::URL_SAFE_NO_PAD;
use parking_lot::Mutex;

use super::auth::ct_eq;
use crate::config::AdminConfig;
use crate::http::serialize::ADMIN_SESSION_COOKIE;

pub const COOKIE_NAME: &str = ADMIN_SESSION_COOKIE;
const SECRET_LEN: usize = 32;
const ENCODED_LEN: usize = 43;
const MAX_SESSIONS: usize = 64;
const TAG_LEN: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SessionId([u8; SECRET_LEN]);

#[derive(Clone, Copy)]
pub struct Csrf([u8; SECRET_LEN]);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SessionTag([u8; TAG_LEN]);

#[derive(Clone, Copy, Debug)]
pub struct SessionLimits {
    idle: Duration,
    lifetime: Duration,
}

struct Session {
    csrf: Csrf,
    peer: IpAddr,
    created: Instant,
    last_seen: Instant,
}

#[derive(Default)]
pub struct Sessions {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    map: HashMap<SessionId, Session>,
    generation: Generation,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Generation(u64);

pub struct Issued {
    pub cookie: String,
    pub view: SessionView,
}

#[derive(Clone, Copy)]
pub struct SessionView {
    pub csrf: Csrf,
    pub tag: SessionTag,
    pub idle_timeout: Duration,
    pub expires_at: SystemTime,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CreateError {
    RandomUnavailable,
    Stale,
}

impl From<&AdminConfig> for SessionLimits {
    fn from(admin: &AdminConfig) -> Self {
        SessionLimits {
            idle: admin.session_idle_timeout,
            lifetime: admin.session_lifetime,
        }
    }
}

impl SessionId {
    fn parse(encoded: &str) -> Option<SessionId> {
        if encoded.len() != ENCODED_LEN {
            return None;
        }
        let decoded = URL_SAFE_NO_PAD.decode(encoded).ok()?;
        decoded.as_slice().try_into().ok().map(SessionId)
    }

    fn tag(&self) -> SessionTag {
        let [a, b, ..] = self.0;
        SessionTag([a, b])
    }
}

impl Csrf {
    pub fn matches(&self, presented: &str) -> bool {
        presented.len() == ENCODED_LEN
            && URL_SAFE_NO_PAD
                .decode(presented)
                .is_ok_and(|decoded| ct_eq(&decoded, &self.0))
    }

    pub fn encoded(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl fmt::Display for SessionTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b] = self.0;
        write!(f, "session:{a:02x}{b:02x}")
    }
}

impl Session {
    fn live(&self, limits: SessionLimits, now: Instant) -> bool {
        now.saturating_duration_since(self.last_seen) < limits.idle
            && now.saturating_duration_since(self.created) < limits.lifetime
    }

    fn view(&self, id: &SessionId, limits: SessionLimits, now: Instant) -> SessionView {
        let left = limits
            .lifetime
            .saturating_sub(now.saturating_duration_since(self.created));
        SessionView {
            csrf: self.csrf,
            tag: id.tag(),
            idle_timeout: limits.idle,
            expires_at: SystemTime::now()
                .checked_add(left)
                .unwrap_or_else(SystemTime::now),
        }
    }
}

impl Sessions {
    pub fn generation(&self) -> Generation {
        self.inner.lock().generation
    }

    pub fn create(
        &self,
        limits: SessionLimits,
        generation: Generation,
        peer: IpAddr,
    ) -> Result<Issued, CreateError> {
        let id = SessionId(random()?);
        let csrf = Csrf(random()?);
        let now = Instant::now();
        let session = Session {
            csrf,
            peer,
            created: now,
            last_seen: now,
        };
        let view = session.view(&id, limits, now);
        let mut inner = self.inner.lock();
        if inner.generation != generation {
            return Err(CreateError::Stale);
        }
        let map = &mut inner.map;
        map.retain(|_, session| session.live(limits, now));
        if map.len() >= MAX_SESSIONS
            && let Some(oldest) = map
                .iter()
                .min_by_key(|(_, session)| session.created)
                .map(|(id, _)| *id)
        {
            map.remove(&oldest);
        }
        map.insert(id, session);
        Ok(Issued {
            cookie: URL_SAFE_NO_PAD.encode(id.0),
            view,
        })
    }

    pub fn touch(&self, cookie: &str, limits: SessionLimits, peer: IpAddr) -> Option<SessionView> {
        let id = SessionId::parse(cookie)?;
        let now = Instant::now();
        let mut inner = self.inner.lock();
        let map = &mut inner.map;
        let session = map.get_mut(&id)?;
        if session.peer != peer {
            return None;
        }
        if !session.live(limits, now) {
            map.remove(&id);
            return None;
        }
        session.last_seen = now;
        Some(session.view(&id, limits, now))
    }

    pub fn remove(&self, cookie: &str, limits: SessionLimits, peer: IpAddr) -> Option<SessionView> {
        let id = SessionId::parse(cookie)?;
        let now = Instant::now();
        let mut inner = self.inner.lock();
        let map = &mut inner.map;
        if map.get(&id)?.peer != peer {
            return None;
        }
        map.remove(&id)
            .filter(|session| session.live(limits, now))
            .map(|session| session.view(&id, limits, now))
    }

    pub fn clear(&self) {
        let mut inner = self.inner.lock();
        inner.map.clear();
        inner.generation = Generation(inner.generation.0.wrapping_add(1));
    }
}

fn random() -> Result<[u8; SECRET_LEN], CreateError> {
    let mut bytes = [0u8; SECRET_LEN];
    aws_lc_rs::rand::fill(&mut bytes).map_err(|_| CreateError::RandomUnavailable)?;
    Ok(bytes)
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/admin/session/tests.rs"]
mod tests;
