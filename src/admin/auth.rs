/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::env;
use std::iter;
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use crate::config::AdminConfig;
use crate::error::{ProxyError, Result};
use crate::runtime::compile::ADMIN_TOKEN_ENV;

const LOCKOUT_MAX_ENTRIES: usize = 16 * 1024;
const IPV6_PREFIX_MASK: u128 = !0 << 64;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ClientKey(IpAddr);

impl From<IpAddr> for ClientKey {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => ClientKey(IpAddr::V4(v4)),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => ClientKey(IpAddr::V4(v4)),
                None => ClientKey(IpAddr::V6(Ipv6Addr::from(
                    u128::from(v6) & IPV6_PREFIX_MASK,
                ))),
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LockoutPolicy {
    threshold: u32,
    duration: Duration,
}

impl From<&AdminConfig> for LockoutPolicy {
    fn from(admin: &AdminConfig) -> Self {
        LockoutPolicy {
            threshold: admin.lockout_threshold,
            duration: admin.lockout_duration,
        }
    }
}

impl LockoutPolicy {
    pub fn duration(self) -> Duration {
        self.duration
    }
}

#[derive(Clone, Copy, Debug)]
struct Failures {
    count: u32,
    last: Instant,
}

#[derive(Default)]
pub struct Lockout {
    failures: HashMap<ClientKey, Failures>,
}

impl Lockout {
    pub fn is_locked(&self, key: ClientKey, policy: LockoutPolicy, now: Instant) -> bool {
        self.failures.get(&key).is_some_and(|f| {
            f.count >= policy.threshold && now.saturating_duration_since(f.last) < policy.duration
        })
    }

    pub fn record_failure(&mut self, key: ClientKey, policy: LockoutPolicy, now: Instant) -> bool {
        if self.failures.len() >= LOCKOUT_MAX_ENTRIES && !self.failures.contains_key(&key) {
            self.make_room(policy, now);
        }
        let count = match self.failures.entry(key) {
            Entry::Occupied(mut entry) => {
                let failures = entry.get_mut();
                if now.saturating_duration_since(failures.last) >= policy.duration {
                    failures.count = 0;
                }
                failures.count = failures.count.saturating_add(1);
                failures.last = now;
                failures.count
            }
            Entry::Vacant(entry) => {
                entry
                    .insert(Failures {
                        count: 1,
                        last: now,
                    })
                    .count
            }
        };
        count == policy.threshold
    }

    pub fn record_success(&mut self, key: ClientKey) {
        self.failures.remove(&key);
    }

    fn make_room(&mut self, policy: LockoutPolicy, now: Instant) {
        self.failures
            .retain(|_, f| now.saturating_duration_since(f.last) < policy.duration);
        if self.failures.len() < LOCKOUT_MAX_ENTRIES {
            return;
        }
        if let Some(oldest) = self
            .failures
            .iter()
            .min_by_key(|(_, f)| f.last)
            .map(|(key, _)| *key)
        {
            self.failures.remove(&oldest);
        }
    }
}

pub fn ct_eq(provided: &[u8], expected: &[u8]) -> bool {
    let mut diff = u8::from(provided.len() != expected.len());
    for (e, p) in expected
        .iter()
        .zip(provided.iter().chain(iter::repeat(&0u8)))
    {
        diff |= e ^ p;
    }
    diff == 0
}

impl AdminConfig {
    pub fn load_token(&self) -> Result<Box<str>> {
        let token: Box<str> = if let Ok(env) = env::var(ADMIN_TOKEN_ENV) {
            env.into()
        } else if let Some(path) = &self.bearer_token_file {
            std::fs::read_to_string(path)
                .map_err(|e| ProxyError::config(format!("failed to read admin token {path}: {e}")))?
                .trim()
                .into()
        } else if let Some(inline) = &self.bearer_token {
            inline.expose().as_str().into()
        } else {
            return Err(ProxyError::config("admin token not configured"));
        };
        if token.len() < self.min_token_len {
            return Err(ProxyError::config(format!(
                "admin token is shorter than min_token_len ({})",
                self.min_token_len
            )));
        }
        Ok(token)
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/admin/auth/tests.rs"]
mod tests;
