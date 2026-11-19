/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::{self, Write};

use ahash::RandomState;
use tracing_subscriber::{EnvFilter, fmt as subscriber};

const VISIBLE_CHARS: usize = 2;
const TAG_MASK: u64 = 0xffff_ffff;

pub fn init(level: &str) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = subscriber()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

#[derive(Default)]
pub struct RedactKey(RandomState);

impl RedactKey {
    pub fn redact<'a>(&'a self, value: &'a str) -> Redacted<'a> {
        Redacted { key: self, value }
    }
}

pub struct Redacted<'a> {
    key: &'a RedactKey,
    value: &'a str,
}

impl fmt::Display for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.value.is_empty() {
            return f.write_str("<empty>");
        }
        self.value
            .chars()
            .take(VISIBLE_CHARS)
            .try_for_each(|c| f.write_char(c))?;
        let tag = self.key.0.hash_one(self.value) & TAG_MASK;
        write!(f, "***#{tag:08x}")
    }
}

impl fmt::Debug for Redacted<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../proxy-tests/unit/src/observe/tests.rs"]
mod tests;
