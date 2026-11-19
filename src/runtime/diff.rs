/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::Config;

impl Config {
    pub fn restart_required(&self, new: &Config) -> Vec<Box<str>> {
        let mut keys = Vec::new();
        if self.server.threads != new.server.threads {
            keys.push(Box::from("server.threads"));
        }
        if self.server.log_level != new.server.log_level {
            keys.push(Box::from("server.log_level"));
        }
        match (&self.admin, &new.admin) {
            (Some(old), Some(new)) if old.bind != new.bind => keys.push(Box::from("admin.bind")),
            (Some(_), None) | (None, Some(_)) => keys.push(Box::from("admin")),
            _ => {}
        }
        keys
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/runtime/diff/tests.rs"]
mod tests;
