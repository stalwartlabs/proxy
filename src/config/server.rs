/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::duration;

#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub threads: usize,
    #[serde(with = "duration")]
    pub shutdown_grace: Duration,
    #[serde(with = "duration")]
    pub bridge_idle: Duration,
    #[serde(with = "duration")]
    pub backend_timeout: Duration,
    pub backend_connect_retries: u32,
    pub host_down_threshold: u32,
    pub host_down_min_clients: u32,
    #[serde(with = "duration")]
    pub host_down_cooldown: Duration,
    pub proxy_ttl: u32,
    pub log_level: String,
    pub hostname: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            threads: 0,
            shutdown_grace: Duration::from_secs(30),
            bridge_idle: Duration::from_secs(1800),
            backend_timeout: Duration::from_secs(10),
            backend_connect_retries: 1,
            host_down_threshold: 5,
            host_down_min_clients: 2,
            host_down_cooldown: Duration::from_secs(30),
            proxy_ttl: 7,
            log_level: "info".to_string(),
            hostname: None,
        }
    }
}
