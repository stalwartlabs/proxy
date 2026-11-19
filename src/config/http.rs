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
pub struct HttpConfig {
    pub route: Vec<HttpRoute>,
    pub body_extract_cap: usize,
    pub max_head_size: usize,
    #[serde(with = "duration")]
    pub relay_idle: Duration,
    #[serde(with = "duration")]
    pub keepalive_timeout: Duration,
    pub max_keepalive_requests: u32,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            route: Vec::new(),
            body_extract_cap: 64 * 1024,
            max_head_size: 64 * 1024,
            relay_idle: Duration::from_secs(60),
            keepalive_timeout: Duration::from_secs(75),
            max_keepalive_requests: 1000,
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRoute {
    #[serde(rename = "match")]
    pub match_glob: String,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub extract: Option<HttpExtract>,
    #[serde(default)]
    pub fallback: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpExtract {
    pub from: ExtractFrom,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub param: Option<String>,
    #[serde(default)]
    pub header: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtractFrom {
    Authorization,
    Query,
    Body,
    Header,
}
