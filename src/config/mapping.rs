/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::duration;
use super::secret::SecretUrl;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Normalize {
    #[default]
    None,
    Lowercase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MappingSource {
    File,
    Redis,
    Sql,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MappingConfig {
    pub source: MappingSource,
    #[serde(default)]
    pub normalize: Normalize,
    #[serde(default = "super::secs::<30>", with = "duration")]
    pub negative_ttl: Duration,
    #[serde(default = "super::secs::<600>", with = "duration")]
    pub positive_ttl: Duration,
    #[serde(default = "super::count::<1_000_000>")]
    pub cache_max_entries: u64,
    #[serde(default)]
    pub cache_max_bytes: Option<u64>,
    #[serde(default = "super::secs::<5>", with = "duration")]
    pub lookup_timeout: Duration,
    #[serde(default)]
    pub file: Option<FileMappingConfig>,
    #[serde(default)]
    pub redis: Option<RedisMappingConfig>,
    #[serde(default)]
    pub sql: Option<SqlMappingConfig>,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileMappingConfig {
    pub path: String,
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedisMappingConfig {
    pub url: SecretUrl,
    #[serde(default = "key_prefix")]
    pub key_prefix: String,
    #[serde(default = "super::size::<16>")]
    pub pool_size: usize,
}

fn key_prefix() -> String {
    "route:".to_string()
}

#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SqlMappingConfig {
    pub url: SecretUrl,
    pub query: String,
    #[serde(default = "super::size::<16>")]
    pub pool_size: usize,
    #[serde(default)]
    pub upsert_query: Option<String>,
    #[serde(default)]
    pub delete_query: Option<String>,
    #[serde(default)]
    pub list_query: Option<String>,
    #[serde(default)]
    pub count_query: Option<String>,
}
