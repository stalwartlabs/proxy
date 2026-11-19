/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

pub const ADMIN_CERTIFICATE_ID: &str = "admin";
pub const DEFAULT_SUBJECT: &str = "*";

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub certificate: AHashMap<String, CertificateConfig>,
    pub protocols: TlsProtocols,
    pub allow_self_signed: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateConfig {
    pub cert: String,
    pub key: String,
    #[serde(default)]
    pub subjects: Vec<String>,
    #[serde(default)]
    pub default: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
pub enum TlsVersion {
    #[default]
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsProtocols {
    pub min_version: TlsVersion,
    pub ignore_client_order: bool,
    pub disable_cipher_suites: Vec<String>,
}

impl Default for TlsProtocols {
    fn default() -> Self {
        TlsProtocols {
            min_version: TlsVersion::Tls12,
            ignore_client_order: false,
            disable_cipher_suites: Vec::new(),
        }
    }
}
