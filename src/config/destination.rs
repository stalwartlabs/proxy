/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::IpAddr;
use std::time::Duration;

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

use super::{Protocol, TlsMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Forwarding {
    Proxy,
    Xclient,
    None,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationConfig {
    pub host: String,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    #[serde(default = "super::yes")]
    pub proxy_protocol: bool,
    #[serde(default)]
    pub forwarding: Option<Forwarding>,
    #[serde(default)]
    pub forwarded: bool,
    #[serde(default)]
    pub tls_allow_invalid_certs: bool,
    #[serde(default)]
    pub tls_pinned_cert_sha256: Option<String>,
    #[serde(default)]
    pub tls_client_cert: Option<String>,
    #[serde(default)]
    pub tls_client_key: Option<String>,
    #[serde(default)]
    pub source_ips: Vec<IpAddr>,
    #[serde(default, with = "super::duration::option")]
    pub dns_cache_ttl: Option<Duration>,
    #[serde(default)]
    pub hide_auth_errors: bool,
    #[serde(default)]
    pub allow_plaintext_auth: bool,
    #[serde(default)]
    pub protocol: AHashMap<Protocol, DestProtocol>,
}

impl DestinationConfig {
    pub fn host_is_ip(&self) -> bool {
        self.host.parse::<IpAddr>().is_ok()
    }

    pub fn tls_name(&self) -> &str {
        self.tls_server_name.as_deref().unwrap_or(&self.host)
    }

    pub fn forwarding_for(&self, protocol: Protocol) -> Forwarding {
        if let Some(ep) = self.protocol.get(&protocol)
            && let Some(f) = ep.forwarding
        {
            return f;
        }
        if let Some(f) = self.forwarding {
            return f;
        }
        if self.proxy_protocol {
            Forwarding::Proxy
        } else {
            Forwarding::None
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestProtocol {
    pub port: u16,
    pub tls: TlsMode,
    #[serde(default)]
    pub forwarding: Option<Forwarding>,
}
