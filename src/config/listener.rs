/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::{Protocol, TlsMode, duration};
use crate::net::cidr::Cidr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    #[default]
    Off,
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardedMode {
    #[default]
    Off,
    Trust,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerConfig {
    pub protocol: Protocol,
    pub bind: Vec<SocketAddr>,
    pub tls: TlsMode,
    #[serde(default)]
    pub proxy_protocol: ProxyProtocolMode,
    #[serde(default)]
    pub proxy_trusted: Vec<Cidr>,
    #[serde(default = "super::size::<8192>")]
    pub max_connections: usize,
    #[serde(default = "super::secs::<30>", with = "duration")]
    pub preauth_timeout: Duration,
    #[serde(default = "super::int::<3>")]
    pub max_auth_attempts: u32,
    #[serde(default)]
    pub forwarded: ForwardedMode,
}

impl ListenerConfig {
    pub fn same_sockets(&self, other: &ListenerConfig) -> bool {
        self.protocol == other.protocol
            && self.tls == other.tls
            && self.bind == other.bind
            && self.max_connections == other.max_connections
    }
}
