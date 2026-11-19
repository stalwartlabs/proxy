/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::allow::AllowConfig;
use super::secret::Secret;
use super::{TlsMode, duration};

const EPHEMERAL_PORT: u16 = 0;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    pub bind: SocketAddr,
    #[serde(default = "TlsMode::implicit")]
    pub tls: TlsMode,
    #[serde(default)]
    pub bearer_token_file: Option<String>,
    #[serde(default)]
    pub bearer_token: Option<Secret<String>>,
    #[serde(default = "super::size::<32>")]
    pub min_token_len: usize,
    #[serde(default = "super::int::<5>")]
    pub lockout_threshold: u32,
    #[serde(default = "super::secs::<300>", with = "duration")]
    pub lockout_duration: Duration,
    #[serde(default)]
    pub config_write: bool,
    #[serde(default = "super::size::<1_048_576>")]
    pub max_body_size: usize,
    #[serde(default = "super::secs::<1800>", with = "duration")]
    pub session_idle_timeout: Duration,
    #[serde(default = "super::secs::<43200>", with = "duration")]
    pub session_lifetime: Duration,
    #[serde(default)]
    pub allow: AllowConfig,
}

impl AdminConfig {
    fn reserves_port(&self) -> bool {
        let ip = self.bind.ip().to_canonical();
        self.bind.port() != EPHEMERAL_PORT && (ip.is_loopback() || ip.is_unspecified())
    }

    pub fn reserved(&self, bind: SocketAddr) -> bool {
        let ip = bind.ip().to_canonical();
        self.reserves_port()
            && bind.port() == self.bind.port()
            && (self.bind.ip().to_canonical().is_unspecified()
                || ip.is_loopback()
                || ip.is_unspecified())
    }

    pub fn binds(&self) -> impl Iterator<Item = SocketAddr> {
        let twin = match self.bind.ip().to_canonical() {
            IpAddr::V4(ip) if ip.is_loopback() => Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            IpAddr::V4(ip) if ip.is_unspecified() => Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            IpAddr::V6(ip) if ip.is_loopback() => Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            IpAddr::V6(ip) if ip.is_unspecified() => Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            _ => None,
        };
        let port = self.bind.port();
        std::iter::once(self.bind).chain(twin.map(|ip| SocketAddr::new(ip, port)))
    }
}
