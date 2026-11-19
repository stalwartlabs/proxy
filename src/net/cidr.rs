/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

const V4_MAPPED_PREFIX: u32 = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: u128,
    mask: u128,
    is_v6: bool,
}

fn to_u128(ip: IpAddr) -> (u128, bool) {
    match ip {
        IpAddr::V4(v4) => (u128::from(v4.to_ipv6_mapped()), false),
        IpAddr::V6(v6) => (u128::from(v6), true),
    }
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        let addr = match ip {
            IpAddr::V4(_) if self.is_v6 => return false,
            IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
            IpAddr::V6(v6) => u128::from(v6),
        };
        (addr & self.mask) == self.network
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_str, prefix_str) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let ip: IpAddr = addr_str
            .trim()
            .parse()
            .map_err(|_| format!("invalid IP address in CIDR {s:?}"))?;
        let (network_raw, is_v6) = to_u128(ip);
        let max_prefix = if is_v6 { 128 } else { 32 };
        let prefix: u32 = match prefix_str {
            Some(p) => p
                .trim()
                .parse()
                .map_err(|_| format!("invalid prefix in CIDR {s:?}"))?,
            None => max_prefix,
        };
        if prefix > max_prefix {
            return Err(format!("prefix /{prefix} too large for address in {s:?}"));
        }
        let mask = u128::MAX.checked_shl(max_prefix - prefix).unwrap_or(0);
        Ok(Cidr {
            network: network_raw & mask,
            mask,
            is_v6,
        })
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let network = Ipv6Addr::from(self.network);
        let ones = self.mask.leading_ones();
        match network.to_ipv4_mapped() {
            Some(v4) if !self.is_v6 => write!(f, "{v4}/{}", ones.saturating_sub(V4_MAPPED_PREFIX)),
            _ => write!(f, "{network}/{ones}"),
        }
    }
}

impl Serialize for Cidr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl Cidr {
    pub fn any_contains(nets: &[Cidr], ip: IpAddr) -> bool {
        nets.iter().any(|n| n.contains(ip))
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/net/cidr/tests.rs"]
mod tests;
