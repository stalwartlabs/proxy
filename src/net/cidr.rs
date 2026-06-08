/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;

use serde::{Deserialize, Deserializer};

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
        let (mut addr, is_v6) = to_u128(ip);
        if self.is_v6 != is_v6 {
            if !self.is_v6 && is_v6 {
                if let IpAddr::V6(v6) = ip {
                    if let Some(v4) = v6.to_ipv4_mapped() {
                        addr = u128::from(v4.to_ipv6_mapped());
                    } else {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }
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
        let total_bits = if is_v6 { 128 } else { 32 };
        let host_bits = total_bits - prefix;
        let mask = if host_bits == 0 {
            u128::MAX
        } else {
            (!0u128).checked_shl(host_bits).unwrap_or(0)
        };
        let mask = if is_v6 {
            mask
        } else {
            mask | u128::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0))
        };
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

pub fn any_contains(nets: &[Cidr], ip: IpAddr) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_v4() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains("10.1.2.3".parse().unwrap()));
        assert!(c.contains("10.255.255.255".parse().unwrap()));
        assert!(!c.contains("11.0.0.1".parse().unwrap()));
        let c: Cidr = "192.168.1.1".parse().unwrap();
        assert!(c.contains("192.168.1.1".parse().unwrap()));
        assert!(!c.contains("192.168.1.2".parse().unwrap()));
    }

    #[test]
    fn matches_v6() {
        let c: Cidr = "2001:db8::/32".parse().unwrap();
        assert!(c.contains("2001:db8::1".parse().unwrap()));
        assert!(!c.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn mapped_v4_in_v4_net() {
        let c: Cidr = "10.0.0.0/8".parse().unwrap();
        assert!(c.contains("::ffff:10.0.0.5".parse().unwrap()));
    }
}
