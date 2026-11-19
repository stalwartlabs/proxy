/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::net::cidr::Cidr;

const WILDCARD_PREFIX: &str = "*.";

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowConfig {
    pub listener_addresses: Vec<Cidr>,
    pub listener_ports: Vec<PortRange>,
    pub destination_hosts: Vec<HostPattern>,
    pub destination_ports: Vec<PortRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    first: u16,
    last: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    Network(Cidr),
    Name(Box<str>),
    Subdomain(Box<str>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostVerdict {
    Allowed,
    ByAddress,
    Denied,
}

impl AllowConfig {
    pub fn listener_bind(&self, bind: SocketAddr) -> Option<&'static str> {
        let ip = bind.ip().to_canonical();
        if !self.listener_addresses.is_empty() && !Cidr::any_contains(&self.listener_addresses, ip)
        {
            return Some("listener_addresses");
        }
        if !PortRange::any_contains(&self.listener_ports, bind.port()) {
            return Some("listener_ports");
        }
        None
    }

    pub fn destination_port(&self, port: u16) -> bool {
        PortRange::any_contains(&self.destination_ports, port)
    }

    pub fn destination_host(&self, host: &str) -> HostVerdict {
        if self.destination_hosts.is_empty() {
            return HostVerdict::Allowed;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return match self.network_contains(ip) {
                true => HostVerdict::Allowed,
                false => HostVerdict::Denied,
            };
        }
        let host = host.trim_end_matches('.');
        let by_name = self.destination_hosts.iter().any(|pattern| match pattern {
            HostPattern::Name(name) => name.eq_ignore_ascii_case(host),
            HostPattern::Subdomain(parent) => host
                .len()
                .checked_sub(parent.len())
                .and_then(|split| host.split_at_checked(split))
                .is_some_and(|(label, suffix)| {
                    label.ends_with('.') && label.len() > 1 && suffix.eq_ignore_ascii_case(parent)
                }),
            HostPattern::Network(_) => false,
        });
        match by_name {
            true => HostVerdict::Allowed,
            false if self.has_networks() => HostVerdict::ByAddress,
            false => HostVerdict::Denied,
        }
    }

    pub fn network_contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.destination_hosts
            .iter()
            .any(|pattern| matches!(pattern, HostPattern::Network(net) if net.contains(ip)))
    }

    fn has_networks(&self) -> bool {
        self.destination_hosts
            .iter()
            .any(|pattern| matches!(pattern, HostPattern::Network(_)))
    }
}

impl PortRange {
    pub const fn new(first: u16, last: u16) -> Self {
        PortRange { first, last }
    }

    fn contains(&self, port: u16) -> bool {
        (self.first..=self.last).contains(&port)
    }

    fn any_contains(ranges: &[PortRange], port: u16) -> bool {
        ranges.is_empty() || ranges.iter().any(|range| range.contains(port))
    }
}

impl FromStr for PortRange {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let port = |part: &str| {
            part.trim()
                .parse::<u16>()
                .map_err(|_| format!("invalid port range {text:?}"))
        };
        let (first, last) = match text.split_once('-') {
            Some((first, last)) => (port(first)?, port(last)?),
            None => {
                let single = port(text)?;
                (single, single)
            }
        };
        if first > last {
            return Err(format!("port range {text:?} is reversed"));
        }
        Ok(PortRange { first, last })
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.first, self.last) {
            (first, last) if first == last => write!(f, "{first}"),
            (first, last) => write!(f, "{first}-{last}"),
        }
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PortRangeVisitor;

        impl Visitor<'_> for PortRangeVisitor {
            type Value = PortRange;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a port number or a \"first-last\" range")
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> Result<PortRange, E> {
                u16::try_from(value)
                    .map(|port| PortRange::new(port, port))
                    .map_err(|_| E::custom(format!("port {value} is out of range")))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> Result<PortRange, E> {
                u16::try_from(value)
                    .map(|port| PortRange::new(port, port))
                    .map_err(|_| E::custom(format!("port {value} is out of range")))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<PortRange, E> {
                value.parse().map_err(E::custom)
            }
        }

        deserializer.deserialize_any(PortRangeVisitor)
    }
}

impl Serialize for PortRange {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl FromStr for HostPattern {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.trim();
        if let Some(parent) = text.strip_prefix(WILDCARD_PREFIX) {
            return match HostPattern::valid_name(parent) {
                true => Ok(HostPattern::Subdomain(parent.to_ascii_lowercase().into())),
                false => Err(format!("invalid host pattern {text:?}")),
            };
        }
        if text.bytes().any(|byte| byte == b'/' || byte == b':') || text.parse::<IpAddr>().is_ok() {
            return text.parse().map(HostPattern::Network);
        }
        match HostPattern::valid_name(text) {
            true => Ok(HostPattern::Name(text.to_ascii_lowercase().into())),
            false => Err(format!("invalid host pattern {text:?}")),
        }
    }
}

impl HostPattern {
    fn valid_name(name: &str) -> bool {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'))
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostPattern::Network(net) => net.fmt(f),
            HostPattern::Name(name) => f.write_str(name),
            HostPattern::Subdomain(parent) => write!(f, "{WILDCARD_PREFIX}{parent}"),
        }
    }
}

impl<'de> Deserialize<'de> for HostPattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

impl Serialize for HostPattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/config/allow/tests.rs"]
mod tests;
