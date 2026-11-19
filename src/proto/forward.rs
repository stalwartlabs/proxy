/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::ops::BitOr;

use tokio::net::TcpStream;

use crate::config::{Forwarding, Protocol};
use crate::error::{ProxyError, Result, Stage};
use crate::net::dial::Peers;
use crate::proto::backend::{EncryptedLeg, starts_with_ci};
use crate::runtime::destination::{Destination, Endpoint};
use crate::token::valid_routing_identifier;

const MAX_ID_REPLY_LINES: usize = 16;
const CLIENT_TRANSPORT_TLS: &str = "TLS";
const CLIENT_TRANSPORT_INSECURE: &str = "insecure";
const COMMAND_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct XclientAttrs(u16);

impl XclientAttrs {
    pub const ADDR: Self = XclientAttrs(1);
    pub const PORT: Self = XclientAttrs(1 << 1);
    pub const DESTADDR: Self = XclientAttrs(1 << 2);
    pub const DESTPORT: Self = XclientAttrs(1 << 3);
    pub const SESSION: Self = XclientAttrs(1 << 4);
    pub const TTL: Self = XclientAttrs(1 << 5);
    pub const CLIENT_TRANSPORT: Self = XclientAttrs(1 << 6);
    pub const HELO: Self = XclientAttrs(1 << 7);
    pub const PROTO: Self = XclientAttrs(1 << 8);
    pub const ALL: Self = XclientAttrs((1 << 9) - 1);
    const MAIL: Self = XclientAttrs(Self::ALL.0 & !Self::HELO.0 & !Self::PROTO.0);

    pub fn parse<'a>(names: impl IntoIterator<Item = &'a [u8]>) -> Self {
        names
            .into_iter()
            .fold(XclientAttrs::default(), |attrs, name| {
                match hashify::map_ignore_case!(
                    name,
                    XclientAttrs,
                    "ADDR" => XclientAttrs::ADDR,
                    "PORT" => XclientAttrs::PORT,
                    "DESTADDR" => XclientAttrs::DESTADDR,
                    "DESTPORT" => XclientAttrs::DESTPORT,
                    "SESSION" => XclientAttrs::SESSION,
                    "TTL" => XclientAttrs::TTL,
                    "CLIENT-TRANSPORT" => XclientAttrs::CLIENT_TRANSPORT,
                    "HELO" => XclientAttrs::HELO,
                    "PROTO" => XclientAttrs::PROTO,
                ) {
                    Some(attr) => attrs | *attr,
                    None => attrs,
                }
            })
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    fn has(self, attr: XclientAttrs) -> bool {
        self.0 & attr.0 != 0
    }
}

impl BitOr for XclientAttrs {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        XclientAttrs(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XclientDialect {
    Mail,
    Smtp(XclientAttrs),
}

struct XclientAddr {
    ip: IpAddr,
    smtp: bool,
}

impl fmt::Display for XclientAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V6(v6) if self.smtp => write!(f, "IPV6:{v6}"),
            ip => ip.fmt(f),
        }
    }
}

pub struct ForwardInfo<'a> {
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub client_tls: bool,
    pub helo: Option<&'a str>,
    pub session: u64,
    pub ttl: u32,
}

impl<'a> ForwardInfo<'a> {
    pub fn new(
        peer: SocketAddr,
        local: SocketAddr,
        client_tls: bool,
        helo: Option<&'a str>,
        session: u64,
        inbound_ttl: u32,
    ) -> Self {
        ForwardInfo {
            peer,
            local,
            client_tls,
            helo,
            session,
            ttl: inbound_ttl.saturating_sub(1),
        }
    }

    pub fn peers(&self) -> Peers {
        Peers {
            peer: self.peer,
            local: self.local,
        }
    }

    fn transport(&self) -> &'static str {
        if self.client_tls {
            CLIENT_TRANSPORT_TLS
        } else {
            CLIENT_TRANSPORT_INSECURE
        }
    }

    pub fn xclient_command(&self, dialect: XclientDialect) -> String {
        let (attrs, smtp) = match dialect {
            XclientDialect::Mail => (XclientAttrs::MAIL, false),
            XclientDialect::Smtp(attrs) => (attrs, true),
        };
        let mut out = String::with_capacity(COMMAND_CAPACITY);
        out.push_str("XCLIENT");
        if attrs.has(XclientAttrs::ADDR) {
            let addr = XclientAddr {
                ip: self.peer.ip(),
                smtp,
            };
            let _ = write!(out, " ADDR={addr}");
        }
        if attrs.has(XclientAttrs::PORT) {
            let _ = write!(out, " PORT={}", self.peer.port());
        }
        if attrs.has(XclientAttrs::DESTADDR) {
            let addr = XclientAddr {
                ip: self.local.ip(),
                smtp,
            };
            let _ = write!(out, " DESTADDR={addr}");
        }
        if attrs.has(XclientAttrs::DESTPORT) {
            let _ = write!(out, " DESTPORT={}", self.local.port());
        }
        if attrs.has(XclientAttrs::SESSION) {
            let _ = write!(out, " SESSION=P{:x}", self.session);
        }
        if attrs.has(XclientAttrs::TTL) {
            let _ = write!(out, " TTL={}", self.ttl);
        }
        if attrs.has(XclientAttrs::CLIENT_TRANSPORT) {
            let _ = write!(out, " CLIENT-TRANSPORT={}", self.transport());
        }
        if attrs.has(XclientAttrs::HELO)
            && let Some(helo) = self.helo
            && !helo.is_empty()
            && valid_routing_identifier(helo)
        {
            let _ = write!(out, " HELO={helo}");
        }
        if attrs.has(XclientAttrs::PROTO) {
            out.push_str(" PROTO=ESMTP");
        }
        out.push_str("\r\n");
        out
    }

    pub fn write_imap_id(&self, out: &mut String) {
        let _ = write!(
            out,
            "(\"x-originating-ip\" \"{}\" \"x-originating-port\" \"{}\" \
             \"x-connected-ip\" \"{}\" \"x-connected-port\" \"{}\" \
             \"x-proxy-ttl\" \"{}\" \"x-session-id\" \"P{:x}\" \
             \"x-client-transport\" \"{}\")",
            self.peer.ip(),
            self.peer.port(),
            self.local.ip(),
            self.local.port(),
            self.ttl,
            self.session,
            self.transport(),
        );
    }
}

impl Destination {
    pub fn warn_unadvertised(&self, protocol: Protocol) {
        if self.warn_once_unadvertised() {
            tracing::warn!(
                destination = %self.name,
                protocol = protocol.as_str(),
                "forwarding = xclient but the backend does not advertise it; forwarding skipped"
            );
        }
    }
}

pub struct LoopGuard {
    binds: Box<[SocketAddr]>,
    has_wildcard: bool,
    proxy_ttl: u32,
}

impl LoopGuard {
    pub fn new(binds: impl IntoIterator<Item = SocketAddr>, proxy_ttl: u32) -> Self {
        let mut binds: Vec<SocketAddr> = binds.into_iter().collect();
        binds.sort_unstable();
        binds.dedup();
        LoopGuard {
            has_wildcard: binds.iter().any(|bind| bind.ip().is_unspecified()),
            binds: binds.into_boxed_slice(),
            proxy_ttl,
        }
    }

    pub fn check_target(&self, ep: &Endpoint) -> Result<()> {
        if let Some(addrs) = &ep.addrs
            && addrs.iter().any(|addr| self.binds.contains(addr))
        {
            return Err(ProxyError::loop_detected(
                "proxying loop: destination is one of our own listeners",
            ));
        }
        if ep.forwarding == Forwarding::Xclient && self.proxy_ttl <= 1 {
            return Err(ProxyError::loop_detected(
                "proxying loop: forwarded TTL exhausted",
            ));
        }
        Ok(())
    }

    pub fn check_connected(&self, ep: &Endpoint, tcp: &TcpStream) -> Result<()> {
        if ep.addrs.is_some() && !self.has_wildcard {
            return Ok(());
        }
        let (Ok(peer), Ok(local)) = (tcp.peer_addr(), tcp.local_addr()) else {
            return Ok(());
        };
        let peer = canonical(peer);
        let on_this_host = peer.ip().is_loopback() || peer.ip() == canonical(local).ip();
        let hit = self.binds.iter().any(|bind| {
            *bind == peer
                || (on_this_host
                    && bind.port() == peer.port()
                    && wildcard_accepts(bind.ip(), peer.ip()))
        });
        if hit {
            return Err(ProxyError::loop_detected(
                "proxying loop: backend connection reached one of our own listeners",
            ));
        }
        Ok(())
    }
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        SocketAddr::V4(_) => addr,
    }
}

fn wildcard_accepts(bind: IpAddr, peer: IpAddr) -> bool {
    match bind {
        IpAddr::V4(v4) => v4.is_unspecified() && peer.is_ipv4(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

impl ProxyError {
    #[cold]
    #[inline(never)]
    fn loop_detected(msg: &'static str) -> ProxyError {
        ProxyError::config(msg)
    }
}

impl ForwardInfo<'_> {
    pub async fn send_imap_id(&self, leg: &mut EncryptedLeg) -> Result<()> {
        let mut cmd = String::with_capacity(COMMAND_CAPACITY);
        cmd.push_str("F1 ID ");
        self.write_imap_id(&mut cmd);
        cmd.push_str("\r\n");
        leg.send(cmd.as_bytes(), Stage::Forwarding).await?;
        for _ in 0..MAX_ID_REPLY_LINES {
            let line = leg.read_line(Stage::Forwarding).await?;
            if starts_with_ci(line.trim_ascii_start(), b"F1 ") {
                return Ok(());
            }
        }
        Err(ProxyError::unavailable(
            Stage::Forwarding,
            "backend ID reply was not tagged",
        ))
    }

    pub async fn send_pop3_xclient(&self, leg: &mut EncryptedLeg) -> Result<()> {
        let cmd = self.xclient_command(XclientDialect::Mail);
        leg.send(cmd.as_bytes(), Stage::Forwarding).await?;
        if !leg.read_line(Stage::Forwarding).await?.starts_with(b"+OK") {
            return Err(ProxyError::unavailable(
                Stage::Forwarding,
                "backend rejected XCLIENT",
            ));
        }
        Ok(())
    }

    pub async fn send_managesieve_xclient(&self, leg: &mut EncryptedLeg) -> Result<()> {
        let cmd = self.xclient_command(XclientDialect::Mail);
        leg.send(cmd.as_bytes(), Stage::Forwarding).await?;
        let reply = leg.read_line(Stage::Forwarding).await?;
        if !starts_with_ci(reply.trim_ascii_start(), b"OK") {
            return Err(ProxyError::unavailable(
                Stage::Forwarding,
                "backend rejected XCLIENT",
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/proto/forward/tests.rs"]
mod tests;
