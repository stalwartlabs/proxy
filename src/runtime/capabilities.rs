/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Write;

use crate::config::{
    CapabilitiesConfig, ImapCapabilities, ManageSieveCapabilities, Pop3Capabilities,
    SubmissionCapabilities, TlsMode,
};
use crate::sasl::SaslMech;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsState {
    Plain,
    PlainStarttls,
    Tls,
}

impl TlsState {
    pub const ALL: [TlsState; 3] = [TlsState::Plain, TlsState::PlainStarttls, TlsState::Tls];

    pub fn new(is_tls: bool, listener: TlsMode) -> Self {
        match (is_tls, listener) {
            (true, _) => TlsState::Tls,
            (false, TlsMode::Starttls) => TlsState::PlainStarttls,
            (false, _) => TlsState::Plain,
        }
    }

    pub fn is_tls(self) -> bool {
        matches!(self, TlsState::Tls)
    }

    pub fn offers_starttls(self) -> bool {
        matches!(self, TlsState::PlainStarttls)
    }
}

pub struct PerState<T>([T; 3]);

impl<T> PerState<T> {
    fn build(mut f: impl FnMut(TlsState) -> T) -> Self {
        PerState(TlsState::ALL.map(&mut f))
    }

    pub fn get(&self, state: TlsState) -> &T {
        let [plain, starttls, tls] = &self.0;
        match state {
            TlsState::Plain => plain,
            TlsState::PlainStarttls => starttls,
            TlsState::Tls => tls,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SaslSet(u8);

impl SaslSet {
    const CLEARTEXT: u8 = 1 << 7;

    fn bit(mech: SaslMech) -> u8 {
        1 << mech as u8
    }

    fn build(configured: &[SaslMech], cleartext_allowed: bool) -> Self {
        let mut bits = configured.iter().fold(0, |acc, &m| acc | Self::bit(m));
        if cleartext_allowed {
            bits |= Self::CLEARTEXT;
        }
        SaslSet(bits)
    }

    pub fn configured(self, mech: SaslMech) -> bool {
        self.0 & Self::bit(mech) != 0
    }

    pub fn cleartext_allowed(self) -> bool {
        self.0 & Self::CLEARTEXT != 0
    }

    pub fn offers(self, mech: SaslMech) -> bool {
        self.configured(mech) && (self.cleartext_allowed() || !mech.is_cleartext())
    }
}

pub struct ImapWire {
    pub greeting: PerState<Box<[u8]>>,
    pub capability: PerState<Box<[u8]>>,
    pub sasl: PerState<SaslSet>,
}

pub struct Pop3Wire {
    pub banner: Box<[u8]>,
    pub capa: PerState<Box<[u8]>>,
    pub auth_list: PerState<Box<[u8]>>,
    pub sasl: PerState<SaslSet>,
}

pub struct ManageSieveWire {
    pub capability: PerState<Box<[u8]>>,
    pub sasl: PerState<SaslSet>,
}

pub struct SubmissionWire {
    banner_tail: Box<[u8]>,
    ehlo_tail: PerState<Box<[u8]>>,
    pub sasl: PerState<SaslSet>,
}

pub struct Capabilities {
    pub imap: ImapWire,
    pub pop3: Pop3Wire,
    pub managesieve: ManageSieveWire,
    pub submission: SubmissionWire,
}

impl Capabilities {
    pub fn build(caps: &CapabilitiesConfig) -> Self {
        Capabilities {
            imap: ImapWire::build(&caps.imap),
            pop3: Pop3Wire::build(&caps.pop3),
            managesieve: ManageSieveWire::build(&caps.managesieve),
            submission: SubmissionWire::build(&caps.submission),
        }
    }
}

#[derive(Clone, Copy)]
struct Mechs<'a>(&'a [SaslMech]);

impl<'a> Mechs<'a> {
    fn sets(self, allow_plain_without_tls: bool) -> PerState<SaslSet> {
        PerState::build(|state| SaslSet::build(self.0, allow_plain_without_tls || state.is_tls()))
    }

    fn offered(self, set: SaslSet) -> impl Iterator<Item = &'static str> + 'a {
        self.0
            .iter()
            .filter(move |&&m| set.offers(m))
            .map(|m| m.as_str())
    }
}

fn boxed(s: String) -> Box<[u8]> {
    s.into_bytes().into_boxed_slice()
}

impl ImapWire {
    fn build(caps: &ImapCapabilities) -> Self {
        let mechs = Mechs(&caps.sasl);
        let sasl = mechs.sets(caps.allow_plain_auth_without_tls);
        let tokens = PerState::build(|state| {
            let set = *sasl.get(state);
            let mut out = caps.advertise.join(" ");
            for mech in mechs.offered(set) {
                let _ = write!(out, " AUTH={mech}");
            }
            if !set.cleartext_allowed() {
                out.push_str(" LOGINDISABLED");
            }
            if state.offers_starttls() {
                out.push_str(" STARTTLS");
            }
            out.trim_start().to_string()
        });
        ImapWire {
            greeting: PerState::build(|state| {
                boxed(format!(
                    "* OK [CAPABILITY {}] {}\r\n",
                    tokens.get(state),
                    caps.banner
                ))
            }),
            capability: PerState::build(|state| {
                boxed(format!("* CAPABILITY {}\r\n", tokens.get(state)))
            }),
            sasl,
        }
    }
}

impl Pop3Wire {
    fn build(caps: &Pop3Capabilities) -> Self {
        let mechs = Mechs(&caps.sasl);
        let sasl = mechs.sets(caps.allow_plain_auth_without_tls);
        Pop3Wire {
            banner: boxed(format!("+OK {}\r\n", caps.banner)),
            capa: PerState::build(|state| {
                let set = *sasl.get(state);
                let mut out = String::from("+OK Capability list follows\r\n");
                if set.cleartext_allowed() {
                    out.push_str("USER\r\n");
                }
                let mut offered = mechs.offered(set).peekable();
                if offered.peek().is_some() {
                    out.push_str("SASL");
                    for mech in offered {
                        out.push(' ');
                        out.push_str(mech);
                    }
                    out.push_str("\r\n");
                }
                if state.offers_starttls() {
                    out.push_str("STLS\r\n");
                }
                out.push_str("TOP\r\nRESP-CODES\r\nPIPELINING\r\nEXPIRE NEVER\r\nUIDL\r\nUTF8\r\n");
                out.push_str("IMPLEMENTATION Stalwart Server\r\n.\r\n");
                boxed(out)
            }),
            auth_list: PerState::build(|state| {
                let mut out = String::from("+OK\r\n");
                for mech in mechs.offered(*sasl.get(state)) {
                    out.push_str(mech);
                    out.push_str("\r\n");
                }
                out.push_str(".\r\n");
                boxed(out)
            }),
            sasl,
        }
    }
}

impl ManageSieveWire {
    fn build(caps: &ManageSieveCapabilities) -> Self {
        let mechs = Mechs(&caps.sasl);
        let sasl = mechs.sets(caps.allow_plain_auth_without_tls);
        ManageSieveWire {
            capability: PerState::build(|state| {
                let mut out = String::new();
                let _ = write!(
                    out,
                    "\"IMPLEMENTATION\" \"{}\"\r\n\"VERSION\" \"1.0\"\r\n\"SASL\" \"",
                    caps.implementation
                );
                for (i, mech) in mechs.offered(*sasl.get(state)).enumerate() {
                    if i > 0 {
                        out.push(' ');
                    }
                    out.push_str(mech);
                }
                let _ = write!(out, "\"\r\n\"SIEVE\" \"{}\"\r\n", caps.sieve.join(" "));
                if state.offers_starttls() {
                    out.push_str("\"STARTTLS\"\r\n");
                }
                out.push_str("OK \"Stalwart ManageSieve ready.\"\r\n");
                boxed(out)
            }),
            sasl,
        }
    }
}

impl SubmissionWire {
    fn build(caps: &SubmissionCapabilities) -> Self {
        let mechs = Mechs(&caps.sasl);
        let sasl = mechs.sets(caps.allow_plain_auth_without_tls);
        SubmissionWire {
            banner_tail: boxed(format!(" ESMTP {}\r\n", caps.banner)),
            ehlo_tail: PerState::build(|state| {
                let mut auth = String::new();
                for mech in mechs.offered(*sasl.get(state)) {
                    auth.push_str(if auth.is_empty() { "AUTH " } else { " " });
                    auth.push_str(mech);
                }
                let starttls = state.offers_starttls().then_some("STARTTLS");
                let mut lines = caps
                    .ehlo
                    .iter()
                    .map(String::as_str)
                    .chain(starttls)
                    .chain(Some(auth.as_str()).filter(|auth| !auth.is_empty()))
                    .peekable();
                let mut out = String::new();
                while let Some(line) = lines.next() {
                    let sep = if lines.peek().is_some() { '-' } else { ' ' };
                    let _ = write!(out, "250{sep}{line}\r\n");
                }
                boxed(out)
            }),
            sasl,
        }
    }

    pub fn write_banner(&self, out: &mut Vec<u8>, hostname: &str) {
        out.reserve(4 + hostname.len() + self.banner_tail.len());
        out.extend_from_slice(b"220 ");
        out.extend_from_slice(hostname.as_bytes());
        out.extend_from_slice(&self.banner_tail);
    }

    pub fn write_ehlo(&self, out: &mut Vec<u8>, state: TlsState, hostname: &str, client: &str) {
        let tail = self.ehlo_tail.get(state);
        let sep = if tail.is_empty() { b' ' } else { b'-' };
        out.reserve(40 + hostname.len() + client.len() + tail.len());
        out.extend_from_slice(b"250");
        out.push(sep);
        out.extend_from_slice(hostname.as_bytes());
        out.extend_from_slice(b" at your service, [");
        out.extend_from_slice(client.as_bytes());
        out.extend_from_slice(b"]\r\n");
        out.extend_from_slice(tail);
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/runtime/capabilities/tests.rs"]
mod tests;
