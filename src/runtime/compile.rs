/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::env;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use ahash::AHashMap;
use globset::Glob;
use regex::Regex;
use rustls_pki_types::ServerName;

use crate::config::allow::{AllowConfig, HostVerdict};
use crate::config::{
    AdminConfig, Config, DestinationConfig, ExtractFrom, ListenerConfig, MappingSource, Protocol,
    ProxyProtocolMode, TlsMode,
};
use crate::error::ConfigErrors;
use crate::net::tls;

pub const MAX_CONNECTIONS: usize = 1_000_000;
pub const MAX_HEAD_SIZE: usize = 1024 * 1024;
const EPHEMERAL_PORT: u16 = 0;
pub const ADMIN_TOKEN_ENV: &str = "PROXY_ADMIN_TOKEN";

impl Config {
    pub fn validate(&self) -> Result<(), ConfigErrors> {
        let mut check = Check {
            raw: self,
            errors: ConfigErrors::default(),
        };
        check.server();
        check.tls();
        check.listeners();
        check.routing();
        check.destinations();
        check.http();
        check.mapping();
        check.admin();
        check.capabilities();
        check.errors.into_result()
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum BindOwner<'a> {
    Admin,
    Listener(&'a str),
}

impl BindOwner<'_> {
    fn bind_path(self) -> String {
        match self {
            BindOwner::Admin => "admin.bind".to_string(),
            BindOwner::Listener(name) => format!("listener.{name}.bind"),
        }
    }
}

impl fmt::Display for BindOwner<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindOwner::Admin => f.write_str("[admin]"),
            BindOwner::Listener(name) => write!(f, "listener {name:?}"),
        }
    }
}

struct Check<'a> {
    raw: &'a Config,
    errors: ConfigErrors,
}

fn sorted<V>(map: &AHashMap<String, V>) -> Vec<(&str, &V)> {
    let mut entries: Vec<(&str, &V)> = map.iter().map(|(k, v)| (k.as_str(), v)).collect();
    entries.sort_unstable_by_key(|(k, _)| *k);
    entries
}

impl<'a> Check<'a> {
    fn push(&mut self, path: impl Into<Box<str>>, message: impl Into<Cow<'static, str>>) {
        self.errors.push(path, message);
    }

    fn non_zero(&mut self, value: Duration, path: impl FnOnce() -> String) {
        if value.is_zero() {
            self.push(path(), "must be greater than zero");
        }
    }

    fn destination(&mut self, name: &str, path: &str) -> Option<&'a DestinationConfig> {
        let found = self.raw.destination.get(name);
        if found.is_none() {
            self.push(path, format!("undeclared destination {name:?}"));
        }
        found
    }

    fn server(&mut self) {
        let raw = self.raw;
        let server = &raw.server;
        self.non_zero(server.backend_timeout, || "server.backend_timeout".into());
        self.non_zero(server.bridge_idle, || "server.bridge_idle".into());
    }

    fn tls(&mut self) {
        let raw = self.raw;
        let suites = &raw.tls.protocols.disable_cipher_suites;
        for (index, name) in suites.iter().enumerate() {
            if !tls::is_known_cipher_suite(name) {
                self.push(
                    format!("tls.protocols.disable_cipher_suites[{index}]"),
                    format!("unknown cipher suite {name:?}"),
                );
            }
        }
        if raw.tls.certificate.is_empty() && !raw.tls.allow_self_signed {
            let terminating = raw
                .listener
                .values()
                .any(|listener| listener.tls != TlsMode::Plain);
            if terminating || raw.admin.is_some() {
                self.push(
                    "tls.certificate",
                    "a TLS listener or [admin] needs a certificate; set allow_self_signed = true to serve a generated self-signed one",
                );
            }
        }
    }

    fn listeners(&mut self) {
        let mut binds: Vec<(SocketAddr, BindOwner)> = Vec::new();
        let raw = self.raw;
        for (name, listener) in sorted(&raw.listener) {
            self.listener(name, listener);
            binds.extend(
                listener
                    .bind
                    .iter()
                    .filter(|addr| addr.port() != EPHEMERAL_PORT)
                    .map(|addr| (*addr, BindOwner::Listener(name))),
            );
            if let Some(admin) = &raw.admin {
                self.admin_reserved(name, listener, admin);
            }
        }
        if let Some(admin) = raw
            .admin
            .as_ref()
            .filter(|a| a.bind.port() != EPHEMERAL_PORT)
        {
            binds.push((admin.bind, BindOwner::Admin));
        }
        binds.sort_unstable_by_key(|(addr, owner)| {
            (
                addr.is_ipv6(),
                addr.port(),
                !addr.ip().is_unspecified(),
                *addr,
                *owner,
            )
        });
        let same_socket_space = |(a, _): &(SocketAddr, BindOwner),
                                 (b, _): &(SocketAddr, BindOwner)| {
            a.is_ipv6() == b.is_ipv6() && a.port() == b.port()
        };
        for group in binds.chunk_by(same_socket_space) {
            let [(wildcard, wildcard_owner), rest @ ..] = group else {
                continue;
            };
            if wildcard.ip().is_unspecified() {
                for (addr, owner) in rest {
                    self.push(
                        owner.bind_path(),
                        format!("{addr} overlaps {wildcard} bound by {wildcard_owner}"),
                    );
                }
                continue;
            }
            for pair in group.windows(2) {
                if let [(addr, first), (next, second)] = pair
                    && addr == next
                {
                    self.push(
                        second.bind_path(),
                        format!("{addr} is already bound by {first}"),
                    );
                }
            }
        }
    }

    fn admin_reserved(&mut self, name: &str, listener: &ListenerConfig, admin: &AdminConfig) {
        for addr in &listener.bind {
            let overlap_reported = addr.is_ipv6() == admin.bind.is_ipv6()
                && (*addr == admin.bind
                    || addr.ip().is_unspecified()
                    || admin.bind.ip().is_unspecified());
            if admin.reserved(*addr) && !overlap_reported {
                self.push(
                    format!("listener.{name}.bind"),
                    format!(
                        "{addr} uses port {} reserved by [admin] (bind {})",
                        admin.bind.port(),
                        admin.bind
                    ),
                );
            }
            if let Some(list) = admin.allow.listener_bind(*addr) {
                self.push(
                    format!("listener.{name}.bind"),
                    format!("{addr} is not allowed by admin.allow.{list}"),
                );
            }
        }
    }

    fn listener(&mut self, name: &str, listener: &'a ListenerConfig) {
        if listener.bind.is_empty() {
            self.push(format!("listener.{name}.bind"), "no bind addresses");
        }
        if !(1..=MAX_CONNECTIONS).contains(&listener.max_connections) {
            self.push(
                format!("listener.{name}.max_connections"),
                format!("must be between 1 and {MAX_CONNECTIONS}"),
            );
        }
        self.non_zero(listener.preauth_timeout, || {
            format!("listener.{name}.preauth_timeout")
        });
        let raw = self.raw;
        let Some(routing) = &raw.routing else {
            self.push(
                format!("listener.{name}"),
                "a listener requires a [routing] section with default_destination",
            );
            return;
        };
        match listener.proxy_protocol {
            ProxyProtocolMode::Off => {}
            mode => {
                if listener.proxy_trusted.is_empty() {
                    self.push(
                        format!("listener.{name}.proxy_trusted"),
                        "proxy_protocol is enabled but proxy_trusted is empty",
                    );
                }
                if mode == ProxyProtocolMode::Optional && listener.protocol != Protocol::Http {
                    self.push(
                        format!("listener.{name}.proxy_protocol"),
                        format!(
                            "optional is only allowed on http listeners; {} is server-first and would stall until preauth_timeout",
                            listener.protocol.as_str()
                        ),
                    );
                }
            }
        }
        if listener.protocol.is_passthrough() {
            if listener.tls == TlsMode::Starttls {
                self.push(
                    format!("listener.{name}.tls"),
                    format!(
                        "a pass-through ({}) listener cannot use tls=starttls (the proxy bridges raw and does not terminate STARTTLS); use plain or implicit",
                        listener.protocol.as_str()
                    ),
                );
            }
            return;
        }
        if let Some(default) = raw.destination.get(&routing.default_destination)
            && !default.protocol.contains_key(&listener.protocol)
        {
            self.push(
                format!("listener.{name}.protocol"),
                format!(
                    "default_destination {:?} does not declare protocol {} required by this listener",
                    routing.default_destination,
                    listener.protocol.as_str()
                ),
            );
        }
    }

    fn routing(&mut self) {
        let raw = self.raw;
        let Some(routing) = &raw.routing else {
            return;
        };
        self.destination(&routing.default_destination, "routing.default_destination");
        let passthrough_listener = |protocol: Protocol| {
            raw.listener
                .values()
                .any(|listener| listener.protocol == protocol)
        };
        let has_smtp = passthrough_listener(Protocol::Smtp);
        let has_lmtp = passthrough_listener(Protocol::Lmtp);
        let Some(name) = &routing.smtp_passthrough_destination else {
            if has_smtp || has_lmtp {
                self.push(
                    "routing.smtp_passthrough_destination",
                    "smtp/lmtp listener configured but routing.smtp_passthrough_destination is unset",
                );
            }
            return;
        };
        let path = "routing.smtp_passthrough_destination";
        let Some(dest) = self.destination(name, path) else {
            return;
        };
        let missing_smtp = !dest.protocol.contains_key(&Protocol::Smtp);
        let missing_lmtp = has_lmtp && !dest.protocol.contains_key(&Protocol::Lmtp);
        if missing_smtp {
            self.push(
                path,
                format!("destination {name:?} must declare the smtp protocol"),
            );
        }
        if missing_lmtp {
            self.push(
                path,
                format!("destination {name:?} must declare lmtp (an lmtp listener exists)"),
            );
        }
    }

    fn destinations(&mut self) {
        let raw = self.raw;
        for (name, dest) in sorted(&raw.destination) {
            self.destination_config(name, dest);
            if let Some(admin) = &raw.admin {
                self.destination_allowed(name, dest, &admin.allow);
            }
        }
    }

    fn destination_allowed(&mut self, name: &str, dest: &DestinationConfig, allow: &AllowConfig) {
        if allow.destination_host(&dest.host) == HostVerdict::Denied {
            self.push(
                format!("destination.{name}.host"),
                format!(
                    "{:?} is not allowed by admin.allow.destination_hosts",
                    dest.host
                ),
            );
        }
        let mut protocols: Vec<_> = dest.protocol.iter().collect();
        protocols.sort_unstable_by_key(|(protocol, _)| protocol.as_str());
        for (protocol, endpoint) in protocols {
            if !allow.destination_port(endpoint.port) {
                self.push(
                    format!("destination.{name}.protocol.{}.port", protocol.as_str()),
                    format!(
                        "port {} is not allowed by admin.allow.destination_ports",
                        endpoint.port
                    ),
                );
            }
        }
    }

    fn destination_config(&mut self, name: &str, dest: &DestinationConfig) {
        if let Some(ttl) = dest.dns_cache_ttl {
            self.non_zero(ttl, || format!("destination.{name}.dns_cache_ttl"));
        }
        let host_is_ip = dest.host_is_ip();
        let mut first_tls = None;
        for protocol in Protocol::ALL {
            let Some(endpoint) = dest.protocol.get(&protocol) else {
                continue;
            };
            if protocol.is_credential_bearing()
                && endpoint.tls == TlsMode::Plain
                && !dest.allow_plaintext_auth
            {
                self.push(
                    format!("destination.{name}.protocol.{}.tls", protocol.as_str()),
                    "uses plaintext TLS but carries credentials; set allow_plaintext_auth to override",
                );
            }
            if endpoint.tls != TlsMode::Plain && first_tls.is_none() {
                first_tls = Some(protocol);
            }
        }
        if let Some(protocol) = first_tls
            && host_is_ip
            && dest.tls_server_name.is_none()
        {
            self.push(
                format!("destination.{name}.tls_server_name"),
                format!(
                    "required: the host is an IP address and protocol {} uses TLS",
                    protocol.as_str()
                ),
            );
        } else if first_tls.is_some() && ServerName::try_from(dest.tls_name()).is_err() {
            let key = match dest.tls_server_name {
                Some(_) => "tls_server_name",
                None => "host",
            };
            self.push(
                format!("destination.{name}.{key}"),
                "is not a valid TLS server name",
            );
        }
        if let Some(pin) = &dest.tls_pinned_cert_sha256 {
            let path = || format!("destination.{name}.tls_pinned_cert_sha256");
            if let Err(err) = tls::parse_pin(pin) {
                self.push(path(), err.to_string());
            }
            if dest.tls_allow_invalid_certs {
                self.push(
                    path(),
                    "cannot be combined with tls_allow_invalid_certs; remove one of them",
                );
            }
        }
        match (&dest.tls_client_cert, &dest.tls_client_key) {
            (Some(_), None) => self.push(
                format!("destination.{name}.tls_client_key"),
                "required when tls_client_cert is set",
            ),
            (None, Some(_)) => self.push(
                format!("destination.{name}.tls_client_cert"),
                "required when tls_client_key is set",
            ),
            _ => {}
        }
    }

    fn http_destination(&mut self, name: &str, path: String) {
        if let Some(dest) = self.destination(name, &path)
            && !dest.protocol.contains_key(&Protocol::Http)
        {
            self.push(
                path,
                format!("destination {name:?} does not declare the http protocol"),
            );
        }
    }

    fn http(&mut self) {
        let raw = self.raw;
        let http = &raw.http;
        self.non_zero(http.relay_idle, || "http.relay_idle".into());
        if http.max_head_size > MAX_HEAD_SIZE {
            self.push(
                "http.max_head_size",
                format!("must not exceed {MAX_HEAD_SIZE} bytes"),
            );
        }
        for (index, route) in http.route.iter().enumerate() {
            if let Err(err) = Glob::new(&route.match_glob) {
                self.push(
                    format!("http.route[{index}].match"),
                    format!("invalid http route glob {:?}: {err}", route.match_glob),
                );
            }
            if let Some(dest) = &route.destination {
                self.http_destination(dest, format!("http.route[{index}].destination"));
            }
            if let Some(fallback) = &route.fallback {
                self.http_destination(fallback, format!("http.route[{index}].fallback"));
            }
            let Some(extract) = &route.extract else {
                continue;
            };
            let missing = match extract.from {
                ExtractFrom::Body if extract.regex.is_none() => Some(("regex", "body")),
                ExtractFrom::Query if extract.param.is_none() => Some(("param", "query")),
                ExtractFrom::Header if extract.header.is_none() => Some(("header", "header")),
                _ => None,
            };
            if let Some((field, from)) = missing {
                self.push(
                    format!("http.route[{index}].extract.{field}"),
                    format!("http extract from={from} requires a {field}"),
                );
            }
            if let Some(re) = &extract.regex
                && let Err(err) = Regex::new(re)
            {
                self.push(
                    format!("http.route[{index}].extract.regex"),
                    format!("invalid http extract regex {re:?}: {err}"),
                );
            }
        }
    }

    fn mapping(&mut self) {
        let raw = self.raw;
        let Some(mapping) = &raw.mapping else {
            return;
        };
        if raw.routing.is_none() {
            self.push(
                "mapping",
                "a [mapping] section requires a [routing] section with default_destination",
            );
        }
        self.non_zero(mapping.lookup_timeout, || "mapping.lookup_timeout".into());
        if mapping.cache_max_bytes == Some(0) {
            self.push("mapping.cache_max_bytes", "must be greater than zero");
        }
        let missing = match mapping.source {
            MappingSource::File => mapping.file.is_none().then_some("file"),
            MappingSource::Redis => mapping.redis.is_none().then_some("redis"),
            MappingSource::Sql => mapping.sql.is_none().then_some("sql"),
        };
        if let Some(source) = missing {
            self.push(
                format!("mapping.{source}"),
                format!("mapping.source={source} requires [mapping.{source}]"),
            );
        }
    }

    fn admin(&mut self) {
        let raw = self.raw;
        let Some(admin) = &raw.admin else {
            return;
        };
        if admin.tls != TlsMode::Implicit {
            self.push(
                "admin.tls",
                "must be implicit (plaintext admin is rejected)",
            );
        }
        self.non_zero(admin.session_idle_timeout, || {
            "admin.session_idle_timeout".into()
        });
        self.non_zero(admin.session_lifetime, || "admin.session_lifetime".into());
        if admin.max_body_size == 0 {
            self.push("admin.max_body_size", "must be greater than zero");
        }
        if env::var(ADMIN_TOKEN_ENV).is_ok() || admin.bearer_token_file.is_some() {
            return;
        }
        match &admin.bearer_token {
            None => self.push(
                "admin.bearer_token",
                format!("admin requires bearer_token_file, bearer_token, or {ADMIN_TOKEN_ENV}"),
            ),
            Some(token) if token.expose().len() < admin.min_token_len => self.push(
                "admin.bearer_token",
                format!("shorter than min_token_len ({})", admin.min_token_len),
            ),
            Some(_) => {}
        }
    }

    fn capabilities(&mut self) {
        let caps = &self.raw.capabilities;
        for (section, mechs) in [
            ("imap", &caps.imap.sasl),
            ("managesieve", &caps.managesieve.sasl),
            ("submission", &caps.submission.sasl),
            ("pop3", &caps.pop3.sasl),
        ] {
            let mut seen = Vec::with_capacity(mechs.len());
            for (index, mech) in mechs.iter().enumerate() {
                if seen.contains(mech) {
                    self.push(
                        format!("capabilities.{section}.sasl[{index}]"),
                        format!("lists mechanism {} more than once", mech.as_str()),
                    );
                } else {
                    seen.push(*mech);
                }
            }
        }
    }
}
