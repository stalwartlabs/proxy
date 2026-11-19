/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use smallvec::SmallVec;

use super::super::session::SessionView;
use crate::config::{
    DestProtocol, DestinationConfig, ForwardedMode, Forwarding, Protocol, ProxyProtocolMode,
    TlsMode,
};
use crate::error::{ConfigError, ConfigErrors};
use crate::net::cidr::Cidr;
use crate::route::TRANSIENT_TTL;
use crate::runtime::health::{HealthSnapshot, LastFailure, Millis};
use crate::runtime::metrics::{Sample, Totals};
use crate::runtime::time::UtcTime;
use crate::runtime::{DestId, Runtime};

#[derive(Serialize)]
pub struct SessionBody {
    csrf: String,
    idle_timeout_s: u64,
    expires_at: UtcTime,
}

impl From<&SessionView> for SessionBody {
    fn from(view: &SessionView) -> Self {
        SessionBody {
            csrf: view.csrf.encoded(),
            idle_timeout_s: view.idle_timeout.as_secs(),
            expires_at: UtcTime(view.expires_at),
        }
    }
}

pub struct Name(pub Option<Arc<str>>);

impl Serialize for Name {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.as_deref().serialize(serializer)
    }
}

pub struct ProtocolCounts<'a>(pub &'a [usize; Protocol::COUNT]);

impl Serialize for ProtocolCounts<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(Protocol::COUNT))?;
        for (protocol, count) in Protocol::ALL.iter().zip(self.0) {
            map.serialize_entry(protocol.as_str(), count)?;
        }
        map.end()
    }
}

#[derive(Serialize)]
pub struct Counters {
    accepted: u64,
    rejected_limit: u64,
    auth_ok: u64,
    auth_rejected: u64,
    backend_failures: u64,
}

impl From<Totals> for Counters {
    fn from(totals: Totals) -> Self {
        Counters {
            accepted: totals.accepted,
            rejected_limit: totals.rejected_limit,
            auth_ok: totals.auth_ok,
            auth_rejected: totals.auth_rejected,
            backend_failures: totals.backend_failures,
        }
    }
}

#[derive(Serialize)]
pub struct CacheTtl {
    positive_ms: u64,
    negative_ms: u64,
    transient_ms: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum CacheBound {
    MaxEntries(u64),
    MaxBytes(u64),
}

#[derive(Serialize)]
pub struct CacheView {
    entries: u64,
    #[serde(flatten)]
    bound: CacheBound,
    hits: u64,
    misses: u64,
    hit_rate_pct: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<CacheTtl>,
}

pub enum WithTtl {
    Yes,
    No,
}

impl CacheView {
    pub fn of(rt: &Runtime, ttl: WithTtl) -> Self {
        let counters = rt.router.stats.snapshot();
        let mapping = rt.raw.mapping.as_ref();
        let millis = |ttl: Duration| u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX);
        CacheView {
            entries: rt.router.cache_entries(),
            bound: match mapping {
                Some(mapping) => match mapping.cache_max_bytes {
                    Some(bytes) => CacheBound::MaxBytes(bytes),
                    None => CacheBound::MaxEntries(mapping.cache_max_entries),
                },
                None => CacheBound::MaxEntries(0),
            },
            hits: counters.hits,
            misses: counters.misses,
            hit_rate_pct: counters.hit_rate_pct(),
            ttl: match (ttl, mapping) {
                (WithTtl::Yes, Some(mapping)) => Some(CacheTtl {
                    positive_ms: millis(mapping.positive_ttl),
                    negative_ms: millis(mapping.negative_ttl),
                    transient_ms: millis(TRANSIENT_TTL.min(mapping.negative_ttl)),
                }),
                (WithTtl::Yes, None) | (WithTtl::No, _) => None,
            },
        }
    }
}

pub struct Points<'a>(pub &'a [Sample]);

impl Serialize for Points<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for sample in self.0 {
            seq.serialize_element(&[
                sample.sessions,
                sample.accepted,
                sample.auth_ok,
                sample.auth_rejected,
                sample.backend_failures,
                sample.cache_hits,
                sample.cache_misses,
            ])?;
        }
        seq.end()
    }
}

pub const SERIES_FIELDS: [&str; 7] = [
    "active",
    "accepted",
    "auth_ok",
    "auth_rejected",
    "backend_failures",
    "cache_hits",
    "cache_misses",
];

#[derive(Serialize)]
pub struct EndpointView {
    port: u16,
    tls: TlsMode,
    forwarding: Forwarding,
}

struct EndpointMap<'a>(&'a DestinationConfig);

impl Serialize for EndpointMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let dest = self.0;
        let mut entries: SmallVec<[(Protocol, &DestProtocol); Protocol::COUNT]> = dest
            .protocol
            .iter()
            .map(|(protocol, endpoint)| (*protocol, endpoint))
            .collect();
        entries.sort_unstable_by_key(|(protocol, _)| protocol.index());
        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for (protocol, endpoint) in entries {
            map.serialize_entry(
                protocol.as_str(),
                &EndpointView {
                    port: endpoint.port,
                    tls: endpoint.tls,
                    forwarding: dest.forwarding_for(protocol),
                },
            )?;
        }
        map.end()
    }
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum TlsVerify {
    Platform,
    Pinned,
    Insecure,
}

#[derive(Serialize)]
struct FailureView<'a> {
    at: UtcTime,
    stage: &'static str,
    class: &'static str,
    error: &'a str,
}

#[derive(Serialize)]
struct HealthView<'a> {
    state: &'static str,
    consecutive_failures: u32,
    failure_sources: u32,
    host_level_failure: bool,
    down_until: Option<UtcTime>,
    last_failure: Option<FailureView<'a>>,
}

#[derive(Serialize)]
pub struct DestinationView<'a> {
    id: &'a str,
    host: &'a str,
    tls_server_name: Option<&'a str>,
    protocols: EndpointMap<'a>,
    forwarding: Forwarding,
    forwarded: bool,
    tls_verify: TlsVerify,
    tls_client_cert: bool,
    source_ips: &'a [IpAddr],
    hide_auth_errors: bool,
    allow_plaintext_auth: bool,
    roles: &'static [&'static str],
    health: HealthView<'a>,
    sessions: usize,
    mapped_identifiers: Option<u64>,
}

pub struct DestinationStats {
    pub sessions: usize,
    pub mapped: Option<u64>,
}

impl<'a> DestinationView<'a> {
    pub fn new(
        rt: &Runtime,
        id: DestId,
        name: &'a str,
        config: &'a DestinationConfig,
        health: &'a HealthSnapshot,
        stats: DestinationStats,
    ) -> Self {
        let roles: &'static [&'static str] =
            match (rt.default_dest == Some(id), rt.passthrough_dest == Some(id)) {
                (true, true) => &["default", "passthrough"],
                (true, false) => &["default"],
                (false, true) => &["passthrough"],
                (false, false) => &[],
            };
        let wall = |at: Millis| UtcTime(rt.shared.clock.wall(at));
        DestinationView {
            id: name,
            host: &config.host,
            tls_server_name: config.tls_server_name.as_deref(),
            protocols: EndpointMap(config),
            forwarding: config.forwarding.unwrap_or(match config.proxy_protocol {
                true => Forwarding::Proxy,
                false => Forwarding::None,
            }),
            forwarded: config.forwarded,
            tls_verify: match (
                config.tls_pinned_cert_sha256.is_some(),
                config.tls_allow_invalid_certs,
            ) {
                (true, _) => TlsVerify::Pinned,
                (false, true) => TlsVerify::Insecure,
                (false, false) => TlsVerify::Platform,
            },
            tls_client_cert: config.tls_client_cert.is_some(),
            source_ips: &config.source_ips,
            hide_auth_errors: config.hide_auth_errors,
            allow_plaintext_auth: config.allow_plaintext_auth,
            roles,
            health: HealthView {
                state: health.state.as_str(),
                consecutive_failures: health.consecutive_failures,
                failure_sources: health.failure_sources,
                host_level_failure: health.host_level_failure,
                down_until: health.down_until.map(wall),
                last_failure: health.last_failure.as_ref().map(|failure: &LastFailure| {
                    FailureView {
                        at: wall(failure.at),
                        stage: failure.stage.as_str(),
                        class: failure.class.as_str(),
                        error: &failure.error,
                    }
                }),
            },
            sessions: stats.sessions,
            mapped_identifiers: stats.mapped,
        }
    }
}

#[derive(Serialize)]
pub struct ListenerView<'a> {
    pub id: &'a str,
    pub protocol: Protocol,
    pub bind: &'a [SocketAddr],
    pub tls: TlsMode,
    pub proxy_protocol: ProxyProtocolMode,
    pub proxy_trusted: &'a [Cidr],
    pub max_connections: usize,
    pub sessions: usize,
    pub preauth_timeout_s: u64,
    pub max_auth_attempts: u32,
    pub forwarded: ForwardedMode,
    pub accepted: u64,
    pub rejected_limit: u64,
}

pub fn remaining(until: Instant) -> Duration {
    until.saturating_duration_since(Instant::now())
}

#[derive(Serialize)]
struct ErrorItem<'a> {
    path: &'a str,
    message: &'a str,
    line: Option<u32>,
}

pub struct ErrorList<'a>(pub &'a [ConfigError]);

impl Serialize for ErrorList<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|error| ErrorItem {
            path: &error.path,
            message: &error.message,
            line: error.line,
        }))
    }
}

#[derive(Serialize)]
pub struct Invalid<'a> {
    pub valid: bool,
    pub errors: ErrorList<'a>,
}

impl<'a> Invalid<'a> {
    pub fn of(errors: &'a ConfigErrors) -> Self {
        Invalid {
            valid: false,
            errors: ErrorList(&errors.0),
        }
    }
}

impl UtcTime {
    pub fn after(left: Duration) -> UtcTime {
        UtcTime(
            SystemTime::now()
                .checked_add(left)
                .unwrap_or_else(SystemTime::now),
        )
    }
}
