/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod duration;

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ahash::AHashMap;
use serde::Deserialize;

use crate::error::{ProxyError, Result};
use crate::net::cidr::Cidr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Smtp,
    Submission,
    Lmtp,
    Imap,
    Pop3,
    #[serde(rename = "managesieve")]
    ManageSieve,
    Http,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Smtp => "smtp",
            Protocol::Submission => "submission",
            Protocol::Lmtp => "lmtp",
            Protocol::Imap => "imap",
            Protocol::Pop3 => "pop3",
            Protocol::ManageSieve => "managesieve",
            Protocol::Http => "http",
        }
    }

    pub fn is_credential_bearing(&self) -> bool {
        matches!(
            self,
            Protocol::Imap
                | Protocol::Pop3
                | Protocol::ManageSieve
                | Protocol::Submission
                | Protocol::Http
        )
    }

    pub fn is_passthrough(&self) -> bool {
        matches!(self, Protocol::Smtp | Protocol::Lmtp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    Implicit,
    Starttls,
    Plain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolMode {
    Off,
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ForwardedMode {
    #[default]
    Off,
    Trust,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Forwarding {
    Proxy,
    Xclient,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Normalize {
    #[default]
    None,
    Lowercase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MappingSource {
    File,
    Redis,
    Sql,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub listener: AHashMap<String, ListenerConfig>,
    #[serde(default)]
    pub destination: AHashMap<String, DestinationConfig>,
    pub routing: RoutingConfig,
    pub mapping: MappingConfig,
    #[serde(default)]
    pub capabilities: CapabilitiesConfig,
    #[serde(default)]
    pub oauth: OAuthConfig,
    #[serde(default)]
    pub http: HttpConfig,
    pub admin: Option<AdminConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub threads: usize,
    #[serde(default = "default_shutdown_grace", with = "duration")]
    pub shutdown_grace: Duration,
    #[serde(default = "default_bridge_idle", with = "duration")]
    pub bridge_idle: Duration,
    #[serde(default = "default_backend_timeout", with = "duration")]
    pub backend_timeout: Duration,
    #[serde(default = "default_backend_connect_retries")]
    pub backend_connect_retries: u32,
    #[serde(default = "default_host_down_threshold")]
    pub host_down_threshold: u32,
    #[serde(default = "default_host_down_cooldown", with = "duration")]
    pub host_down_cooldown: Duration,
    #[serde(default = "default_proxy_ttl")]
    pub proxy_ttl: u32,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default)]
    pub hostname: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            threads: 0,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
            bridge_idle: DEFAULT_BRIDGE_IDLE,
            backend_timeout: DEFAULT_BACKEND_TIMEOUT,
            backend_connect_retries: DEFAULT_BACKEND_CONNECT_RETRIES,
            host_down_threshold: DEFAULT_HOST_DOWN_THRESHOLD,
            host_down_cooldown: DEFAULT_HOST_DOWN_COOLDOWN,
            proxy_ttl: DEFAULT_PROXY_TTL,
            log_level: DEFAULT_LOG_LEVEL.to_string(),
            hostname: None,
        }
    }
}

impl ServerConfig {
    pub fn hostname_for(&self, local: SocketAddr) -> String {
        match &self.hostname {
            Some(h) => h.clone(),
            None => local.ip().to_string(),
        }
    }
}

const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(30);
const DEFAULT_BRIDGE_IDLE: Duration = Duration::from_secs(1800);
const DEFAULT_BACKEND_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_BACKEND_CONNECT_RETRIES: u32 = 1;
const DEFAULT_HOST_DOWN_THRESHOLD: u32 = 5;
const DEFAULT_HOST_DOWN_COOLDOWN: Duration = Duration::from_secs(30);
const DEFAULT_PROXY_TTL: u32 = 7;
const DEFAULT_LOG_LEVEL: &str = "info";

fn default_shutdown_grace() -> Duration {
    DEFAULT_SHUTDOWN_GRACE
}
fn default_bridge_idle() -> Duration {
    DEFAULT_BRIDGE_IDLE
}
fn default_backend_timeout() -> Duration {
    DEFAULT_BACKEND_TIMEOUT
}
fn default_backend_connect_retries() -> u32 {
    DEFAULT_BACKEND_CONNECT_RETRIES
}
fn default_host_down_threshold() -> u32 {
    DEFAULT_HOST_DOWN_THRESHOLD
}
fn default_host_down_cooldown() -> Duration {
    DEFAULT_HOST_DOWN_COOLDOWN
}
fn default_proxy_ttl() -> u32 {
    DEFAULT_PROXY_TTL
}
fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}

#[derive(Debug, Default, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub certificate: AHashMap<String, CertificateConfig>,
    #[serde(default)]
    pub protocols: TlsProtocols,
}

#[derive(Debug, Deserialize)]
pub struct CertificateConfig {
    pub cert: String,
    pub key: String,
    #[serde(default)]
    pub subjects: Vec<String>,
    #[serde(default)]
    pub default: bool,
}

#[derive(Debug, Deserialize)]
pub struct TlsProtocols {
    #[serde(default = "default_min_version")]
    pub min_version: String,
    #[serde(default)]
    pub ignore_client_order: bool,
    #[serde(default)]
    pub disable_cipher_suites: Vec<String>,
}

impl Default for TlsProtocols {
    fn default() -> Self {
        TlsProtocols {
            min_version: default_min_version(),
            ignore_client_order: false,
            disable_cipher_suites: Vec::new(),
        }
    }
}

const DEFAULT_MIN_VERSION: &str = "1.2";
fn default_min_version() -> String {
    DEFAULT_MIN_VERSION.to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenerConfig {
    pub protocol: Protocol,
    pub bind: Vec<SocketAddr>,
    pub tls: TlsMode,
    #[serde(default = "default_proxy_off")]
    pub proxy_protocol: ProxyProtocolMode,
    #[serde(default)]
    pub proxy_trusted: Vec<Cidr>,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_preauth_timeout", with = "duration")]
    pub preauth_timeout: Duration,
    #[serde(default = "default_max_auth_attempts")]
    pub max_auth_attempts: u32,
    #[serde(default)]
    pub forwarded: ForwardedMode,
}

const DEFAULT_MAX_CONNECTIONS: usize = 8192;
const DEFAULT_PREAUTH_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_AUTH_ATTEMPTS: u32 = 3;

fn default_proxy_off() -> ProxyProtocolMode {
    ProxyProtocolMode::Off
}
fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS
}
fn default_preauth_timeout() -> Duration {
    DEFAULT_PREAUTH_TIMEOUT
}
fn default_max_auth_attempts() -> u32 {
    DEFAULT_MAX_AUTH_ATTEMPTS
}

#[derive(Debug, Deserialize)]
pub struct DestinationConfig {
    pub host: String,
    #[serde(default)]
    pub tls_server_name: Option<String>,
    #[serde(default = "default_true")]
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
    #[serde(default)]
    pub hide_auth_errors: bool,
    #[serde(default)]
    pub allow_plaintext_auth: bool,
    #[serde(default)]
    pub protocol: AHashMap<Protocol, DestProtocol>,
}

fn default_true() -> bool {
    true
}

impl DestinationConfig {
    pub fn host_is_ip(&self) -> bool {
        self.host.parse::<IpAddr>().is_ok()
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

#[derive(Debug, Clone, Deserialize)]
pub struct DestProtocol {
    pub port: u16,
    pub tls: TlsMode,
    #[serde(default)]
    pub forwarding: Option<Forwarding>,
}

#[derive(Debug, Deserialize)]
pub struct RoutingConfig {
    pub default_destination: String,
    #[serde(default)]
    pub smtp_passthrough_destination: Option<String>,
    #[serde(default = "default_master_user_separators")]
    pub master_user_separators: Vec<String>,
}

const DEFAULT_MASTER_USER_SEPARATORS: &[&str] = &["%"];
fn default_master_user_separators() -> Vec<String> {
    DEFAULT_MASTER_USER_SEPARATORS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct MappingConfig {
    pub source: MappingSource,
    #[serde(default)]
    pub normalize: Normalize,
    #[serde(default = "default_negative_ttl", with = "duration")]
    pub negative_ttl: Duration,
    #[serde(default = "default_positive_ttl", with = "duration")]
    pub positive_ttl: Duration,
    #[serde(default = "default_cache_max")]
    pub cache_max_entries: u64,
    #[serde(default = "default_lookup_timeout", with = "duration")]
    pub lookup_timeout: Duration,
    #[serde(default)]
    pub file: Option<FileMappingConfig>,
    #[serde(default)]
    pub redis: Option<RedisMappingConfig>,
    #[serde(default)]
    pub sql: Option<SqlMappingConfig>,
}

const DEFAULT_NEGATIVE_TTL: Duration = Duration::from_secs(30);
const DEFAULT_POSITIVE_TTL: Duration = Duration::from_secs(600);
const DEFAULT_CACHE_MAX: u64 = 1_000_000;
const DEFAULT_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

fn default_negative_ttl() -> Duration {
    DEFAULT_NEGATIVE_TTL
}
fn default_positive_ttl() -> Duration {
    DEFAULT_POSITIVE_TTL
}
fn default_cache_max() -> u64 {
    DEFAULT_CACHE_MAX
}
fn default_lookup_timeout() -> Duration {
    DEFAULT_LOOKUP_TIMEOUT
}

#[derive(Debug, Deserialize)]
pub struct FileMappingConfig {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct RedisMappingConfig {
    pub url: String,
    #[serde(default = "default_key_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
}

const DEFAULT_KEY_PREFIX: &str = "route:";
const DEFAULT_POOL_SIZE: usize = 16;

fn default_key_prefix() -> String {
    DEFAULT_KEY_PREFIX.to_string()
}
fn default_pool_size() -> usize {
    DEFAULT_POOL_SIZE
}

#[derive(Debug, Deserialize)]
pub struct SqlMappingConfig {
    pub url: String,
    pub query: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default)]
    pub upsert_query: Option<String>,
    #[serde(default)]
    pub delete_query: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CapabilitiesConfig {
    #[serde(default)]
    pub imap: ImapCapabilities,
    #[serde(default)]
    pub managesieve: ManageSieveCapabilities,
    #[serde(default)]
    pub submission: SubmissionCapabilities,
    #[serde(default)]
    pub pop3: Pop3Capabilities,
}

#[derive(Debug, Deserialize)]
pub struct ImapCapabilities {
    #[serde(default = "default_imap_advertise")]
    pub advertise: Vec<String>,
    #[serde(default = "default_sasl")]
    pub sasl: Vec<String>,
    #[serde(default)]
    pub allow_plain_auth_without_tls: bool,
    #[serde(default = "default_imap_banner")]
    pub banner: String,
}

impl Default for ImapCapabilities {
    fn default() -> Self {
        ImapCapabilities {
            advertise: default_imap_advertise(),
            sasl: default_sasl(),
            allow_plain_auth_without_tls: false,
            banner: default_imap_banner(),
        }
    }
}

const DEFAULT_IMAP_ADVERTISE: &[&str] = &[
    "IMAP4rev2",
    "IMAP4rev1",
    "ENABLE",
    "SASL-IR",
    "LITERAL+",
    "ID",
    "UTF8=ACCEPT",
    "JMAPACCESS",
];
const DEFAULT_SASL: &[&str] = &["PLAIN", "OAUTHBEARER", "XOAUTH2"];
const DEFAULT_IMAP_BANNER: &str = "Stalwart IMAP4rev2 at your service.";

fn default_imap_advertise() -> Vec<String> {
    DEFAULT_IMAP_ADVERTISE
        .iter()
        .map(|s| s.to_string())
        .collect()
}
fn default_sasl() -> Vec<String> {
    DEFAULT_SASL.iter().map(|s| s.to_string()).collect()
}
fn default_imap_banner() -> String {
    DEFAULT_IMAP_BANNER.to_string()
}

#[derive(Debug, Deserialize)]
pub struct ManageSieveCapabilities {
    #[serde(default = "default_sieve_ext")]
    pub sieve: Vec<String>,
    #[serde(default = "default_sasl")]
    pub sasl: Vec<String>,
    #[serde(default)]
    pub allow_plain_auth_without_tls: bool,
    #[serde(default = "default_sieve_impl")]
    pub implementation: String,
}

impl Default for ManageSieveCapabilities {
    fn default() -> Self {
        ManageSieveCapabilities {
            sieve: default_sieve_ext(),
            sasl: default_sasl(),
            allow_plain_auth_without_tls: false,
            implementation: default_sieve_impl(),
        }
    }
}

const DEFAULT_SIEVE_EXT: &[&str] = &[
    "body",
    "comparator-elbonia",
    "comparator-i;ascii-casemap",
    "comparator-i;ascii-numeric",
    "comparator-i;octet",
    "convert",
    "copy",
    "date",
    "duplicate",
    "editheader",
    "enclose",
    "encoded-character",
    "enotify",
    "envelope",
    "envelope-deliverby",
    "envelope-dsn",
    "environment",
    "ereject",
    "extlists",
    "extracttext",
    "fcc",
    "fileinto",
    "foreverypart",
    "ihave",
    "imap4flags",
    "imapsieve",
    "include",
    "index",
    "mailbox",
    "mailboxid",
    "mboxmetadata",
    "mime",
    "redirect-deliverby",
    "redirect-dsn",
    "regex",
    "reject",
    "relational",
    "replace",
    "servermetadata",
    "spamtest",
    "spamtestplus",
    "special-use",
    "subaddress",
    "vacation",
    "vacation-seconds",
    "variables",
    "virustest",
];
const DEFAULT_SIEVE_IMPL: &str = "Stalwart ManageSieve";

fn default_sieve_ext() -> Vec<String> {
    DEFAULT_SIEVE_EXT.iter().map(|s| s.to_string()).collect()
}
fn default_sieve_impl() -> String {
    DEFAULT_SIEVE_IMPL.to_string()
}

#[derive(Debug, Deserialize)]
pub struct SubmissionCapabilities {
    #[serde(default = "default_ehlo")]
    pub ehlo: Vec<String>,
    #[serde(default = "default_sasl")]
    pub sasl: Vec<String>,
    #[serde(default)]
    pub allow_plain_auth_without_tls: bool,
    #[serde(default = "default_smtp_banner")]
    pub banner: String,
}

impl Default for SubmissionCapabilities {
    fn default() -> Self {
        SubmissionCapabilities {
            ehlo: default_ehlo(),
            sasl: default_sasl(),
            allow_plain_auth_without_tls: false,
            banner: default_smtp_banner(),
        }
    }
}

const DEFAULT_EHLO: &[&str] = &[
    "ENHANCEDSTATUSCODES",
    "8BITMIME",
    "BINARYMIME",
    "SMTPUTF8",
    "PIPELINING",
    "CHUNKING",
    "REQUIRETLS",
    "SIZE",
];
const DEFAULT_SMTP_BANNER: &str = "at your service.";

fn default_ehlo() -> Vec<String> {
    DEFAULT_EHLO.iter().map(|s| s.to_string()).collect()
}
fn default_smtp_banner() -> String {
    DEFAULT_SMTP_BANNER.to_string()
}

#[derive(Debug, Deserialize)]
pub struct Pop3Capabilities {
    #[serde(default = "default_sasl")]
    pub sasl: Vec<String>,
    #[serde(default)]
    pub allow_plain_auth_without_tls: bool,
    #[serde(default = "default_pop3_banner")]
    pub banner: String,
}

impl Default for Pop3Capabilities {
    fn default() -> Self {
        Pop3Capabilities {
            sasl: default_sasl(),
            allow_plain_auth_without_tls: false,
            banner: default_pop3_banner(),
        }
    }
}
const DEFAULT_POP3_BANNER: &str = "Stalwart POP3 at your service.";
fn default_pop3_banner() -> String {
    DEFAULT_POP3_BANNER.to_string()
}

#[derive(Debug, Deserialize)]
pub struct OAuthConfig {
    #[serde(default = "default_jwt_claim")]
    pub jwt_username_claim: String,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        OAuthConfig {
            jwt_username_claim: default_jwt_claim(),
        }
    }
}
const DEFAULT_JWT_CLAIM: &str = "email";
fn default_jwt_claim() -> String {
    DEFAULT_JWT_CLAIM.to_string()
}

#[derive(Debug, Deserialize)]
pub struct HttpConfig {
    #[serde(default)]
    pub route: Vec<HttpRoute>,
    #[serde(default = "default_body_cap")]
    pub body_extract_cap: usize,
    #[serde(default = "default_head_cap")]
    pub max_head_size: usize,
    #[serde(default = "default_relay_idle", with = "duration")]
    pub relay_idle: Duration,
    #[serde(default = "default_keepalive_timeout", with = "duration")]
    pub keepalive_timeout: Duration,
    #[serde(default = "default_max_keepalive_requests")]
    pub max_keepalive_requests: u32,
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            route: Vec::new(),
            body_extract_cap: DEFAULT_BODY_CAP,
            max_head_size: DEFAULT_HEAD_CAP,
            relay_idle: DEFAULT_RELAY_IDLE,
            keepalive_timeout: DEFAULT_KEEPALIVE_TIMEOUT,
            max_keepalive_requests: DEFAULT_MAX_KEEPALIVE_REQUESTS,
        }
    }
}

const DEFAULT_BODY_CAP: usize = 64 * 1024;
const DEFAULT_HEAD_CAP: usize = 64 * 1024;
const DEFAULT_RELAY_IDLE: Duration = Duration::from_secs(60);
const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(75);
const DEFAULT_MAX_KEEPALIVE_REQUESTS: u32 = 1000;

fn default_body_cap() -> usize {
    DEFAULT_BODY_CAP
}
fn default_head_cap() -> usize {
    DEFAULT_HEAD_CAP
}
fn default_relay_idle() -> Duration {
    DEFAULT_RELAY_IDLE
}
fn default_keepalive_timeout() -> Duration {
    DEFAULT_KEEPALIVE_TIMEOUT
}
fn default_max_keepalive_requests() -> u32 {
    DEFAULT_MAX_KEEPALIVE_REQUESTS
}

#[derive(Debug, Deserialize)]
pub struct HttpRoute {
    #[serde(rename = "match")]
    pub match_glob: String,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub extract: Option<HttpExtract>,
    #[serde(default)]
    pub fallback: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpExtract {
    pub from: ExtractFrom,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub param: Option<String>,
    #[serde(default)]
    pub header: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtractFrom {
    Authorization,
    Query,
    Body,
    Header,
}

#[derive(Debug, Deserialize)]
pub struct AdminConfig {
    pub bind: SocketAddr,
    #[serde(default = "default_admin_tls")]
    pub tls: TlsMode,
    #[serde(default)]
    pub bearer_token_file: Option<String>,
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default = "default_min_token_len")]
    pub min_token_len: usize,
    #[serde(default = "default_lockout_threshold")]
    pub lockout_threshold: u32,
    #[serde(default = "default_lockout_duration", with = "duration")]
    pub lockout_duration: Duration,
}

const DEFAULT_MIN_TOKEN_LEN: usize = 32;
const DEFAULT_LOCKOUT_THRESHOLD: u32 = 5;
const DEFAULT_LOCKOUT_DURATION: Duration = Duration::from_secs(300);

fn default_admin_tls() -> TlsMode {
    TlsMode::Implicit
}
fn default_min_token_len() -> usize {
    DEFAULT_MIN_TOKEN_LEN
}
fn default_lockout_threshold() -> u32 {
    DEFAULT_LOCKOUT_THRESHOLD
}
fn default_lockout_duration() -> Duration {
    DEFAULT_LOCKOUT_DURATION
}

impl Config {
    pub fn parse_and_validate(raw: &str) -> Result<Self> {
        let config: Config =
            toml::from_str(raw).map_err(|e| ProxyError::config(format!("TOML parse: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    fn destination(&self, id: &str) -> Result<&DestinationConfig> {
        self.destination
            .get(id)
            .ok_or_else(|| ProxyError::config(format!("undeclared destination {id:?}")))
    }

    fn validate(&self) -> Result<()> {
        let has_lmtp_listener = self.listener.values().any(|l| l.protocol == Protocol::Lmtp);

        let default_dest = self.destination(&self.routing.default_destination)?;

        for (id, listener) in &self.listener {
            if listener.bind.is_empty() {
                return Err(ProxyError::config(format!(
                    "listener {id:?} has no bind addresses"
                )));
            }
            if matches!(
                listener.proxy_protocol,
                ProxyProtocolMode::Optional | ProxyProtocolMode::Required
            ) && listener.proxy_trusted.is_empty()
            {
                return Err(ProxyError::config(format!(
                    "listener {id:?} uses proxy_protocol but proxy_trusted is empty"
                )));
            }
            if listener.protocol.is_passthrough() {
                if listener.tls == TlsMode::Starttls {
                    return Err(ProxyError::config(format!(
                        "listener {id:?} is a pass-through ({}) and cannot use tls=starttls (the proxy bridges raw and does not terminate STARTTLS); use plain or implicit",
                        listener.protocol.as_str()
                    )));
                }
                continue;
            }
            if listener.protocol == Protocol::Http {
                continue;
            }
            if !default_dest.protocol.contains_key(&listener.protocol) {
                return Err(ProxyError::config(format!(
                    "default_destination {:?} does not declare protocol {} required by listener {id:?}",
                    self.routing.default_destination,
                    listener.protocol.as_str()
                )));
            }
        }

        if let Some(pt) = &self.routing.smtp_passthrough_destination {
            let dest = self.destination(pt)?;
            if !dest.protocol.contains_key(&Protocol::Smtp) {
                return Err(ProxyError::config(format!(
                    "smtp_passthrough_destination {pt:?} must declare the smtp protocol"
                )));
            }
            if has_lmtp_listener && !dest.protocol.contains_key(&Protocol::Lmtp) {
                return Err(ProxyError::config(format!(
                    "smtp_passthrough_destination {pt:?} must declare lmtp (an lmtp listener exists)"
                )));
            }
        } else if self.listener.values().any(|l| l.protocol.is_passthrough()) {
            return Err(ProxyError::config(
                "smtp/lmtp listener configured but routing.smtp_passthrough_destination is unset",
            ));
        }

        for (id, dest) in &self.destination {
            self.validate_destination(id, dest)?;
        }

        for route in &self.http.route {
            globset::Glob::new(&route.match_glob).map_err(|e| {
                ProxyError::config(format!(
                    "invalid http route glob {:?}: {e}",
                    route.match_glob
                ))
            })?;
            if let Some(dest_id) = &route.destination {
                let dest = self.destination(dest_id)?;
                if !dest.protocol.contains_key(&Protocol::Http) {
                    return Err(ProxyError::config(format!(
                        "http route destination {dest_id:?} does not declare the http protocol"
                    )));
                }
            }
            if let Some(extract) = &route.extract {
                if extract.from == ExtractFrom::Body && extract.regex.is_none() {
                    return Err(ProxyError::config(
                        "http extract from=body requires a regex",
                    ));
                }
                if extract.from == ExtractFrom::Query && extract.param.is_none() {
                    return Err(ProxyError::config(
                        "http extract from=query requires a param",
                    ));
                }
                if extract.from == ExtractFrom::Header && extract.header.is_none() {
                    return Err(ProxyError::config(
                        "http extract from=header requires a header name",
                    ));
                }
                if let Some(re) = &extract.regex {
                    regex::Regex::new(re).map_err(|e| {
                        ProxyError::config(format!("invalid http extract regex {re:?}: {e}"))
                    })?;
                }
            }
        }

        match self.mapping.source {
            MappingSource::File if self.mapping.file.is_none() => {
                return Err(ProxyError::config(
                    "mapping.source=file requires [mapping.file]",
                ));
            }
            MappingSource::Redis if self.mapping.redis.is_none() => {
                return Err(ProxyError::config(
                    "mapping.source=redis requires [mapping.redis]",
                ));
            }
            MappingSource::Sql if self.mapping.sql.is_none() => {
                return Err(ProxyError::config(
                    "mapping.source=sql requires [mapping.sql]",
                ));
            }
            _ => {}
        }

        if let Some(admin) = &self.admin {
            if admin.tls != TlsMode::Implicit {
                return Err(ProxyError::config(
                    "admin.tls must be implicit (plaintext admin is rejected)",
                ));
            }
            if admin.bearer_token_file.is_none()
                && admin.bearer_token.is_none()
                && std::env::var("PROXY_ADMIN_TOKEN").is_err()
            {
                return Err(ProxyError::config(
                    "admin requires bearer_token_file, bearer_token, or PROXY_ADMIN_TOKEN",
                ));
            }
        }

        Ok(())
    }

    fn validate_destination(&self, id: &str, dest: &DestinationConfig) -> Result<()> {
        let host_is_ip = dest.host_is_ip();
        for (proto, ep) in &dest.protocol {
            if proto.is_credential_bearing()
                && ep.tls == TlsMode::Plain
                && !dest.allow_plaintext_auth
            {
                return Err(ProxyError::config(format!(
                    "destination {id:?} protocol {} uses plaintext TLS but carries credentials; set allow_plaintext_auth to override",
                    proto.as_str()
                )));
            }
            if host_is_ip && ep.tls != TlsMode::Plain && dest.tls_server_name.is_none() {
                return Err(ProxyError::config(format!(
                    "destination {id:?} has an IP host and a TLS leg ({}) but no tls_server_name",
                    proto.as_str()
                )));
            }
        }
        Ok(())
    }
}
