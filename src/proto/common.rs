/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::{AHashMap, AHashSet};
use parking_lot::Mutex;

use rustls::ClientConfig;
use rustls::crypto::CryptoProvider;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsAcceptor;

use crate::config::{Config, DestProtocol, DestinationConfig, Forwarding, Protocol, TlsMode};
use crate::error::{ProxyError, Result};
use crate::imap_receiver::Mechanism;
use crate::net::BoxedStream;
use crate::net::tls;
use crate::sasl::Credential;

pub struct Handoff {
    pub stream: BoxedStream,
    pub mech: Mechanism,
    pub raw_challenge: Vec<u8>,
    pub identifier: Option<String>,
    pub residual: Vec<u8>,
}

pub struct Resume {
    pub stream: BoxedStream,
    pub buf: Vec<u8>,
}

pub fn take_rest(it: &mut std::slice::Iter<'_, u8>) -> Vec<u8> {
    let rest = it.as_slice().to_vec();
    *it = Default::default();
    rest
}

pub fn bump(failures: &mut u32, max: u32) -> bool {
    *failures += 1;
    *failures >= max
}

pub fn credential_from_sasl(mech: &Mechanism, raw: &[u8]) -> Option<Credential> {
    match mech {
        Mechanism::Plain => Credential::decode_sasl_challenge_plain(raw),
        Mechanism::OAuthBearer | Mechanism::XOauth2 => Credential::decode_sasl_challenge_oauth(raw),
        _ => None,
    }
}

pub fn mechanism_name(mech: &Mechanism) -> &'static str {
    match mech {
        Mechanism::OAuthBearer => "OAUTHBEARER",
        Mechanism::XOauth2 => "XOAUTH2",
        _ => "PLAIN",
    }
}

#[derive(Default)]
pub struct Greetings {
    pub imap: GreetingVariants,
    pub pop3: GreetingVariants,
    pub managesieve: GreetingVariants,
}

#[derive(Default)]
pub struct GreetingVariants {
    variants: [Arc<str>; 4],
}

impl GreetingVariants {
    fn build(mut f: impl FnMut(bool, bool) -> String) -> Self {
        GreetingVariants {
            variants: [
                Arc::from(f(false, false).as_str()),
                Arc::from(f(false, true).as_str()),
                Arc::from(f(true, false).as_str()),
                Arc::from(f(true, true).as_str()),
            ],
        }
    }

    pub fn get(&self, is_tls: bool, offer_starttls: bool) -> &Arc<str> {
        &self.variants[(is_tls as usize) * 2 + (offer_starttls as usize)]
    }
}

pub fn build_greetings(config: &Config) -> Greetings {
    let caps = &config.capabilities;
    Greetings {
        imap: GreetingVariants::build(|is_tls, off| {
            crate::proto::imap::capability_string(&caps.imap, off, is_tls)
        }),
        pop3: GreetingVariants::build(|is_tls, off| {
            let plain_ok = plain_auth_allowed(caps.pop3.allow_plain_auth_without_tls, is_tls);
            crate::proto::pop3::capa_response(&caps.pop3, off, plain_ok)
        }),
        managesieve: GreetingVariants::build(|is_tls, off| {
            crate::proto::managesieve::capability_block(&caps.managesieve, off, is_tls)
        }),
    }
}

pub const LOGIN_USERNAME_CHALLENGE: &str = "VXNlcm5hbWU6";
pub const LOGIN_PASSWORD_CHALLENGE: &str = "UGFzc3dvcmQ6";

pub fn is_cleartext_mechanism(mech: &str) -> bool {
    mech.eq_ignore_ascii_case("PLAIN") || mech.eq_ignore_ascii_case("LOGIN")
}

pub fn advertised_sasl(sasl: &[String], plain_ok: bool) -> Vec<&str> {
    sasl.iter()
        .filter(|m| plain_ok || !is_cleartext_mechanism(m))
        .map(|s| s.as_str())
        .collect()
}

pub fn sasl_offered(sasl: &[String], mech: &str) -> bool {
    sasl.iter().any(|m| m.eq_ignore_ascii_case(mech))
}

pub fn sasl_cancelled(response: &[u8]) -> bool {
    response.trim_ascii() == b"*"
}

pub fn login_challenge(username_b64: &[u8], password_b64: &[u8]) -> Option<Vec<u8>> {
    let username = crate::sasl::decode_sasl_ir(username_b64)?;
    let password = crate::sasl::decode_sasl_ir(password_b64)?;
    let mut raw = Vec::with_capacity(username.len() + password.len() + 2);
    raw.push(0);
    raw.extend_from_slice(&username);
    raw.push(0);
    raw.extend_from_slice(&password);
    Some(raw)
}

pub fn advertises_token(haystack: &[u8], token: &str) -> bool {
    haystack
        .split(|b| *b == b'\n' || *b == b'\r')
        .map(strip_smtp_status)
        .any(|line| {
            line.split(|b| b.is_ascii_whitespace() || *b == b'[' || *b == b']' || *b == b'"')
                .any(|word| word.eq_ignore_ascii_case(token.as_bytes()))
        })
}

fn strip_smtp_status(line: &[u8]) -> &[u8] {
    if line.len() >= 4
        && line[..3].iter().all(u8::is_ascii_digit)
        && (line[3] == b'-' || line[3] == b' ')
    {
        &line[4..]
    } else {
        line
    }
}

pub struct DestRuntime {
    pub mail_tls: Arc<ClientConfig>,
    pub http_tls: Arc<ClientConfig>,
}

#[derive(Default)]
pub struct Metrics {
    pub active_connections: std::sync::atomic::AtomicI64,
}

#[derive(Default)]
pub struct DestHealth {
    inner: Mutex<HealthState>,
}

#[derive(Default)]
struct HealthState {
    consecutive_failures: u32,
    failure_sources: AHashSet<IpAddr>,
    host_level_failure: bool,
    down_until: Option<Instant>,
}

impl HealthState {
    fn clear_evidence(&mut self) {
        self.failure_sources.clear();
        self.host_level_failure = false;
    }
}

const MAX_TRACKED_FAILURE_SOURCES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Attribution {
    Host,
    Client(IpAddr),
}

impl Attribution {
    fn of(err: &ProxyError, peer: IpAddr) -> Self {
        match err {
            ProxyError::BackendConnect(_) => Attribution::Host,
            _ => Attribution::Client(peer),
        }
    }
}

impl DestHealth {
    fn gate(&self) -> Result<()> {
        let mut st = self.inner.lock();
        if let Some(until) = st.down_until {
            if Instant::now() < until {
                return Err(ProxyError::backend(
                    "destination temporarily marked down after repeated failures",
                ));
            }
            st.down_until = None;
            st.clear_evidence();
        }
        Ok(())
    }

    fn record_success(&self) {
        let mut st = self.inner.lock();
        st.consecutive_failures = 0;
        st.clear_evidence();
        st.down_until = None;
    }

    fn record_failure(&self, at: Attribution, limits: &HealthLimits) {
        let mut st = self.inner.lock();
        st.consecutive_failures = st.consecutive_failures.saturating_add(1);
        match at {
            Attribution::Host => st.host_level_failure = true,
            Attribution::Client(ip) => {
                if st.failure_sources.len() < MAX_TRACKED_FAILURE_SOURCES {
                    st.failure_sources.insert(ip);
                }
            }
        }
        let broad = st.host_level_failure || st.failure_sources.len() as u32 >= limits.min_clients;
        if limits.threshold > 0 && st.consecutive_failures >= limits.threshold && broad {
            st.down_until = Some(Instant::now() + limits.cooldown);
        }
    }

    pub fn reset(&self) {
        let mut st = self.inner.lock();
        st.consecutive_failures = 0;
        st.clear_evidence();
        st.down_until = None;
    }

    pub fn snapshot(&self) -> HealthSnapshot {
        let st = self.inner.lock();
        let down = matches!(st.down_until, Some(until) if Instant::now() < until);
        HealthSnapshot {
            consecutive_failures: st.consecutive_failures,
            failure_sources: st.failure_sources.len() as u32,
            host_level_failure: st.host_level_failure,
            down,
        }
    }
}

pub struct HealthLimits {
    threshold: u32,
    min_clients: u32,
    cooldown: Duration,
}

impl HealthLimits {
    fn for_server(server: &crate::config::ServerConfig) -> Self {
        HealthLimits {
            threshold: server.host_down_threshold,
            min_clients: server.host_down_min_clients,
            cooldown: server.host_down_cooldown,
        }
    }
}

pub struct HealthSnapshot {
    pub consecutive_failures: u32,
    pub failure_sources: u32,
    pub host_level_failure: bool,
    pub down: bool,
}

const REGISTRY_SHARDS: usize = 32;

struct LiveConn {
    id: u64,
    cancel: tokio::sync::watch::Sender<bool>,
}

#[derive(Default)]
struct Shard {
    live: HashMap<Arc<str>, Vec<LiveConn>>,
    delays: HashMap<Arc<str>, Instant>,
}

#[derive(Clone)]
pub struct ConnRegistry {
    shards: Arc<[Mutex<Shard>]>,
}

impl Default for ConnRegistry {
    fn default() -> Self {
        let shards = (0..REGISTRY_SHARDS)
            .map(|_| Mutex::new(Shard::default()))
            .collect::<Vec<_>>();
        ConnRegistry {
            shards: shards.into(),
        }
    }
}

pub struct ConnGuard {
    shards: Arc<[Mutex<Shard>]>,
    shard_idx: usize,
    identifier: Arc<str>,
    id: u64,
    rx: tokio::sync::watch::Receiver<bool>,
}

fn shard_index(identifier: &str, shards: usize) -> usize {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    identifier.hash(&mut hasher);
    (hasher.finish() as usize) % shards
}

impl ConnRegistry {
    fn shard_idx(&self, identifier: &str) -> usize {
        shard_index(identifier, self.shards.len())
    }

    pub fn register(&self, identifier: &str) -> ConnGuard {
        let (cancel, rx) = tokio::sync::watch::channel(false);
        self.insert(identifier, cancel, rx)
    }

    pub fn register_cancel(
        &self,
        identifier: &str,
        cancel: tokio::sync::watch::Sender<bool>,
    ) -> ConnGuard {
        let rx = cancel.subscribe();
        self.insert(identifier, cancel, rx)
    }

    fn insert(
        &self,
        identifier: &str,
        cancel: tokio::sync::watch::Sender<bool>,
        rx: tokio::sync::watch::Receiver<bool>,
    ) -> ConnGuard {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let id = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let key: Arc<str> = Arc::from(identifier);
        let shard_idx = self.shard_idx(&key);
        self.shards[shard_idx]
            .lock()
            .live
            .entry(key.clone())
            .or_default()
            .push(LiveConn { id, cancel });
        ConnGuard {
            shards: self.shards.clone(),
            shard_idx,
            identifier: key,
            id,
            rx,
        }
    }

    pub fn kick(&self, identifier: &str) -> usize {
        let shard = self.shards[self.shard_idx(identifier)].lock();
        match shard.live.get(identifier) {
            Some(conns) => {
                for c in conns {
                    let _ = c.cancel.send(true);
                }
                conns.len()
            }
            None => 0,
        }
    }

    pub fn set_delay(&self, identifier: &str, until: Instant) {
        let mut shard = self.shards[self.shard_idx(identifier)].lock();
        let now = Instant::now();
        shard.delays.retain(|_, &mut u| u > now);
        shard.delays.insert(Arc::from(identifier), until);
    }

    pub fn delay_remaining(&self, identifier: &str) -> Option<Duration> {
        let mut shard = self.shards[self.shard_idx(identifier)].lock();
        if let Some(&until) = shard.delays.get(identifier) {
            let now = Instant::now();
            if now < until {
                return Some(until - now);
            }
            shard.delays.remove(identifier);
        }
        None
    }
}

impl ConnGuard {
    pub fn cancel(&self) -> tokio::sync::watch::Receiver<bool> {
        self.rx.clone()
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let mut shard = self.shards[self.shard_idx].lock();
        if let Some(conns) = shard.live.get_mut(self.identifier.as_ref()) {
            conns.retain(|c| c.id != self.id);
            if conns.is_empty() {
                shard.live.remove(self.identifier.as_ref());
            }
        }
    }
}

pub struct DialedEndpoint<'a> {
    pub dest: &'a DestinationConfig,
    pub ep: &'a DestProtocol,
    pub tls_cfg: Arc<ClientConfig>,
    pub forwarding: Forwarding,
    pub backend: BoxedStream,
}

pub struct Ctx {
    pub config: Arc<Config>,
    pub router: Arc<crate::route::Router>,
    pub http_router: Arc<crate::http::router::HttpRouter>,
    pub tls_acceptor: Option<TlsAcceptor>,
    pub dests: AHashMap<String, DestRuntime>,
    pub dest_health: AHashMap<String, DestHealth>,
    pub self_binds: AHashSet<std::net::SocketAddr>,
    pub conns: Arc<ConnRegistry>,
    pub metrics: Arc<Metrics>,
    pub greetings: Greetings,
}

impl Ctx {
    pub fn build_dest_runtimes(
        config: &Config,
        provider: &Arc<CryptoProvider>,
    ) -> Result<AHashMap<String, DestRuntime>> {
        let mut map = AHashMap::new();
        for (id, dest) in &config.destination {
            let mail_tls = tls::build_client_config(dest, provider.clone(), false)?;
            let http_tls = tls::build_client_config(dest, provider.clone(), true)?;
            map.insert(id.clone(), DestRuntime { mail_tls, http_tls });
        }
        Ok(map)
    }

    pub fn build_dest_health(config: &Config) -> AHashMap<String, DestHealth> {
        config
            .destination
            .keys()
            .map(|id| (id.clone(), DestHealth::default()))
            .collect()
    }

    pub fn build_self_binds(config: &Config) -> AHashSet<std::net::SocketAddr> {
        config
            .listener
            .values()
            .flat_map(|l| l.bind.iter().copied())
            .collect()
    }

    pub fn destination(&self, id: &str) -> Result<&DestinationConfig> {
        self.config
            .destination
            .get(id)
            .ok_or_else(|| ProxyError::backend(format!("unknown destination {id:?}")))
    }

    pub fn endpoint(
        &self,
        dest_id: &str,
        protocol: Protocol,
    ) -> Result<(&DestinationConfig, &DestProtocol, Arc<ClientConfig>)> {
        let dest = self.destination(dest_id)?;
        let ep = dest.protocol.get(&protocol).ok_or_else(|| {
            ProxyError::backend(format!(
                "destination {dest_id:?} does not support protocol {}",
                protocol.as_str()
            ))
        })?;
        let runtime = self
            .dests
            .get(dest_id)
            .ok_or_else(|| ProxyError::backend("missing destination runtime"))?;
        let tls_cfg = if protocol == Protocol::Http {
            runtime.http_tls.clone()
        } else {
            runtime.mail_tls.clone()
        };
        Ok((dest, ep, tls_cfg))
    }

    pub async fn dial_endpoint(
        &self,
        dest_id: &str,
        protocol: Protocol,
        peer: SocketAddr,
        local: SocketAddr,
    ) -> Result<DialedEndpoint<'_>> {
        let (dest, ep, tls_cfg) = self.endpoint(dest_id, protocol)?;
        let forwarding = dest.forwarding_for(protocol);
        crate::proto::forward::guard_loop(
            &self.self_binds,
            dest,
            ep,
            forwarding,
            self.config.server.proxy_ttl,
        )?;
        let backend = crate::outbound::dial(dest, ep, forwarding, &tls_cfg, peer, local).await?;
        Ok(DialedEndpoint {
            dest,
            ep,
            tls_cfg,
            forwarding,
            backend,
        })
    }

    pub async fn resolve(&self, identifier: Option<&str>) -> Arc<str> {
        self.router.resolve(identifier).await
    }

    pub fn register_conn(&self, identifier: &str) -> ConnGuard {
        self.conns.register(&self.router.normalize(identifier))
    }

    pub fn register_conn_cancel(
        &self,
        identifier: &str,
        cancel: tokio::sync::watch::Sender<bool>,
    ) -> ConnGuard {
        self.conns
            .register_cancel(&self.router.normalize(identifier), cancel)
    }

    pub fn routing_identifier(&self, identifier: Option<String>) -> Option<String> {
        let mut id = identifier?;
        let account =
            crate::route::master_account(&id, &self.config.routing.master_user_separators);
        id.truncate(account.len());
        (!id.is_empty()).then_some(id)
    }

    pub fn hide_auth_errors(&self, dest_id: &str) -> bool {
        self.destination(dest_id)
            .map(|d| d.hide_auth_errors)
            .unwrap_or(false)
    }
}

pub fn plain_auth_allowed(allow_without_tls: bool, is_tls: bool) -> bool {
    allow_without_tls || is_tls
}

pub fn assert_egress_encrypted(
    dest: &DestinationConfig,
    ep: &DestProtocol,
    leg_is_tls: bool,
) -> Result<()> {
    if leg_is_tls {
        return Ok(());
    }
    if ep.tls == TlsMode::Plain && dest.allow_plaintext_auth {
        return Ok(());
    }
    Err(ProxyError::backend(
        "refusing to send credentials over an unencrypted backend leg",
    ))
}

const BACKEND_RETRY_DELAY: Duration = Duration::from_millis(200);

pub async fn establish<F, Fut, T>(
    ctx: &Ctx,
    dest_id: &str,
    peer: SocketAddr,
    mut open: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    if let Some(health) = ctx.dest_health.get(dest_id) {
        health.gate()?;
    }

    let server = &ctx.config.server;
    let limits = HealthLimits::for_server(server);
    let mut attempt: u32 = 0;
    loop {
        let outcome = match tokio::time::timeout(server.backend_timeout, open()).await {
            Ok(res) => res,
            Err(_) => Err(ProxyError::backend_connect(
                "backend establishment timed out",
            )),
        };

        match outcome {
            Ok(value) => {
                if let Some(health) = ctx.dest_health.get(dest_id) {
                    health.record_success();
                }
                return Ok(value);
            }
            Err(err) => {
                if err.is_retryable() && attempt < server.backend_connect_retries {
                    attempt += 1;
                    tracing::debug!(
                        destination = %dest_id,
                        attempt,
                        error = %err,
                        "retrying backend connection"
                    );
                    tokio::time::sleep(BACKEND_RETRY_DELAY).await;
                    continue;
                }
                if let Some(health) = ctx.dest_health.get(dest_id) {
                    let at = Attribution::of(&err, peer.ip());
                    if matches!(at, Attribution::Client(_)) {
                        tracing::debug!(
                            destination = %dest_id,
                            error = %err,
                            "backend failure attributed to the client, not counted as host evidence on its own"
                        );
                    }
                    health.record_failure(at, &limits);
                }
                return Err(err);
            }
        }
    }
}

pub async fn hold_login(ctx: &Ctx, identifier: Option<&str>) {
    if let Some(id) = identifier
        && let Some(remaining) = ctx.conns.delay_remaining(&ctx.router.normalize(id))
    {
        let capped = remaining.min(Duration::from_secs(120));
        tracing::debug!(
            hold_ms = capped.as_millis() as u64,
            "holding login (delay_until)"
        );
        tokio::time::sleep(capped).await;
    }
}

pub struct BackendLeg {
    pub stream: BoxedStream,
    pub residual: Vec<u8>,
    pub accepts_initial_response: bool,
}

impl BackendLeg {
    pub fn new(stream: BoxedStream, residual: Vec<u8>) -> Self {
        Self {
            stream,
            residual,
            accepts_initial_response: true,
        }
    }

    pub fn with_initial_response(mut self, accepted: bool) -> Self {
        self.accepts_initial_response = accepted;
        self
    }
}

pub struct AuthFrame {
    inline: Vec<u8>,
    deferred: Option<(Vec<u8>, Vec<u8>)>,
}

impl AuthFrame {
    pub fn inline(frame: Vec<u8>) -> Self {
        Self {
            inline: frame,
            deferred: None,
        }
    }

    pub fn with_deferred(mut self, command: Vec<u8>, response: Vec<u8>) -> Self {
        self.deferred = Some((command, response));
        self
    }

    fn wire(&self, accepts_initial_response: bool) -> (&[u8], Option<&[u8]>) {
        match &self.deferred {
            Some((command, response)) if !accepts_initial_response => {
                (command.as_slice(), Some(response.as_slice()))
            }
            _ => (self.inline.as_slice(), None),
        }
    }
}

pub enum AuthWire {
    Imap { tag: String },
    Pop3,
    Smtp,
    ManageSieve,
}

impl AuthWire {
    fn logout(&self) -> &'static [u8] {
        match self {
            AuthWire::Imap { .. } => b"ZZ LOGOUT\r\n",
            AuthWire::Pop3 | AuthWire::Smtp => b"QUIT\r\n",
            AuthWire::ManageSieve => b"LOGOUT\r\n",
        }
    }
}

enum AuthLine {
    Continuation,
    Passthrough,
    FinalOk,
    FinalFail,
}

const SASL_EMPTY_RESPONSE: &[u8] = b"AQ==\r\n";

fn classify_auth_line(line: &[u8], wire: &AuthWire) -> AuthLine {
    match wire {
        AuthWire::Imap { tag } => {
            if line.first() == Some(&b'+') {
                AuthLine::Continuation
            } else if line.len() > tag.len()
                && line[..tag.len()].eq_ignore_ascii_case(tag.as_bytes())
                && line.get(tag.len()) == Some(&b' ')
            {
                let rest = line[tag.len() + 1..].trim_ascii_start();
                if rest.len() >= 2 && rest[..2].eq_ignore_ascii_case(b"OK") {
                    AuthLine::FinalOk
                } else {
                    AuthLine::FinalFail
                }
            } else {
                AuthLine::Passthrough
            }
        }
        AuthWire::Pop3 => {
            if line.starts_with(b"+ ") {
                AuthLine::Continuation
            } else if line.starts_with(b"+OK") {
                AuthLine::FinalOk
            } else {
                AuthLine::FinalFail
            }
        }
        AuthWire::Smtp => {
            if line.len() < 3 {
                return AuthLine::FinalFail;
            }
            let code = std::str::from_utf8(&line[..3])
                .ok()
                .and_then(|s| s.parse::<u16>().ok());
            let sep = line.get(3).copied();
            match code {
                Some(334) => AuthLine::Continuation,
                _ if sep == Some(b'-') => AuthLine::Passthrough,
                Some(c) if (200..300).contains(&c) => AuthLine::FinalOk,
                _ => AuthLine::FinalFail,
            }
        }
        AuthWire::ManageSieve => {
            if line.first() == Some(&b'{') || line.first() == Some(&b'+') {
                AuthLine::Continuation
            } else {
                let upper = line.trim_ascii_start().to_ascii_uppercase();
                if upper.starts_with(b"OK") {
                    AuthLine::FinalOk
                } else if upper.starts_with(b"NO") || upper.starts_with(b"BYE") {
                    AuthLine::FinalFail
                } else {
                    AuthLine::Passthrough
                }
            }
        }
    }
}

fn generic_auth_failure(wire: &AuthWire) -> Vec<u8> {
    match wire {
        AuthWire::Imap { tag } => {
            format!("{tag} NO [AUTHENTICATIONFAILED] Authentication failed.\r\n").into_bytes()
        }
        AuthWire::Pop3 => b"-ERR Authentication failed.\r\n".to_vec(),
        AuthWire::Smtp => b"535 5.7.8 Authentication failed.\r\n".to_vec(),
        AuthWire::ManageSieve => b"NO \"Authentication failed.\"\r\n".to_vec(),
    }
}

pub async fn complete_backend_auth(
    client: &mut BoxedStream,
    backend: &mut BoxedStream,
    residual: &mut Vec<u8>,
    wire: AuthWire,
    mut pending_response: Option<&[u8]>,
    hide: bool,
    max: usize,
) -> Result<bool> {
    let mut client_out: Vec<u8> = Vec::new();
    for _ in 0..64 {
        let line = crate::outbound::read_line(backend, residual, max).await?;
        match classify_auth_line(&line, &wire) {
            AuthLine::Continuation => {
                let response = pending_response.take().unwrap_or(SASL_EMPTY_RESPONSE);
                crate::outbound::write_all(backend, response).await?;
            }
            AuthLine::Passthrough => {
                client_out.extend_from_slice(&line);
                client_out.extend_from_slice(b"\r\n");
            }
            AuthLine::FinalOk => {
                client_out.extend_from_slice(&line);
                client_out.extend_from_slice(b"\r\n");
                write(client, &client_out).await?;
                return Ok(true);
            }
            AuthLine::FinalFail => {
                if hide {
                    client_out.extend_from_slice(&generic_auth_failure(&wire));
                } else {
                    client_out.extend_from_slice(&line);
                    client_out.extend_from_slice(b"\r\n");
                }
                write(client, &client_out).await?;
                return Ok(false);
            }
        }
    }
    Err(ProxyError::backend(
        "backend auth dialogue did not complete",
    ))
}

#[allow(clippy::too_many_arguments)]
pub async fn bridge_authenticated<F, Fut>(
    ctx: &Ctx,
    dest_id: &str,
    mut stream: BoxedStream,
    peer: SocketAddr,
    identifier: Option<&str>,
    client_residual: Vec<u8>,
    started: Instant,
    label: &'static str,
    wire: AuthWire,
    auth: &AuthFrame,
    unavailable: &[u8],
    max: usize,
    open: F,
) -> Result<Option<Resume>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<BackendLeg>>,
{
    if let Some(id) = identifier
        && !crate::token::valid_routing_identifier(id)
    {
        tracing::warn!(
            protocol = label,
            destination = %dest_id,
            "rejecting login: routing identifier contains invalid characters"
        );
        let _ = write(&mut stream, unavailable).await;
        return Ok(None);
    }

    let BackendLeg {
        stream: mut backend,
        residual: mut backend_residual,
        accepts_initial_response,
    } = match establish(ctx, dest_id, peer, open).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, protocol = label, destination = %dest_id, "backend unavailable");
            let _ = write(&mut stream, unavailable).await;
            return Ok(None);
        }
    };

    let logout = wire.logout();
    let (auth_frame, pending_response) = auth.wire(accepts_initial_response);
    crate::outbound::write_all(&mut backend, auth_frame).await?;

    let hide = ctx.hide_auth_errors(dest_id);
    let auth_ok = match tokio::time::timeout(
        ctx.config.server.backend_timeout,
        complete_backend_auth(
            &mut stream,
            &mut backend,
            &mut backend_residual,
            wire,
            pending_response,
            hide,
            max,
        ),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            return Err(ProxyError::backend("backend auth completion timed out"));
        }
    };

    if !auth_ok {
        tracing::debug!(
            protocol = label,
            destination = %dest_id,
            "backend rejected authentication; resuming pre-authentication dialogue"
        );
        let _ = crate::outbound::write_all(&mut backend, logout).await;
        let _ = tokio::time::timeout(crate::outbound::SHUTDOWN_GRACE, backend.shutdown()).await;
        return Ok(Some(Resume {
            stream,
            buf: client_residual,
        }));
    }

    let guard = identifier.map(|id| ctx.register_conn(id));
    let cancel = guard.as_ref().map(|g| g.cancel());
    let (to_backend, to_client) = crate::outbound::bridge(
        stream,
        backend,
        &client_residual,
        &backend_residual,
        ctx.config.server.bridge_idle,
        cancel,
    )
    .await?;
    tracing::info!(
        protocol = label,
        destination = %dest_id,
        bytes_to_backend = to_backend,
        bytes_to_client = to_client,
        secs = started.elapsed().as_secs_f64(),
        "session closed"
    );
    Ok(None)
}

pub async fn write(stream: &mut BoxedStream, bytes: &[u8]) -> Result<()> {
    stream
        .write_all(bytes)
        .await
        .map_err(|e| ProxyError::Protocol(format!("writing client: {e}").into()))?;
    stream
        .flush()
        .await
        .map_err(|e| ProxyError::Protocol(format!("flushing client: {e}").into()))
}

pub async fn upgrade_tls_inbound(
    stream: BoxedStream,
    acceptor: &TlsAcceptor,
) -> Result<BoxedStream> {
    let tls = acceptor
        .accept(stream)
        .await
        .map_err(|e| ProxyError::tls(format!("inbound STARTTLS handshake failed: {e}")))?;
    Ok(Box::new(tls))
}

pub async fn fill(stream: &mut BoxedStream, buf: &mut Vec<u8>, max: usize) -> Result<usize> {
    if buf.len() >= max {
        return Err(ProxyError::preauth("pre-auth buffer exceeded maximum size"));
    }
    let mut scratch = [0u8; 8192];
    let want = scratch.len().min(max - buf.len());
    let n = stream
        .read(&mut scratch[..want])
        .await
        .map_err(|e| ProxyError::Protocol(format!("reading client: {e}").into()))?;
    buf.extend_from_slice(&scratch[..n]);
    Ok(n)
}

pub async fn read_crlf_line(
    stream: &mut BoxedStream,
    seed: Vec<u8>,
    max: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = seed;
    let mut from = 0;
    loop {
        if let Some(pos) = buf[from..].iter().position(|&b| b == b'\n') {
            let nl = from + pos;
            let mut line = buf;
            let residual = line.split_off(nl + 1);
            line.truncate(nl);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok((line, residual));
        }
        from = buf.len();
        if buf.len() > max {
            return Err(ProxyError::preauth("client line exceeded maximum length"));
        }
        let n = fill(stream, &mut buf, max + 8192).await?;
        if n == 0 {
            return Err(ProxyError::Closed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_frame_defers_initial_response_when_not_accepted() {
        let frame = AuthFrame::inline(b"a1 AUTHENTICATE PLAIN AGFAYgBj\r\n".to_vec())
            .with_deferred(
                b"a1 AUTHENTICATE PLAIN\r\n".to_vec(),
                b"AGFAYgBj\r\n".to_vec(),
            );

        assert_eq!(
            frame.wire(true),
            (b"a1 AUTHENTICATE PLAIN AGFAYgBj\r\n".as_slice(), None)
        );
        assert_eq!(
            frame.wire(false),
            (
                b"a1 AUTHENTICATE PLAIN\r\n".as_slice(),
                Some(b"AGFAYgBj\r\n".as_slice())
            )
        );
    }

    #[test]
    fn auth_frame_without_deferred_form_stays_inline() {
        let frame = AuthFrame::inline(b"AUTH PLAIN AGFAYgBj\r\n".to_vec());

        assert_eq!(
            frame.wire(false),
            (b"AUTH PLAIN AGFAYgBj\r\n".as_slice(), None)
        );
    }

    #[test]
    fn advertises_token_handles_smtp_ehlo_continuation_lines() {
        let ehlo = b"250-mail.example\r\n250-PIPELINING\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 CHUNKING\r\n";
        assert!(advertises_token(ehlo, "STARTTLS"));
        assert!(advertises_token(ehlo, "PIPELINING"));
        assert!(advertises_token(ehlo, "CHUNKING"));
        assert!(advertises_token(ehlo, "PLAIN"));
        assert!(!advertises_token(ehlo, "BURL"));
    }

    #[test]
    fn advertises_token_handles_imap_and_pop3_capability_lines() {
        let imap = b"* OK [CAPABILITY IMAP4rev2 SASL-IR STARTTLS AUTH=PLAIN] ready\r\n";
        assert!(advertises_token(imap, "STARTTLS"));
        assert!(advertises_token(imap, "IMAP4rev2"));
        let pop3 = b"+OK ready [XCLIENT]\r\n";
        assert!(advertises_token(pop3, "XCLIENT"));
    }

    fn sasl_list(mechs: &[&str]) -> Vec<String> {
        mechs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn advertised_sasl_keeps_login_when_cleartext_is_allowed() {
        let sasl = sasl_list(&["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"]);
        assert_eq!(
            advertised_sasl(&sasl, true),
            vec!["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"]
        );
    }

    #[test]
    fn advertised_sasl_drops_login_with_plain_when_cleartext_is_refused() {
        let sasl = sasl_list(&["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"]);
        assert_eq!(
            advertised_sasl(&sasl, false),
            vec!["OAUTHBEARER", "XOAUTH2"]
        );
    }

    #[test]
    fn advertised_sasl_omits_login_when_not_configured() {
        let sasl = sasl_list(&["PLAIN", "OAUTHBEARER"]);
        assert_eq!(advertised_sasl(&sasl, true), vec!["PLAIN", "OAUTHBEARER"]);
        assert!(!sasl_offered(&sasl, "LOGIN"));
        assert!(sasl_offered(&sasl, "plain"));
    }

    #[test]
    fn login_challenge_builds_a_plain_authentication_frame() {
        use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
        let user = BASE64.encode("user@example.com");
        let pass = BASE64.encode("secret");
        assert_eq!(
            login_challenge(user.as_bytes(), pass.as_bytes()).unwrap(),
            b"\0user@example.com\0secret".to_vec()
        );
    }

    #[test]
    fn login_challenge_rejects_invalid_base64() {
        assert!(login_challenge(b"!!!!", b"c2VjcmV0").is_none());
        assert!(login_challenge(b"dXNlcg==", b"!!!!").is_none());
    }

    #[test]
    fn sasl_cancellation_is_a_bare_asterisk() {
        assert!(sasl_cancelled(b"*"));
        assert!(sasl_cancelled(b"*\r"));
        assert!(!sasl_cancelled(b"KiA="));
        assert!(!sasl_cancelled(b""));
    }

    #[test]
    fn smtp_auth_line_classification() {
        assert!(matches!(
            classify_auth_line(b"334", &AuthWire::Smtp),
            AuthLine::Continuation
        ));
        assert!(matches!(
            classify_auth_line(b"235", &AuthWire::Smtp),
            AuthLine::FinalOk
        ));
        assert!(matches!(
            classify_auth_line(b"235 2.7.0 Authentication successful", &AuthWire::Smtp),
            AuthLine::FinalOk
        ));
        assert!(matches!(
            classify_auth_line(b"535 5.7.8 nope", &AuthWire::Smtp),
            AuthLine::FinalFail
        ));
        assert!(matches!(
            classify_auth_line(b"250-PIPELINING", &AuthWire::Smtp),
            AuthLine::Passthrough
        ));
    }

    fn limits(threshold: u32, min_clients: u32, cooldown: Duration) -> HealthLimits {
        HealthLimits {
            threshold,
            min_clients,
            cooldown,
        }
    }

    fn client(addr: &str) -> Attribution {
        Attribution::Client(addr.parse().unwrap())
    }

    #[test]
    fn dest_health_opens_after_threshold_and_recovers() {
        let h = DestHealth::default();
        let lim = limits(3, 2, Duration::from_secs(60));

        h.record_failure(Attribution::Host, &lim);
        h.record_failure(Attribution::Host, &lim);
        assert!(h.gate().is_ok());

        h.record_failure(Attribution::Host, &lim);
        assert!(h.gate().is_err());

        h.record_success();
        assert!(h.gate().is_ok());
    }

    #[test]
    fn dest_health_cooldown_elapses_into_a_probe() {
        let h = DestHealth::default();
        h.record_failure(Attribution::Host, &limits(1, 2, Duration::from_secs(0)));
        assert!(h.gate().is_ok());
    }

    #[test]
    fn attribution_follows_the_failure_stage() {
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert_eq!(
            Attribution::of(&ProxyError::backend_connect("refused"), ip),
            Attribution::Host
        );
        assert_eq!(
            Attribution::of(&ProxyError::backend("closed after PROXY header"), ip),
            Attribution::Client(ip)
        );
        assert_eq!(
            Attribution::of(
                &ProxyError::backend_session("backend closed before sending a complete line"),
                ip
            ),
            Attribution::Client(ip)
        );
        assert_eq!(
            Attribution::of(
                &ProxyError::backend_session("backend TLS handshake failed"),
                ip
            ),
            Attribution::Client(ip)
        );
        assert_eq!(
            Attribution::of(
                &ProxyError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
                ip
            ),
            Attribution::Client(ip)
        );
    }

    #[test]
    fn banned_client_alone_never_opens_the_breaker() {
        let h = DestHealth::default();
        let lim = limits(3, 2, Duration::from_secs(60));
        for _ in 0..50 {
            h.record_failure(client("198.51.100.7"), &lim);
        }
        assert!(h.gate().is_ok());
        let s = h.snapshot();
        assert_eq!(s.consecutive_failures, 50);
        assert_eq!(s.failure_sources, 1);
        assert!(!s.down);
    }

    #[test]
    fn failures_spanning_distinct_clients_open_the_breaker() {
        let h = DestHealth::default();
        let lim = limits(3, 2, Duration::from_secs(60));
        h.record_failure(client("198.51.100.7"), &lim);
        h.record_failure(client("198.51.100.7"), &lim);
        h.record_failure(client("198.51.100.7"), &lim);
        assert!(h.gate().is_ok());

        h.record_failure(client("203.0.113.4"), &lim);
        assert!(h.gate().is_err());
        assert_eq!(h.snapshot().failure_sources, 2);
    }

    #[test]
    fn host_level_failure_opens_the_breaker_without_breadth() {
        let h = DestHealth::default();
        let lim = limits(3, 2, Duration::from_secs(60));
        h.record_failure(client("198.51.100.7"), &lim);
        h.record_failure(client("198.51.100.7"), &lim);
        h.record_failure(Attribution::Host, &lim);
        assert!(h.gate().is_err());
        let s = h.snapshot();
        assert!(s.host_level_failure);
        assert!(s.down);
    }

    #[test]
    fn cooldown_expiry_clears_stale_evidence() {
        let h = DestHealth::default();
        let lim = limits(3, 2, Duration::from_secs(0));
        for _ in 0..3 {
            h.record_failure(Attribution::Host, &lim);
        }
        assert!(h.gate().is_ok());
        let s = h.snapshot();
        assert!(!s.host_level_failure);
        assert_eq!(s.failure_sources, 0);

        h.record_failure(
            client("198.51.100.7"),
            &limits(3, 2, Duration::from_secs(60)),
        );
        assert!(h.gate().is_ok());
    }

    #[test]
    fn cooldown_expiry_still_re_opens_on_a_failed_host_probe() {
        let h = DestHealth::default();
        let lim = limits(3, 2, Duration::from_secs(0));
        for _ in 0..3 {
            h.record_failure(Attribution::Host, &lim);
        }
        assert!(h.gate().is_ok());

        h.record_failure(Attribution::Host, &limits(3, 2, Duration::from_secs(60)));
        assert!(h.gate().is_err());
    }

    #[test]
    fn success_clears_the_failure_streak() {
        let h = DestHealth::default();
        let lim = limits(3, 2, Duration::from_secs(60));
        h.record_failure(client("198.51.100.7"), &lim);
        h.record_failure(client("203.0.113.4"), &lim);
        h.record_success();
        let s = h.snapshot();
        assert_eq!(s.consecutive_failures, 0);
        assert_eq!(s.failure_sources, 0);

        h.record_failure(client("198.51.100.7"), &lim);
        h.record_failure(client("198.51.100.7"), &lim);
        h.record_failure(client("198.51.100.7"), &lim);
        assert!(h.gate().is_ok());
    }

    #[test]
    fn min_clients_zero_counts_failures_alone() {
        let h = DestHealth::default();
        let lim = limits(3, 0, Duration::from_secs(60));
        for _ in 0..3 {
            h.record_failure(client("198.51.100.7"), &lim);
        }
        assert!(h.gate().is_err());
    }

    #[test]
    fn tracked_failure_sources_are_bounded() {
        let h = DestHealth::default();
        let lim = limits(0, 2, Duration::from_secs(60));
        for i in 0..(MAX_TRACKED_FAILURE_SOURCES + 100) {
            let ip = IpAddr::from([10, (i / 256) as u8, (i % 256) as u8, 1]);
            h.record_failure(Attribution::Client(ip), &lim);
        }
        assert_eq!(
            h.snapshot().failure_sources as usize,
            MAX_TRACKED_FAILURE_SOURCES
        );
    }

    #[tokio::test]
    async fn conn_registry_kick_signals_live_sessions() {
        let reg = ConnRegistry::default();
        let guard = reg.register("user@example.com");
        let mut rx = guard.cancel();
        assert_eq!(reg.kick("user@example.com"), 1);
        assert!(rx.changed().await.is_ok());
        assert!(*rx.borrow());
        assert_eq!(reg.kick("nobody@example.com"), 0);
    }

    #[test]
    fn conn_registry_deregisters_on_drop() {
        let reg = ConnRegistry::default();
        {
            let _g = reg.register("user@example.com");
            assert_eq!(reg.kick("user@example.com"), 1);
        }
        assert_eq!(reg.kick("user@example.com"), 0);
    }

    #[test]
    fn conn_registry_delay_window() {
        let reg = ConnRegistry::default();
        assert!(reg.delay_remaining("user@example.com").is_none());
        reg.set_delay("user@example.com", Instant::now() + Duration::from_secs(30));
        assert!(reg.delay_remaining("user@example.com").is_some());
        reg.set_delay("user@example.com", Instant::now());
        assert!(reg.delay_remaining("user@example.com").is_none());
    }

    #[test]
    fn dest_health_threshold_zero_never_trips() {
        let h = DestHealth::default();
        for _ in 0..100 {
            h.record_failure(Attribution::Host, &limits(0, 2, Duration::from_secs(60)));
        }
        assert!(h.gate().is_ok());
    }
}
