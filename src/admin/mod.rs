/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod anonymous;
mod api;
mod auth;
mod http;
mod session;
#[cfg(feature = "ui")]
mod ui;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::config::AdminConfig;
use crate::config::{Config, Revision};
use crate::error::{ProxyError, Result, Side};
use crate::http::head::Method;
use crate::http::reader::Reader;
use crate::net::tls;
use crate::runtime::Runtime;
use crate::runtime::metrics::{EventBody, EventKind};
use anonymous::{Admission, Anonymous, Ticket};
use api::LoggedPath;
use auth::{ClientKey, Lockout, LockoutPolicy, ct_eq};
use http::{After, Out, Reply, Request, Stop};
use session::{COOKIE_NAME, SessionLimits, SessionTag, Sessions};

type SharedRuntime = Arc<ArcSwap<Runtime>>;

const MAX_CONNECTIONS: usize = 64;
const LOOPBACK_RESERVED_CONNECTIONS: usize = 8;
const MAX_CONNECTIONS_PER_CLIENT: u32 = 8;
const MAX_REQUESTS_PER_CONNECTION: u32 = 100;
const CONNECTION_LIFETIME: Duration = Duration::from_secs(300);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const FIRST_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const KEEP_ALIVE_IDLE: Duration = Duration::from_secs(30);
const ANONYMOUS_IDLE: Duration = Duration::from_secs(5);
const REFUSED_LOG_INTERVAL: Duration = Duration::from_secs(60);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);
const BEARER_ACTOR: &str = "bearer";
const API_PREFIX: &str = "/api/v1/";
const HEALTHZ: &str = "/healthz";
const LOCKED_OUT: &str = "too many failed attempts from this address";

struct Admin {
    shared: SharedRuntime,
    config_path: Option<Arc<str>>,
    token: ArcSwap<Box<str>>,
    boot_policy: LockoutPolicy,
    boot_max_body: usize,
    boot_sessions: SessionLimits,
    sessions: Sessions,
    lockout: Mutex<Lockout>,
    slots: Arc<Semaphore>,
    clients: Mutex<HashMap<ClientKey, u32>>,
    anonymous: Anonymous,
    writes: tokio::sync::Mutex<()>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Anonymous,
    Authenticated,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Refusal {
    Global,
    PerClient,
    AnonymousEvicted,
}

#[derive(Default)]
struct RefusedLog {
    since: Option<Instant>,
    suppressed: u64,
}

impl RefusedLog {
    fn note(&mut self, ip: IpAddr, refusal: Refusal, now: Instant) {
        match self.since {
            Some(since) if now.saturating_duration_since(since) < REFUSED_LOG_INTERVAL => {
                self.suppressed = self.suppressed.saturating_add(1);
            }
            _ => {
                tracing::warn!(%ip, ?refusal, suppressed = self.suppressed, "admin connection limit reached");
                self.since = Some(now);
                self.suppressed = 0;
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Caller {
    Bearer,
    Session(SessionTag),
}

impl Caller {
    fn actor(self) -> Box<str> {
        match self {
            Caller::Bearer => BEARER_ACTOR.into(),
            Caller::Session(tag) => tag.to_string().into_boxed_str(),
        }
    }
}

struct Prepared {
    rt: Runtime,
    token: Option<Box<str>>,
}

struct ClientSlot {
    admin: Arc<Admin>,
    key: ClientKey,
    ticket: Option<Ticket>,
    _permit: OwnedSemaphorePermit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TokenCheck {
    Valid,
    Invalid,
    Locked,
}

pub async fn run(
    shared: SharedRuntime,
    config: Arc<Config>,
    config_path: Option<Arc<str>>,
) -> Result<()> {
    let admin = config
        .admin
        .as_ref()
        .ok_or_else(|| ProxyError::config("admin not configured"))?;
    let listener = TcpListener::bind(admin.bind)
        .await
        .map_err(|e| ProxyError::config(format!("admin bind {}: {e}", admin.bind)))?;
    tracing::info!(bind = %admin.bind, "admin listener started");
    serve(shared, config, config_path, listener).await
}

pub async fn serve(
    shared: SharedRuntime,
    config: Arc<Config>,
    config_path: Option<Arc<str>>,
    listener: TcpListener,
) -> Result<()> {
    let admin_config = config
        .admin
        .as_ref()
        .ok_or_else(|| ProxyError::config("admin not configured"))?;
    if shared.load().admin_tls.is_none() {
        return Err(ProxyError::tls(
            "admin requires TLS but no acceptor available",
        ));
    }
    let admin = Arc::new(Admin {
        token: ArcSwap::from_pointee(admin_config.load_token()?),
        boot_policy: LockoutPolicy::from(admin_config),
        boot_max_body: admin_config.max_body_size,
        boot_sessions: SessionLimits::from(admin_config),
        sessions: Sessions::default(),
        shared,
        config_path,
        lockout: Mutex::new(Lockout::default()),
        slots: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        clients: Mutex::new(HashMap::new()),
        anonymous: Anonymous::default(),
        writes: tokio::sync::Mutex::new(()),
    });

    let mut refused = RefusedLog::default();
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::warn!(error = %e, "admin accept failed");
                tokio::time::sleep(ACCEPT_BACKOFF).await;
                continue;
            }
        };
        let ip = peer.ip();
        let slot = match admin.acquire(ip) {
            Ok((slot, Admission::Free)) => slot,
            Ok((slot, Admission::Evicted)) => {
                refused.note(ip, Refusal::AnonymousEvicted, Instant::now());
                slot
            }
            Err(refusal) => {
                refused.note(ip, refusal, Instant::now());
                continue;
            }
        };
        tokio::spawn(async move {
            if let Err(e) = slot.admin.connection(tcp, ip, slot.ticket.as_ref()).await {
                tracing::debug!(error = %e, "admin connection ended");
            }
            drop(slot);
        });
    }
}

impl Admin {
    fn acquire(
        self: &Arc<Self>,
        ip: IpAddr,
    ) -> std::result::Result<(ClientSlot, Admission), Refusal> {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Refusal::Global)?;
        let loopback = ip.to_canonical().is_loopback();
        if self.slots.available_permits() < LOOPBACK_RESERVED_CONNECTIONS && !loopback {
            return Err(Refusal::Global);
        }
        let key = ClientKey::from(ip);
        {
            let mut clients = self.clients.lock();
            let count = clients.entry(key).or_insert(0);
            if *count >= MAX_CONNECTIONS_PER_CLIENT {
                return Err(Refusal::PerClient);
            }
            *count += 1;
        }
        let (ticket, admission) = match loopback {
            true => (None, Admission::Free),
            false => {
                let (ticket, admission) = self.anonymous.admit(key);
                (Some(ticket), admission)
            }
        };
        let slot = ClientSlot {
            admin: self.clone(),
            key,
            ticket,
            _permit: permit,
        };
        Ok((slot, admission))
    }

    fn policy(&self, rt: &Runtime) -> LockoutPolicy {
        rt.raw
            .admin
            .as_ref()
            .map_or(self.boot_policy, LockoutPolicy::from)
    }

    fn is_locked(&self, rt: &Runtime, ip: IpAddr) -> bool {
        self.lockout
            .lock()
            .is_locked(ClientKey::from(ip), self.policy(rt), Instant::now())
    }

    async fn connection(
        &self,
        tcp: TcpStream,
        ip: IpAddr,
        mut ticket: Option<&Ticket>,
    ) -> Result<()> {
        let deadline = Instant::now() + CONNECTION_LIFETIME;
        let (acceptor, max_body) = {
            let rt = self.shared.load();
            let acceptor = rt
                .admin_tls
                .clone()
                .ok_or_else(|| ProxyError::tls("admin requires TLS but no acceptor available"))?;
            let max_body = rt
                .raw
                .admin
                .as_ref()
                .map_or(self.boot_max_body, |admin| admin.max_body_size);
            (acceptor, max_body)
        };
        let Some(handshake) =
            Ticket::unless_evicted(ticket, timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))).await
        else {
            return Ok(());
        };
        let mut stream = handshake
            .map_err(|_| ProxyError::tls("admin TLS handshake timed out"))?
            .map_err(|e| ProxyError::tls(format!("admin TLS handshake: {e}")))?;

        let mut head = Vec::new();
        let mut out = Out::default();
        let mut access = Access::Anonymous;
        let mut reader = Reader::new(Side::Client, 0);
        for served in 1..=MAX_REQUESTS_PER_CONNECTION {
            let idle = match (served, access) {
                (1, _) => FIRST_REQUEST_TIMEOUT,
                (_, Access::Authenticated) => KEEP_ALIVE_IDLE,
                (_, Access::Anonymous) => ANONYMOUS_IDLE,
            };
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let wait = idle.min(left);
            out.clear();
            let read = Request::read(&mut stream, &mut reader, &mut out.body, max_body, wait);
            let Some(read) = Ticket::unless_evicted(ticket, read).await else {
                break;
            };
            let (reply, wants_close) = match read {
                Ok(request) => (
                    self.dispatch(&request, ip, &mut access, &mut out).await,
                    request.wants_close(),
                ),
                Err(Stop::Reject(reply)) => (reply, true),
                Err(Stop::Closed) => break,
            };
            if access == Access::Authenticated
                && let Some(held) = ticket.take()
            {
                self.anonymous.release(held);
            }
            let close =
                wants_close || reply.after == After::Close || served == MAX_REQUESTS_PER_CONNECTION;
            let reply = if close { reply.closing() } else { reply };
            reply.write_to(&mut stream, &mut head, &out).await?;
            if close {
                break;
            }
        }
        http::close(&mut stream).await;
        Ok(())
    }

    async fn dispatch(
        &self,
        request: &Request,
        ip: IpAddr,
        access: &mut Access,
        out: &mut Out,
    ) -> Reply {
        let rt = self.shared.load_full();
        let path = request.path();
        if path != HEALTHZ && self.is_locked(&rt, ip) && !self.holds_session(&rt, request, ip) {
            return Reply::error(&mut out.body, 429, "locked_out", LOCKED_OUT).closing();
        }
        #[cfg(feature = "ui")]
        if let Some(reply) = request.serve_ui(&mut out.body) {
            return reply;
        }
        if let Some(rest) = path.strip_prefix(API_PREFIX) {
            return self.handle_api(&rt, request, rest, ip, access, out).await;
        }
        match (path, request.method()) {
            (HEALTHZ, Method::Get) => Reply::text(&mut out.body, 200, "ok\n"),
            (HEALTHZ, _) => Reply::error(
                &mut out.body,
                405,
                "method_not_allowed",
                "method not allowed",
            ),
            _ => Reply::error(&mut out.body, 404, "not_found", "not found"),
        }
    }

    fn holds_session(&self, rt: &Runtime, request: &Request, ip: IpAddr) -> bool {
        request.bearer().is_none()
            && request.cookie(COOKIE_NAME).is_some_and(|cookie| {
                self.sessions
                    .touch(cookie, self.session_limits(rt), ip)
                    .is_some()
            })
    }

    fn check_bearer(&self, rt: &Runtime, request: &Request, ip: IpAddr) -> bool {
        let token = request.bearer().unwrap_or_default();
        let ok = self.check_token(rt, token, ip) == TokenCheck::Valid;
        if !ok {
            let path = LoggedPath::new(request.path(), &rt.shared.redact);
            tracing::warn!(%ip, %path, "admin 401 unauthorized");
        }
        ok
    }

    fn check_token(&self, rt: &Runtime, presented: &[u8], ip: IpAddr) -> TokenCheck {
        let key = ClientKey::from(ip);
        let policy = self.policy(rt);
        let now = Instant::now();
        let locked = {
            let mut lockout = self.lockout.lock();
            if lockout.is_locked(key, policy, now) {
                return TokenCheck::Locked;
            }
            if !presented.is_empty() && ct_eq(presented, self.token.load().as_bytes()) {
                lockout.record_success(key);
                return TokenCheck::Valid;
            }
            lockout.record_failure(key, policy, now)
        };
        if locked {
            tracing::warn!(%ip, duration = ?policy.duration(), "admin client address locked out");
            rt.shared.record_event(EventBody {
                ip: Some(ip),
                ..EventBody::new(EventKind::Admin, "address locked out").target(ip.to_string())
            });
        }
        TokenCheck::Invalid
    }

    fn session_limits(&self, rt: &Runtime) -> SessionLimits {
        rt.raw
            .admin
            .as_ref()
            .map_or(self.boot_sessions, SessionLimits::from)
    }

    fn set_token(&self, token: Box<str>) {
        if **self.token.load() != token {
            self.token.store(Arc::new(token));
            self.sessions.clear();
        }
    }

    async fn reload_config(&self, path: &str) -> Result<Arc<Runtime>> {
        let _writes = self.writes.lock().await;
        let raw = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| ProxyError::config(format!("read config {path}: {e}")))?;
        let config = Config::parse_and_validate(&raw)?;
        let prepared = self.prepare(config, Revision::of(raw.as_bytes())).await?;
        self.install(prepared)
    }

    async fn prepare(&self, config: Config, revision: Revision) -> Result<Prepared> {
        let token = config
            .admin
            .as_ref()
            .map(AdminConfig::load_token)
            .transpose()?;
        let current = self.shared.load_full();
        let (config, provider) = (Arc::new(config), tls::provider());
        let rt = Runtime::rebuild(config, revision, &current, &provider).await?;
        Ok(Prepared { rt, token })
    }

    fn install(&self, prepared: Prepared) -> Result<Arc<Runtime>> {
        let rt = prepared.rt.install(&self.shared)?;
        if let Some(token) = prepared.token {
            self.set_token(token);
        }
        Ok(rt)
    }

    fn config_writable(&self, rt: &Runtime) -> bool {
        self.config_path.is_some()
            && rt
                .raw
                .admin
                .as_ref()
                .is_some_and(|admin| admin.config_write)
    }

    fn record_as(
        &self,
        rt: &Runtime,
        caller: Caller,
        kind: EventKind,
        message: Box<str>,
        target: Option<&str>,
        ip: IpAddr,
    ) {
        let event = EventBody::new(kind, message).actor(caller.actor(), Some(ip));
        rt.shared.record_event(match target {
            Some(target) => event.target(target),
            None => event,
        });
    }
}

impl Drop for ClientSlot {
    fn drop(&mut self) {
        if let Some(ticket) = &self.ticket {
            self.admin.anonymous.release(ticket);
        }
        let mut clients = self.admin.clients.lock();
        if let Some(count) = clients.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                clients.remove(&self.key);
            }
        }
    }
}
