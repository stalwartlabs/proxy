/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::mem;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::time::{Instant as TokioInstant, timeout, timeout_at};
use tokio_rustls::TlsAcceptor;

use crate::config::TlsMode;
use crate::error::{ErrorKind, ProxyError, Result, Side, Stage};
use crate::net::bridge::{BridgeArgs, BridgeEnd, SHUTDOWN_GRACE};
use crate::net::linebuf::LineBuf;
use crate::net::stream::ClientStream;
use crate::proto::backend::{ClientResponse, Dialect, StartTlsReply};
use crate::proto::forward::ForwardInfo;
use crate::proto::sasl_exchange::{Reject, SaslExchange, Step};
use crate::route::Route;
use crate::route::key::RoutingKey;
use crate::runtime::capabilities::TlsState;
use crate::runtime::metrics::ListenerCounters;
use crate::runtime::registry::{ConnGuard, NewConn};
use crate::runtime::{ListenerId, ListenerSettings, Runtime};

pub const MAX_TAG: usize = 128;
const FAREWELL_GRACE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendMech {
    Plain,
    OAuthBearer,
    XOAuth2,
}

impl BackendMech {
    pub fn as_str(self) -> &'static str {
        match self {
            BackendMech::Plain => "PLAIN",
            BackendMech::OAuthBearer => "OAUTHBEARER",
            BackendMech::XOAuth2 => "XOAUTH2",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tag(Box<str>);

impl Tag {
    pub fn new(raw: &str) -> Option<Self> {
        (!raw.is_empty() && raw.len() <= MAX_TAG).then(|| Tag(raw.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug)]
pub struct Login {
    pub mech: BackendMech,
    pub response: Vec<u8>,
    pub key: Option<RoutingKey>,
    pub tag: Option<Tag>,
    pub helo: Option<Box<str>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Continue,
    Close,
}

#[derive(Clone, Copy, Debug)]
pub struct Failures {
    count: u32,
    max: u32,
}

impl Failures {
    pub fn new(max: u32) -> Self {
        Failures { count: 0, max }
    }

    pub fn bump(&mut self) -> Verdict {
        self.count = self.count.saturating_add(1);
        if self.count >= self.max {
            Verdict::Close
        } else {
            Verdict::Continue
        }
    }
}

pub enum Preauth {
    Login(Login),
    Closed,
    Expired,
}

pub enum ExchangeEnd {
    Step(Step),
    Ended(Preauth),
}

pub enum Flow {
    Next,
    Done(Preauth),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    Data,
    Eof,
    Expired,
}

pub struct ClientConn<'a> {
    pub rt: &'a Runtime,
    pub listener: &'a ListenerSettings,
    pub stream: ClientStream,
    pub buf: LineBuf,
    pub out: Vec<u8>,
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub failures: Failures,
    deadline: TokioInstant,
}

impl<'a> ClientConn<'a> {
    pub fn new(
        rt: &'a Runtime,
        id: ListenerId,
        stream: ClientStream,
        peer: SocketAddr,
        local: SocketAddr,
        cap: usize,
    ) -> Result<Self> {
        let listener = rt.listener(id).ok_or_else(|| {
            ProxyError::config("listener is not part of the running configuration")
        })?;
        Ok(ClientConn {
            rt,
            listener,
            stream,
            buf: LineBuf::client(cap),
            out: Vec::new(),
            peer,
            local,
            failures: Failures::new(listener.max_auth_attempts),
            deadline: TokioInstant::now() + listener.preauth_timeout,
        })
    }

    pub fn restart_deadline(&mut self) {
        self.deadline = TokioInstant::now() + self.listener.preauth_timeout;
    }

    pub async fn fill(&mut self) -> Result<Input> {
        match timeout_at(self.deadline, self.buf.fill(&mut self.stream)).await {
            Ok(Ok(0)) => Ok(Input::Eof),
            Ok(Ok(_)) => Ok(Input::Data),
            Ok(Err(err)) => Err(err),
            Err(_) => Ok(Input::Expired),
        }
    }

    pub fn bump(&mut self) -> Flow {
        match self.failures.bump() {
            Verdict::Continue => Flow::Next,
            Verdict::Close => Flow::Done(Preauth::Closed),
        }
    }

    pub async fn exchange(
        &mut self,
        dialect: Dialect,
        mut exchange: SaslExchange,
        mut step: Step,
    ) -> Result<ExchangeEnd> {
        let rules = &self.rt.key_rules;
        while let Step::Challenge(challenge) = step {
            dialect.write_challenge(&mut self.out, challenge);
            self.flush().await?;
            step = loop {
                if let Some(line) = self.buf.line() {
                    match dialect.client_response(line) {
                        ClientResponse::Data(data) => break exchange.feed(data, rules),
                        ClientResponse::LiteralFollows => continue,
                    }
                }
                match self.fill().await {
                    Ok(Input::Data) => {}
                    Ok(Input::Eof) => return Ok(ExchangeEnd::Ended(Preauth::Closed)),
                    Ok(Input::Expired) => return Ok(ExchangeEnd::Ended(Preauth::Expired)),
                    Err(err) if matches!(err.kind, ErrorKind::LimitExceeded(_)) => {
                        self.buf.clear();
                        break Step::Reject(Reject::TooLong);
                    }
                    Err(err) => return Err(err),
                }
            };
        }
        Ok(ExchangeEnd::Step(step))
    }

    pub async fn farewell(&mut self, line: &[u8]) {
        let _ = timeout(FAREWELL_GRACE, self.stream.send(line)).await;
    }

    pub fn answer_starttls(
        &mut self,
        dialect: Dialect,
        tag: Option<&str>,
    ) -> Option<&'a TlsAcceptor> {
        let acceptor = if self.listener.tls != TlsMode::Starttls || self.stream.is_tls() {
            Err(StartTlsReply::Unavailable)
        } else {
            self.rt
                .inbound_tls
                .as_ref()
                .ok_or(StartTlsReply::NotConfigured)
        };
        let reply = acceptor.err().unwrap_or(StartTlsReply::Begin);
        dialect.write_starttls(&mut self.out, reply, tag);
        acceptor.ok()
    }

    pub fn finish(&mut self, dialect: Dialect, step: Step, tag: Option<Tag>) -> Flow {
        match step {
            Step::Done(mut login) => {
                login.tag = tag;
                Flow::Done(Preauth::Login(login))
            }
            Step::Unroutable(err) => {
                tracing::warn!(protocol = dialect.label(), error = %err, "rejecting login: invalid routing identifier");
                dialect.write_unavailable(&mut self.out, tag.as_ref().map(Tag::as_str));
                Flow::Done(Preauth::Closed)
            }
            Step::Reject(why) => {
                dialect.write_reject(&mut self.out, why, tag.as_ref().map(Tag::as_str));
                match why {
                    Reject::PrivacyRequired => Flow::Next,
                    Reject::TooLong => Flow::Done(Preauth::Closed),
                    _ => self.bump(),
                }
            }
            Step::Challenge(_) => Flow::Next,
        }
    }

    pub fn tls_state(&self) -> TlsState {
        TlsState::new(self.stream.is_tls(), self.listener.tls)
    }

    pub async fn flush(&mut self) -> Result<()> {
        if self.out.is_empty() {
            return Ok(());
        }
        let sent = timeout_at(self.deadline, self.stream.send(&self.out)).await;
        self.out.clear();
        sent.map_err(|_| ProxyError::timeout(Stage::Preauth, Side::Client))?
    }

    async fn unavailable(mut self, dialect: Dialect, login: &Login) -> Result<LoginOutcome<'a>> {
        let mut out = mem::take(&mut self.out);
        dialect.write_unavailable(&mut out, login.tag.as_ref().map(Tag::as_str));
        self.farewell(&out).await;
        Ok(LoginOutcome::Closed)
    }
}

enum LoginOutcome<'a> {
    Bridged(Box<Session>),
    Rejected(Box<ClientConn<'a>>),
    Closed,
}

pub enum Resume<'a> {
    Preauth(Box<ClientConn<'a>>),
    Bridge(Box<Session>),
    Close,
}

pub struct Session {
    args: BridgeArgs,
    dialect: Dialect,
    dest: Arc<str>,
    started: Instant,
    guard: ConnGuard,
}

impl Session {
    pub async fn run(self) -> Result<()> {
        let Session {
            args,
            dialect,
            dest,
            started,
            guard,
        } = self;
        let ended = args.run().await;
        let (to_backend, to_client) = match &ended {
            Ok(totals) => (totals.to_backend, totals.to_client),
            Err(_) => {
                let info = guard.info();
                (
                    info.bytes_up.load(Ordering::Relaxed),
                    info.bytes_down.load(Ordering::Relaxed),
                )
            }
        };
        tracing::info!(
            protocol = dialect.label(),
            destination = %dest,
            bytes_to_backend = to_backend,
            bytes_to_client = to_client,
            secs = started.elapsed().as_secs_f64(),
            end = ended.as_ref().err().map_or("closed", BridgeEnd::label),
            "session closed"
        );
        ended?;
        Ok(())
    }
}

impl<'a> ClientConn<'a> {
    pub async fn conclude(mut self, outcome: Preauth, dialect: Dialect) -> Result<Resume<'a>> {
        let credentials = match outcome {
            Preauth::Login(credentials) => credentials,
            Preauth::Closed => return Ok(Resume::Close),
            Preauth::Expired => {
                self.farewell(dialect.preauth_farewell()).await;
                return Ok(Resume::Close);
            }
        };
        let mut conn = match self.login(credentials, dialect).await? {
            LoginOutcome::Bridged(session) => return Ok(Resume::Bridge(session)),
            LoginOutcome::Rejected(rejected) => rejected,
            LoginOutcome::Closed => return Ok(Resume::Close),
        };
        if conn.failures.bump() == Verdict::Close {
            return Ok(Resume::Close);
        }
        conn.restart_deadline();
        Ok(Resume::Preauth(conn))
    }

    async fn login(mut self, login: Login, dialect: Dialect) -> Result<LoginOutcome<'a>> {
        let rt = self.rt;
        let counters = rt.shared.metrics.listener(self.listener.id);
        let started = Instant::now();
        let dest_id = match &login.key {
            Some(key) => {
                rt.shared.registry.hold_login(key.as_str()).await;
                match rt.router.route(key).await {
                    Route::Mapped(id) => Some(id),
                    Route::Default | Route::Transient => rt.default_dest,
                }
            }
            None => rt.default_dest,
        };
        let Some(dest_id) = dest_id else {
            tracing::warn!(
                protocol = dialect.label(),
                "no default destination is configured"
            );
            return self.unavailable(dialect, &login).await;
        };
        let Some(dest) = rt.destination(dest_id) else {
            tracing::warn!(protocol = dialect.label(), "routed destination was removed");
            return self.unavailable(dialect, &login).await;
        };
        tracing::debug!(protocol = dialect.label(), destination = %dest.name, "routing decision");
        let ep = match dest.endpoint(dialect.protocol()) {
            Ok(ep) => ep,
            Err(err) => {
                tracing::warn!(error = %err, protocol = dialect.label(), destination = %dest.name, "backend unavailable");
                return self.unavailable(dialect, &login).await;
            }
        };
        let fwd = ForwardInfo::new(
            self.peer,
            self.local,
            self.stream.is_tls(),
            login.helo.as_deref(),
            rt.shared.next_session_id(),
            rt.server.proxy_ttl,
        );
        let mut leg = match rt
            .establish(dest, self.peer, || dialect.open(rt, dest, ep, &fwd))
            .await
        {
            Ok(leg) => leg,
            Err(err) => {
                ListenerCounters::bump(&counters.backend_failures);
                tracing::warn!(error = %err, protocol = dialect.label(), destination = %dest.name, "backend unavailable");
                return self.unavailable(dialect, &login).await;
            }
        };

        let replayed = timeout(
            rt.server.backend_timeout,
            leg.replay(&mut self.stream, &login, dialect, dest.auth_errors),
        )
        .await
        .unwrap_or_else(|_| Err(ProxyError::timeout(Stage::Auth, Side::Backend)));
        let accepted = match replayed {
            Ok(accepted) => accepted,
            Err(err) if err.side == Side::Client => return Err(err),
            Err(err) => {
                ListenerCounters::bump(&counters.backend_failures);
                tracing::warn!(error = %err, protocol = dialect.label(), destination = %dest.name, "backend authentication did not complete");
                return self.unavailable(dialect, &login).await;
            }
        };

        if !accepted {
            ListenerCounters::bump(&counters.auth_rejected);
            tracing::debug!(
                protocol = dialect.label(),
                destination = %dest.name,
                "backend rejected authentication; resuming pre-authentication dialogue"
            );
            leg.logout(dialect, SHUTDOWN_GRACE).await;
            return Ok(LoginOutcome::Rejected(Box::new(self)));
        }

        ListenerCounters::bump(&counters.auth_ok);
        let (backend, to_client) = leg.into_parts();
        let backend_addr = backend
            .peer_addr()
            .map_err(|err| ProxyError::io(Stage::Auth, Side::Backend, err))?;
        let guard = rt.shared.registry.register(NewConn {
            key: login.key,
            protocol: dialect.protocol(),
            listener: self.listener.id,
            client: self.peer,
            dest: dest_id,
            backend: backend_addr,
            client_tls: self.stream.tls_info(),
            backend_tls: backend.tls_info(),
        });
        let ClientConn {
            stream, mut buf, ..
        } = self;
        let args = BridgeArgs {
            to_backend: buf.take_residual(),
            to_client,
            kick: Some(guard.cancel()),
            info: Some(guard.info().clone()),
            ..BridgeArgs::new(stream, backend, rt.server.bridge_idle)
        };
        Ok(LoginOutcome::Bridged(Box::new(Session {
            args,
            dialect,
            dest: dest.name.clone(),
            started,
            guard,
        })))
    }
}
