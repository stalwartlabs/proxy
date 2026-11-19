/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod body;
mod exchange;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::sync::watch;
use tokio::time::timeout;

use crate::config::{ForwardedMode, Protocol};
use crate::error::{ErrorKind, ProxyError, Result, Side, Stage};
use crate::net::bridge::{BridgeArgs, SHUTDOWN_GRACE, wait_kick};
use crate::net::dial::Peers;
use crate::net::stream::{BackendStream, ClientStream};
use crate::route::Route;
use crate::route::key::RoutingKey;
use crate::runtime::destination::{CredentialEgress, ForwardedHeader, LegTls};
use crate::runtime::registry::{ConnGuard, ConnInfo, ConnRegistry, NewConn};
use crate::runtime::{DestId, ListenerId, ListenerSettings, Runtime};

use super::head::{BodyFraming, Head, HeaderKind, MessageKind};
use super::router::{Extracted, MatchError, RouteOutcome};
use super::serialize::{error_response, reason_phrase};

use crate::http::reader::{Reader, wire_len};
use body::{flush, send};
use exchange::{Exchange, ExchangeOpts, ExchangeResult, Idle};

const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";

struct Conn<'a> {
    rt: &'a Runtime,
    listener: &'a ListenerSettings,
    id: ListenerId,
    peer: SocketAddr,
    local: SocketAddr,
}

struct Leg {
    dest: DestId,
    addr: SocketAddr,
    forwarded_for: Option<IpAddr>,
}

enum Account {
    Anonymous { kick: watch::Sender<bool> },
    Pinned { key: RoutingKey, guard: ConnGuard },
}

impl Account {
    fn accepts(&self, key: Option<&Extracted>) -> bool {
        match (self, key) {
            (Account::Pinned { key: pinned, .. }, Some(Extracted::Key(key))) => pinned == key,
            (Account::Pinned { .. }, Some(Extracted::Invalid)) => false,
            _ => true,
        }
    }

    fn is_anonymous(&self) -> bool {
        matches!(self, Account::Anonymous { .. })
    }

    fn pin(self, registry: &ConnRegistry, key: &RoutingKey, conn: NewConn) -> Account {
        match self {
            Account::Anonymous { kick } => Account::Pinned {
                key: key.clone(),
                guard: registry.register_with(conn, kick),
            },
            pinned => pinned,
        }
    }

    fn info(&self) -> Option<&ConnInfo> {
        match self {
            Account::Pinned { guard, .. } => Some(guard.info()),
            Account::Anonymous { .. } => None,
        }
    }

    fn into_guard(self) -> Option<ConnGuard> {
        match self {
            Account::Pinned { guard, .. } => Some(guard),
            Account::Anonymous { .. } => None,
        }
    }
}

enum Disposition {
    Close,
    Hijack {
        backend: BackendStream,
        to_backend: Vec<u8>,
        to_client: Vec<u8>,
        guard: Option<ConnGuard>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    First,
    KeepAlive,
}

enum Stop {
    Close,
    Reject(u16),
}

struct Prepared {
    body: Option<Vec<u8>>,
    outcome: RouteOutcome,
}

enum PrepareOutcome {
    Routed(Prepared),
    Rejected(u16),
}

pub async fn handle(
    rt: Arc<Runtime>,
    id: ListenerId,
    mut stream: ClientStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let (kick, kicked) = watch::channel(false);
    let served = {
        let listener = rt
            .listener(id)
            .ok_or_else(|| ProxyError::config("listener has no settings"))?;
        let conn = Conn {
            rt: &rt,
            listener,
            id,
            peer,
            local,
        };
        tokio::select! {
            result = conn.serve(&mut stream, kick) => result?,
            _ = wait_kick(Some(kicked)) => return Err(ProxyError::admin_disconnected()),
        }
    };
    let bridge_idle = rt.server.bridge_idle;
    drop(rt);

    match served {
        Disposition::Close => {
            let _ = timeout(SHUTDOWN_GRACE, stream.shutdown()).await;
            Ok(())
        }
        Disposition::Hijack {
            backend,
            to_backend,
            to_client,
            guard,
        } => {
            BridgeArgs {
                to_backend,
                to_client,
                kick: guard.as_ref().map(ConnGuard::cancel),
                info: guard.as_ref().map(|guard| guard.info().clone()),
                ..BridgeArgs::new(stream, backend, bridge_idle)
            }
            .run()
            .await?;
            Ok(())
        }
    }
}

impl Conn<'_> {
    fn new_conn(
        &self,
        key: &RoutingKey,
        leg: &Leg,
        client: &ClientStream,
        backend: &BackendStream,
    ) -> NewConn {
        NewConn {
            key: Some(key.clone()),
            protocol: Protocol::Http,
            listener: self.id,
            client: self.peer,
            dest: leg.dest,
            backend: leg.addr,
            client_tls: client.tls_info(),
            backend_tls: backend.tls_info(),
        }
    }
}

impl Prepared {
    fn extracted(&self) -> Option<&Extracted> {
        match &self.outcome {
            RouteOutcome::Identifier { key, .. } => Some(key),
            RouteOutcome::Pin(_) => None,
        }
    }

    fn key(&self) -> Option<&RoutingKey> {
        match self.extracted() {
            Some(Extracted::Key(key)) => Some(key),
            _ => None,
        }
    }

    async fn destination(&self, rt: &Runtime) -> Option<DestId> {
        match &self.outcome {
            RouteOutcome::Pin(dest) => Some(*dest),
            RouteOutcome::Identifier { key, fallback } => {
                let mapped = match key {
                    Extracted::Key(key) => match rt.router.route(key).await {
                        Route::Mapped(dest) => Some(dest),
                        Route::Default | Route::Transient => None,
                    },
                    Extracted::Missing | Extracted::Invalid => None,
                };
                mapped.or(*fallback).or(rt.default_dest)
            }
        }
    }
}

impl Conn<'_> {
    async fn serve(
        &self,
        stream: &mut ClientStream,
        kick: watch::Sender<bool>,
    ) -> Result<Disposition> {
        let rt = self.rt;
        let router = rt.http.router.as_ref();
        let max_head = router.max_head_size;
        let idle = Idle {
            body: router.relay_idle,
            stream: rt.server.bridge_idle,
        };

        let mut reader = Reader::new(Side::Client, max_head);
        let mut scratch = Vec::new();
        let mut out = Vec::new();

        let Some((mut head, prepared)) = self
            .next_prepared(
                stream,
                &mut reader,
                &mut scratch,
                self.listener.preauth_timeout,
                Phase::First,
            )
            .await?
        else {
            return Ok(Disposition::Close);
        };
        if let Some(key) = prepared.key() {
            rt.shared.registry.hold_login(key.as_str()).await;
        }
        let Some(target) = prepared.destination(self.rt).await else {
            return Ok(Disposition::reject(stream, 503, idle.body).await);
        };
        let (mut backend, leg) = match self.connect(target).await {
            Ok(connected) => connected,
            Err(err) => {
                tracing::debug!(error = %err, "http backend dial failed");
                return Ok(Disposition::reject(stream, 502, idle.body).await);
            }
        };
        let mut account = Account::Anonymous { kick };
        if let Some(key) = prepared.key() {
            let new = self.new_conn(key, &leg, stream, &backend);
            account = account.pin(&rt.shared.registry, key, new);
        }

        let opts = ExchangeOpts {
            forwarded_for: leg.forwarded_for,
            max_head,
            idle,
            force_close: false,
        };
        let max_requests = router.max_keepalive_requests;
        let mut backend_reader = Reader::new(Side::Backend, max_head);
        let mut body = prepared.body;
        let mut served: u32 = 0;

        loop {
            served = served.saturating_add(1);
            let (outcome, responded) = {
                let mut exchange = Exchange {
                    client: stream,
                    client_reader: &mut reader,
                    backend: &mut backend,
                    backend_reader: &mut backend_reader,
                    out: &mut out,
                    info: account.info(),
                    opts: ExchangeOpts {
                        force_close: max_requests != 0 && served >= max_requests,
                        ..opts
                    },
                    responded: false,
                };
                let outcome = exchange.run(&head, body.as_deref()).await;
                (outcome, exchange.responded)
            };

            match outcome {
                Ok(ExchangeResult::KeepAlive) => {}
                Ok(ExchangeResult::Hijack {
                    to_backend,
                    to_client,
                }) => {
                    return Ok(Disposition::Hijack {
                        backend,
                        to_backend,
                        to_client,
                        guard: account.into_guard(),
                    });
                }
                Ok(ExchangeResult::Close) => return Ok(Disposition::Close),
                Err(err) => {
                    if let Some(status) = err.http_status().filter(|_| !responded) {
                        Disposition::reject(stream, status, idle.body).await;
                    }
                    return Err(err);
                }
            }

            reader.shrink_idle();
            backend_reader.shrink_idle();
            let Some((next, prepared)) = self
                .next_prepared(
                    stream,
                    &mut reader,
                    &mut scratch,
                    router.keepalive_timeout,
                    Phase::KeepAlive,
                )
                .await?
            else {
                return Ok(Disposition::Close);
            };
            head = next;

            let first_login = account.is_anonymous().then(|| prepared.key()).flatten();
            let misdirected = !account.accepts(prepared.extracted()) || {
                if let Some(key) = first_login {
                    rt.shared.registry.hold_login(key.as_str()).await;
                }
                prepared.destination(self.rt).await != Some(target)
            };
            if misdirected {
                if let (Some(buffered), BodyFraming::Length(n)) = (&prepared.body, head.framing()) {
                    let remaining = n.saturating_sub(buffered.len() as u64);
                    let _ = reader.discard(stream, remaining, idle.body).await;
                }
                return Ok(Disposition::reject(stream, 421, idle.body).await);
            }
            if let Some(key) = first_login {
                let new = self.new_conn(key, &leg, stream, &backend);
                account = account.pin(&rt.shared.registry, key, new);
            }
            body = prepared.body;
        }
    }

    async fn connect(&self, target: DestId) -> Result<(BackendStream, Leg)> {
        let rt = self.rt;
        let dest = rt
            .destination(target)
            .ok_or_else(|| ProxyError::unavailable(Stage::Connect, "destination was removed"))?;
        let ep = dest.endpoint(Protocol::Http)?;
        if matches!(ep.leg, LegTls::Starttls(_)) {
            return Err(ProxyError::config("http endpoints cannot use starttls"));
        }
        let peers = Peers {
            peer: self.peer,
            local: self.local,
        };
        let backend = rt
            .establish(dest, self.peer, || dest.dial(ep, peers, &rt.loop_guard))
            .await?;
        if !backend.is_tls() && ep.egress != CredentialEgress::PlaintextAllowed {
            return Err(ProxyError::unavailable(
                Stage::Connect,
                "refusing to send credentials over an unencrypted backend leg",
            ));
        }
        let addr = backend
            .peer_addr()
            .map_err(|err| ProxyError::io(Stage::Connect, Side::Backend, err))?;
        let forwarded_for = match ep.forwarded_header {
            ForwardedHeader::Append => Some(self.peer.ip()),
            ForwardedHeader::Off => None,
        };
        Ok((
            backend,
            Leg {
                dest: target,
                addr,
                forwarded_for,
            },
        ))
    }

    async fn next_prepared(
        &self,
        stream: &mut ClientStream,
        reader: &mut Reader,
        scratch: &mut Vec<usize>,
        wait: Duration,
        phase: Phase,
    ) -> Result<Option<(Head, Prepared)>> {
        let router = self.rt.http.router.as_ref();
        let idle = router.relay_idle;
        let mut head = match reader
            .next_request(stream, router.max_head_size, wait, phase)
            .await
        {
            Ok(head) => head,
            Err(Stop::Close) => return Ok(None),
            Err(Stop::Reject(status)) => {
                Disposition::reject(stream, status, idle).await;
                return Ok(None);
            }
        };
        head.sanitize_inbound_forwarded(self.listener);
        match self
            .prepare(stream, reader, &mut head, scratch, idle)
            .await?
        {
            PrepareOutcome::Routed(prepared) => Ok(Some((head, prepared))),
            PrepareOutcome::Rejected(status) => {
                Disposition::reject(stream, status, idle).await;
                Ok(None)
            }
        }
    }

    async fn prepare(
        &self,
        stream: &mut ClientStream,
        reader: &mut Reader,
        head: &mut Head,
        scratch: &mut Vec<usize>,
        idle: Duration,
    ) -> Result<PrepareOutcome> {
        if head.flags().websocket
            && !matches!(head.framing(), BodyFraming::None | BodyFraming::Length(0))
        {
            return Ok(PrepareOutcome::Rejected(400));
        }
        let rt = self.rt;
        let router = rt.http.router.as_ref();
        let idx = match router.match_index(head, scratch) {
            Ok(Some(idx)) => idx,
            Ok(None) => return Ok(PrepareOutcome::Rejected(404)),
            Err(MatchError::DotSegment) => return Ok(PrepareOutcome::Rejected(400)),
        };

        let body = match router.needs_body_at(idx) {
            true => {
                if head.flags().expect_continue {
                    send(stream, CONTINUE, Side::Client, idle).await?;
                    flush(stream, Side::Client, idle).await?;
                    head.drop_kind(HeaderKind::Expect);
                }
                Some(
                    reader
                        .buffer_body(stream, head, router.body_extract_cap, idle)
                        .await?,
                )
            }
            false => None,
        };

        let outcome = router.route_at(idx, head, body.as_deref(), &rt.key_rules);
        Ok(PrepareOutcome::Routed(Prepared { body, outcome }))
    }
}

impl Reader {
    async fn next_request(
        &mut self,
        stream: &mut ClientStream,
        max_head: usize,
        wait: Duration,
        phase: Phase,
    ) -> std::result::Result<Head, Stop> {
        let deadline = Instant::now() + wait;
        loop {
            match self.parse_head(max_head, MessageKind::Request) {
                Ok(Some(head)) => return Ok(head),
                Ok(None) => {}
                Err(err) => return Err(Stop::Reject(err.status())),
            }
            if self.is_eof() {
                return match self.is_empty() {
                    true => Err(Stop::Close),
                    false => Err(Stop::Reject(400)),
                };
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match self.fill(stream, left).await {
                Ok(_) => {}
                Err(err) if phase == Phase::First && matches!(err.kind, ErrorKind::Timeout) => {
                    return Err(Stop::Reject(408));
                }
                Err(_) => return Err(Stop::Close),
            }
        }
    }

    async fn buffer_body(
        &mut self,
        stream: &mut ClientStream,
        head: &Head,
        cap: usize,
        idle: Duration,
    ) -> Result<Vec<u8>> {
        let BodyFraming::Length(n) = head.framing() else {
            return Ok(Vec::new());
        };
        let want = wire_len(n).min(cap);
        let mut body = Vec::with_capacity(want);
        while body.len() < want {
            if self.is_empty() && self.fill(stream, idle).await? == 0 {
                break;
            }
            let take = (want - body.len()).min(self.data().len());
            body.extend_from_slice(self.data().get(..take).unwrap_or_default());
            self.consume(take);
        }
        Ok(body)
    }
}

impl Head {
    fn sanitize_inbound_forwarded(&mut self, listener: &ListenerSettings) {
        if listener.forwarded != ForwardedMode::Trust {
            self.drop_kind(HeaderKind::Forwarded);
            self.drop_kind(HeaderKind::XForwardedFor);
        }
    }
}

impl ProxyError {
    fn http_status(&self) -> Option<u16> {
        match (self.side, &self.kind) {
            (Side::Backend, _) => Some(502),
            (Side::Client, ErrorKind::Timeout) => Some(408),
            (Side::Client, ErrorKind::Protocol(_) | ErrorKind::LimitExceeded(_)) => Some(400),
            (Side::Client, _) => None,
        }
    }

    #[cold]
    #[inline(never)]
    fn admin_disconnected() -> ProxyError {
        ProxyError::new(
            Stage::Relay,
            Side::Client,
            ErrorKind::Unavailable("disconnected by admin".into()),
        )
    }
}

impl Disposition {
    async fn reject(stream: &mut ClientStream, status: u16, idle: Duration) -> Disposition {
        let response = error_response(status, reason_phrase(status));
        if send(stream, &response, Side::Client, idle).await.is_ok() {
            let _ = flush(stream, Side::Client, idle).await;
        }
        Disposition::Close
    }
}
