/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::time::Duration;

use encodify::base64::STANDARD as BASE64;
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, timeout};

use crate::config::Protocol;
use crate::error::{ErrorKind, ProxyError, Result, Side, Stage};
use crate::net::linebuf::LineBuf;
use crate::net::stream::{BackendStream, ClientStream};
use crate::proto::forward::ForwardInfo;
use crate::proto::sasl_exchange::Reject;
use crate::proto::session::{Login, Tag};
use crate::runtime::Runtime;
use crate::runtime::destination::{AuthErrors, CredentialEgress, Destination, Endpoint};
use crate::runtime::health::Attribution;

const UNTAGGED: &str = "*";
const MAX_AUTH_LINES: usize = 64;
const BACKEND_RETRY_DELAY: Duration = Duration::from_millis(200);
const SASL_EMPTY_RESPONSE: &[u8] = b"AQ==\r\n";
const SASL_EMPTY_RESPONSE_QUOTED: &[u8] = b"\"AQ==\"\r\n";
const MAX_POP3_COMMAND: usize = 255;
const MAX_SMTP_COMMAND: usize = 512;
const MAX_MANAGESIEVE_QUOTED: usize = 1024;

const MAX_BACKEND_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialResponse {
    Inline,
    Deferred,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    Imap,
    Pop3,
    ManageSieve,
    Submission,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientResponse<'a> {
    Data(&'a [u8]),
    LiteralFollows,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartTlsReply {
    Unavailable,
    NotConfigured,
    Begin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthLine {
    Continuation,
    Passthrough,
    FinalOk,
    FinalFail,
}

impl Dialect {
    pub fn protocol(self) -> Protocol {
        match self {
            Dialect::Imap => Protocol::Imap,
            Dialect::Pop3 => Protocol::Pop3,
            Dialect::ManageSieve => Protocol::ManageSieve,
            Dialect::Submission => Protocol::Submission,
        }
    }

    pub fn label(self) -> &'static str {
        self.protocol().as_str()
    }

    pub async fn open(
        self,
        rt: &Runtime,
        dest: &Destination,
        ep: &Endpoint,
        fwd: &ForwardInfo<'_>,
    ) -> Result<EncryptedLeg> {
        match self {
            Dialect::Imap => EncryptedLeg::open_imap(rt, dest, ep, fwd).await,
            Dialect::Pop3 => EncryptedLeg::open_pop3(rt, dest, ep, fwd).await,
            Dialect::ManageSieve => EncryptedLeg::open_managesieve(rt, dest, ep, fwd).await,
            Dialect::Submission => EncryptedLeg::open_submission(rt, dest, ep, fwd).await,
        }
    }

    pub fn write_challenge(self, out: &mut Vec<u8>, b64: &[u8]) {
        out.reserve(b64.len() + 16);
        match self {
            Dialect::Imap | Dialect::Pop3 => out.extend_from_slice(b"+ "),
            Dialect::Submission => out.extend_from_slice(b"334 "),
            Dialect::ManageSieve => {
                let _ = write!(out, "{{{}}}\r\n", b64.len());
            }
        }
        out.extend_from_slice(b64);
        out.extend_from_slice(b"\r\n");
    }

    pub fn client_response(self, line: &[u8]) -> ClientResponse<'_> {
        if self != Dialect::ManageSieve {
            return ClientResponse::Data(line);
        }
        let line = line.trim_ascii();
        if let Some(size) = line.strip_prefix(b"{").and_then(|l| l.strip_suffix(b"}")) {
            let size = size.strip_suffix(b"+").unwrap_or(size);
            if !size.is_empty() && size.iter().all(u8::is_ascii_digit) {
                return ClientResponse::LiteralFollows;
            }
        }
        match line.strip_prefix(b"\"").and_then(|l| l.strip_suffix(b"\"")) {
            Some(quoted) => ClientResponse::Data(quoted),
            None => ClientResponse::Data(line),
        }
    }

    pub fn write_starttls(self, out: &mut Vec<u8>, reply: StartTlsReply, tag: Option<&str>) {
        let line: &[u8] = match self {
            Dialect::Imap => {
                write_tag(out, tag);
                match reply {
                    StartTlsReply::Unavailable => b" BAD STARTTLS not available.\r\n",
                    StartTlsReply::NotConfigured => b" NO STARTTLS not configured.\r\n",
                    StartTlsReply::Begin => b" OK Begin TLS negotiation now.\r\n",
                }
            }
            Dialect::Pop3 => match reply {
                StartTlsReply::Unavailable => b"-ERR STLS not available\r\n",
                StartTlsReply::NotConfigured => b"-ERR STLS not configured\r\n",
                StartTlsReply::Begin => b"+OK Begin TLS negotiation\r\n",
            },
            Dialect::ManageSieve => match reply {
                StartTlsReply::Unavailable => b"NO \"STARTTLS not available\"\r\n",
                StartTlsReply::NotConfigured => b"NO \"STARTTLS not configured\"\r\n",
                StartTlsReply::Begin => b"OK \"Begin TLS negotiation now.\"\r\n",
            },
            Dialect::Submission => match reply {
                StartTlsReply::Unavailable => b"503 5.5.1 STARTTLS not available\r\n",
                StartTlsReply::NotConfigured => b"454 4.7.0 STARTTLS not configured\r\n",
                StartTlsReply::Begin => b"220 2.0.0 Ready to start TLS\r\n",
            },
        };
        out.extend_from_slice(line);
    }

    pub fn write_reject(self, out: &mut Vec<u8>, why: Reject, tag: Option<&str>) {
        let line: &[u8] = match self {
            Dialect::Imap => {
                write_tag(out, tag);
                match why {
                    Reject::Unsupported => b" NO Unsupported authentication mechanism.\r\n",
                    Reject::PrivacyRequired => {
                        b" NO [PRIVACYREQUIRED] Cleartext authentication requires TLS.\r\n"
                    }
                    Reject::InvalidBase64 => b" NO Invalid base64 in SASL response.\r\n",
                    Reject::Malformed => b" NO Malformed credentials.\r\n",
                    Reject::Cancelled => b" NO Authentication cancelled.\r\n",
                    Reject::TooLong => b" BAD Authentication exchange too long.\r\n",
                }
            }
            Dialect::Pop3 => match why {
                Reject::Unsupported => b"-ERR unsupported mechanism\r\n",
                Reject::PrivacyRequired => b"-ERR cleartext authentication requires TLS\r\n",
                Reject::InvalidBase64 => b"-ERR invalid base64\r\n",
                Reject::Malformed => b"-ERR malformed credentials\r\n",
                Reject::Cancelled => b"-ERR authentication cancelled\r\n",
                Reject::TooLong => b"-ERR authentication exchange too long\r\n",
            },
            Dialect::ManageSieve => match why {
                Reject::Unsupported => b"NO \"Unsupported mechanism\"\r\n",
                Reject::PrivacyRequired => b"NO \"Cleartext authentication requires TLS\"\r\n",
                Reject::InvalidBase64 => b"NO \"Invalid base64\"\r\n",
                Reject::Malformed => b"NO \"Malformed credentials\"\r\n",
                Reject::Cancelled => b"NO \"Authentication cancelled\"\r\n",
                Reject::TooLong => b"NO \"Authentication exchange too long\"\r\n",
            },
            Dialect::Submission => match why {
                Reject::Unsupported => b"504 5.5.4 Unsupported authentication mechanism\r\n",
                Reject::PrivacyRequired => {
                    b"538 5.7.11 Encryption required for requested authentication mechanism\r\n"
                }
                Reject::InvalidBase64 => b"501 5.5.2 Invalid base64\r\n",
                Reject::Malformed => b"535 5.7.8 Malformed credentials\r\n",
                Reject::Cancelled => b"501 5.7.0 Authentication cancelled\r\n",
                Reject::TooLong => b"500 5.5.6 Authentication Exchange line is too long\r\n",
            },
        };
        out.extend_from_slice(line);
    }

    pub fn write_unavailable(self, out: &mut Vec<u8>, tag: Option<&str>) {
        let line: &[u8] = match self {
            Dialect::Imap => {
                write_tag(out, tag);
                b" NO [UNAVAILABLE] backend unavailable\r\n"
            }
            Dialect::Pop3 => b"-ERR backend unavailable\r\n",
            Dialect::ManageSieve => b"NO \"backend unavailable\"\r\n",
            Dialect::Submission => b"421 4.3.0 backend unavailable\r\n",
        };
        out.extend_from_slice(line);
    }

    fn write_generic_failure(self, out: &mut Vec<u8>, tag: Option<&str>) {
        let line: &[u8] = match self {
            Dialect::Imap => {
                write_tag(out, tag);
                b" NO [AUTHENTICATIONFAILED] Authentication failed.\r\n"
            }
            Dialect::Pop3 => b"-ERR Authentication failed.\r\n",
            Dialect::ManageSieve => b"NO \"Authentication failed.\"\r\n",
            Dialect::Submission => b"535 5.7.8 Authentication failed.\r\n",
        };
        out.extend_from_slice(line);
    }

    pub fn preauth_farewell(self) -> &'static [u8] {
        match self {
            Dialect::Imap => b"* BYE Pre-authentication timeout\r\n",
            Dialect::Pop3 => b"-ERR Pre-authentication timeout\r\n",
            Dialect::ManageSieve => b"BYE \"Pre-authentication timeout\"\r\n",
            Dialect::Submission => b"421 4.4.2 Pre-authentication timeout\r\n",
        }
    }

    pub fn logout(self) -> &'static [u8] {
        match self {
            Dialect::Imap => b"ZZ LOGOUT\r\n",
            Dialect::Pop3 | Dialect::Submission => b"QUIT\r\n",
            Dialect::ManageSieve => b"LOGOUT\r\n",
        }
    }

    pub fn classify(self, line: &[u8], tag: Option<&Tag>) -> AuthLine {
        match self {
            Dialect::Imap => {
                if line.first() == Some(&b'+') {
                    return AuthLine::Continuation;
                }
                let tag = tag.map_or(UNTAGGED, Tag::as_str).as_bytes();
                let tagged = starts_with_ci(line, tag) && line.get(tag.len()) == Some(&b' ');
                match line.get(tag.len() + 1..) {
                    Some(rest) if tagged => {
                        AuthLine::final_status(starts_with_ci(rest.trim_ascii_start(), b"OK"))
                    }
                    _ => AuthLine::Passthrough,
                }
            }
            Dialect::Pop3 => {
                if line == b"+" || line.starts_with(b"+ ") {
                    AuthLine::Continuation
                } else {
                    AuthLine::final_status(line.starts_with(b"+OK"))
                }
            }
            Dialect::Submission => {
                let Some([a, b, c]) = line.first_chunk::<3>() else {
                    return AuthLine::FinalFail;
                };
                if !(a.is_ascii_digit() && b.is_ascii_digit() && c.is_ascii_digit()) {
                    return AuthLine::FinalFail;
                }
                match (*a, *b, *c, line.get(3)) {
                    (b'3', b'3', b'4', _) => AuthLine::Continuation,
                    (_, _, _, Some(b'-')) => AuthLine::Passthrough,
                    (b'2', _, _, _) => AuthLine::FinalOk,
                    _ => AuthLine::FinalFail,
                }
            }
            Dialect::ManageSieve => {
                if matches!(line.first(), Some(b'{' | b'+' | b'"')) {
                    return AuthLine::Continuation;
                }
                let line = line.trim_ascii_start();
                if starts_with_ci(line, b"OK") {
                    AuthLine::FinalOk
                } else if starts_with_ci(line, b"NO") || starts_with_ci(line, b"BYE") {
                    AuthLine::FinalFail
                } else {
                    AuthLine::Passthrough
                }
            }
        }
    }

    fn empty_response(self) -> &'static [u8] {
        match self {
            Dialect::ManageSieve => SASL_EMPTY_RESPONSE_QUOTED,
            Dialect::Imap | Dialect::Pop3 | Dialect::Submission => SASL_EMPTY_RESPONSE,
        }
    }

    pub fn auth_frame(
        self,
        out: &mut Vec<u8>,
        login: &Login,
        initial: InitialResponse,
    ) -> Option<usize> {
        let mech = login.mech.as_str().as_bytes();
        let encoded = BASE64.encoded_len(login.response.len());
        out.reserve(encoded + mech.len() + 32);
        let quoted = self == Dialect::ManageSieve && encoded <= MAX_MANAGESIEVE_QUOTED;
        let deferred = match self {
            Dialect::Imap => {
                write_tag(out, login.tag.as_ref().map(Tag::as_str));
                out.extend_from_slice(b" AUTHENTICATE ");
                out.extend_from_slice(mech);
                match initial {
                    InitialResponse::Inline => {
                        out.push(b' ');
                        None
                    }
                    InitialResponse::Deferred => {
                        out.extend_from_slice(b"\r\n");
                        Some(out.len())
                    }
                }
            }
            Dialect::Pop3 | Dialect::Submission => {
                let limit = match self {
                    Dialect::Pop3 => MAX_POP3_COMMAND,
                    _ => MAX_SMTP_COMMAND,
                };
                out.extend_from_slice(b"AUTH ");
                out.extend_from_slice(mech);
                if initial == InitialResponse::Inline
                    && b"AUTH ".len() + mech.len() + 1 + encoded + 2 <= limit
                {
                    out.push(b' ');
                    None
                } else {
                    out.extend_from_slice(b"\r\n");
                    Some(out.len())
                }
            }
            Dialect::ManageSieve => {
                out.extend_from_slice(b"AUTHENTICATE \"");
                out.extend_from_slice(mech);
                if quoted {
                    out.extend_from_slice(b"\" \"");
                } else {
                    let _ = write!(out, "\" {{{encoded}+}}\r\n");
                }
                None
            }
        };
        BASE64.encode_append(&login.response, out);
        if quoted {
            out.push(b'"');
        }
        out.extend_from_slice(b"\r\n");
        deferred
    }
}

fn write_tag(out: &mut Vec<u8>, tag: Option<&str>) {
    out.extend_from_slice(tag.unwrap_or(UNTAGGED).as_bytes());
}

pub fn starts_with_ci(line: &[u8], prefix: &[u8]) -> bool {
    line.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

impl AuthLine {
    fn final_status(ok: bool) -> Self {
        if ok {
            AuthLine::FinalOk
        } else {
            AuthLine::FinalFail
        }
    }
}

pub struct EncryptedLeg {
    stream: BackendStream,
    buf: LineBuf,
    initial: InitialResponse,
}

impl EncryptedLeg {
    pub fn new(
        stream: BackendStream,
        buf: LineBuf,
        ep: &Endpoint,
        initial: InitialResponse,
    ) -> Result<Self> {
        if !stream.is_tls() && ep.egress != CredentialEgress::PlaintextAllowed {
            return Err(ProxyError::plaintext_egress());
        }
        Ok(EncryptedLeg {
            stream,
            buf,
            initial,
        })
    }

    pub async fn send(&mut self, bytes: &[u8], stage: Stage) -> Result<()> {
        self.stream.send(bytes, stage).await
    }

    pub async fn read_line(&mut self, stage: Stage) -> Result<&[u8]> {
        self.buf.set_stage(stage);
        self.buf.read_line(&mut self.stream).await
    }

    pub fn into_parts(mut self) -> (BackendStream, Vec<u8>) {
        let residual = self.buf.take_residual();
        (self.stream, residual)
    }

    pub async fn replay(
        &mut self,
        client: &mut ClientStream,
        login: &Login,
        dialect: Dialect,
        errors: AuthErrors,
    ) -> Result<bool> {
        let mut frame = Vec::new();
        let split = dialect.auth_frame(&mut frame, login, self.initial);
        let (command, mut pending) = match split.and_then(|at| frame.split_at_checked(at)) {
            Some((command, response)) => (command, Some(response)),
            None => (frame.as_slice(), None),
        };
        self.send(command, Stage::Auth).await?;

        let mut client_out = Vec::new();
        for _ in 0..MAX_AUTH_LINES {
            let line = self.read_line(Stage::Auth).await?;
            match dialect.classify(line, login.tag.as_ref()) {
                AuthLine::Continuation => {
                    if dialect == Dialect::ManageSieve && line.first() == Some(&b'{') {
                        self.read_line(Stage::Auth).await?;
                    }
                    let response = pending.take().unwrap_or(dialect.empty_response());
                    self.send(response, Stage::Auth).await?;
                }
                AuthLine::Passthrough => {
                    client_out.extend_from_slice(line);
                    client_out.extend_from_slice(b"\r\n");
                }
                AuthLine::FinalOk => {
                    client_out.extend_from_slice(line);
                    client_out.extend_from_slice(b"\r\n");
                    client.send(&client_out).await?;
                    return Ok(true);
                }
                AuthLine::FinalFail => {
                    match errors {
                        AuthErrors::Hide => dialect.write_generic_failure(
                            &mut client_out,
                            login.tag.as_ref().map(Tag::as_str),
                        ),
                        AuthErrors::Relay => {
                            client_out.extend_from_slice(line);
                            client_out.extend_from_slice(b"\r\n");
                        }
                    }
                    client.send(&client_out).await?;
                    return Ok(false);
                }
            }
        }
        Err(ProxyError::unavailable(
            Stage::Auth,
            "backend auth dialogue did not complete",
        ))
    }

    pub async fn logout(mut self, dialect: Dialect, grace: Duration) {
        let _ = self.stream.send(dialect.logout(), Stage::Auth).await;
        let _ = timeout(grace, self.stream.shutdown()).await;
    }
}

impl Destination {
    pub async fn connect_backend(
        &self,
        rt: &Runtime,
        ep: &Endpoint,
        fwd: &ForwardInfo<'_>,
    ) -> Result<(BackendStream, LineBuf)> {
        let stream = self.dial(ep, fwd.peers(), &rt.loop_guard).await?;
        Ok((stream, LineBuf::backend(MAX_BACKEND_LINE)))
    }
}

impl Runtime {
    pub async fn establish<F, Fut, T>(
        &self,
        dest: &Destination,
        peer: SocketAddr,
        mut open: F,
    ) -> Result<T>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let clock = &self.shared.clock;
        dest.health.gate(clock)?;
        let server = &self.server;
        let mut attempt: u32 = 0;
        loop {
            let err = match timeout(server.backend_timeout, open()).await {
                Ok(Ok(value)) => {
                    self.shared
                        .note_health(&dest.name, dest.health.record_success());
                    return Ok(value);
                }
                Ok(Err(err)) => err,
                Err(_) => ProxyError::timeout(Stage::Connect, Side::Backend),
            };
            if err.is_retryable() && attempt < server.backend_connect_retries {
                attempt += 1;
                tracing::debug!(
                    destination = %dest.name,
                    attempt,
                    error = %err,
                    "retrying backend connection"
                );
                sleep(BACKEND_RETRY_DELAY).await;
                continue;
            }
            if !matches!(err.kind, ErrorKind::Config(_)) {
                let at = err.attribution(peer.ip());
                if matches!(at, Attribution::Client(_)) {
                    tracing::debug!(
                        destination = %dest.name,
                        error = %err,
                        "backend failure attributed to the client, not counted as host evidence on its own"
                    );
                }
                let change = dest
                    .health
                    .record_failure(at, &err, &server.health, clock.now());
                self.shared.note_health(&dest.name, change);
            }
            return Err(err);
        }
    }
}

impl ProxyError {
    #[cold]
    #[inline(never)]
    fn plaintext_egress() -> ProxyError {
        ProxyError::unavailable(
            Stage::Starttls,
            "refusing to send credentials over an unencrypted backend leg",
        )
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/proto/backend/tests.rs"]
mod tests;
