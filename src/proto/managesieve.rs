/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::SocketAddr;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use crate::config::{Forwarding, ListenerConfig, ManageSieveCapabilities, Protocol, TlsMode};
use crate::error::{ProxyError, Result};
use crate::imap_receiver::{Command, Error as RecvError, Mechanism, Receiver, State};
use crate::net::BoxedStream;
use crate::outbound;
use crate::proto::common::{
    self, Ctx, Handoff, assert_egress_encrypted, credential_from_sasl, mechanism_name,
    plain_auth_allowed, write,
};
use crate::proto::forward;
use crate::sasl::decode_sasl_ir;
use crate::token::identifier_from_credential;

const MAX_PREAUTH: usize = 64 * 1024;

pub async fn handle(
    ctx: &Ctx,
    listener: &ListenerConfig,
    stream: BoxedStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let caps = &ctx.config.capabilities.managesieve;

    let handoff = match timeout(
        listener.preauth_timeout,
        preauth(ctx, listener, caps, stream),
    )
    .await
    {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Ok(()),
    };

    let Handoff {
        stream,
        mech,
        raw_challenge,
        identifier,
        residual,
    } = handoff;

    let identifier = ctx.routing_identifier(identifier);
    let dest_id = ctx.resolve(identifier.as_deref()).await;
    let started = std::time::Instant::now();
    common::hold_login(ctx, identifier.as_deref()).await;
    let fwd = forward::ForwardInfo::new(
        peer,
        local,
        stream.is_tls(),
        None,
        ctx.config.server.proxy_ttl,
    );

    let auth_frame = format!(
        "AUTHENTICATE \"{}\" \"{}\"\r\n",
        mechanism_name(&mech),
        BASE64.encode(&raw_challenge)
    );

    common::bridge_authenticated(
        ctx,
        &dest_id,
        stream,
        identifier.as_deref(),
        &residual,
        started,
        "managesieve",
        common::AuthWire::ManageSieve,
        auth_frame.as_bytes(),
        b"NO \"backend unavailable\"\r\n",
        MAX_PREAUTH,
        || open_backend(ctx, &dest_id, &fwd),
    )
    .await
}

async fn preauth(
    ctx: &Ctx,
    listener: &ListenerConfig,
    caps: &ManageSieveCapabilities,
    mut stream: BoxedStream,
) -> Result<Option<Handoff>> {
    let mut is_tls = stream.is_tls();
    let starttls_listener = listener.tls == TlsMode::Starttls;

    write(
        &mut stream,
        ctx.greetings
            .managesieve
            .get(is_tls, starttls_listener && !is_tls)
            .as_bytes(),
    )
    .await?;

    let mut receiver =
        Receiver::<Command>::new().with_start_state(State::Command { is_uid: false });
    receiver.max_request_size = MAX_PREAUTH;
    let mut auth_failures = 0u32;
    let mut read = [0u8; 8192];

    loop {
        let n = stream
            .read(&mut read)
            .await
            .map_err(|e| ProxyError::Protocol(format!("reading client: {e}").into()))?;
        if n == 0 {
            return Ok(None);
        }
        let mut it = read[..n].iter();

        loop {
            match receiver.parse(&mut it) {
                Ok(req) => {
                    let plain_ok = plain_auth_allowed(caps.allow_plain_auth_without_tls, is_tls);
                    match req.command {
                        Command::Capability => {
                            write(
                                &mut stream,
                                ctx.greetings
                                    .managesieve
                                    .get(is_tls, starttls_listener && !is_tls)
                                    .as_bytes(),
                            )
                            .await?;
                        }
                        Command::Noop => {
                            write(&mut stream, &noop_response(&req.tokens)).await?;
                        }
                        Command::Logout => {
                            write(&mut stream, b"OK \"Logout completed.\"\r\n").await?;
                            return Ok(None);
                        }
                        Command::StartTls => {
                            if !starttls_listener || is_tls {
                                write(&mut stream, b"NO \"STARTTLS not available\"\r\n").await?;
                                continue;
                            }
                            let Some(acceptor) = ctx.tls_acceptor.as_ref() else {
                                write(&mut stream, b"NO \"STARTTLS not configured\"\r\n").await?;
                                continue;
                            };
                            write(&mut stream, b"OK \"Begin TLS negotiation now.\"\r\n").await?;
                            stream = common::upgrade_tls_inbound(stream, acceptor).await?;
                            is_tls = true;
                            receiver = Receiver::<Command>::new()
                                .with_start_state(State::Command { is_uid: false });
                            receiver.max_request_size = MAX_PREAUTH;
                            write(
                                &mut stream,
                                ctx.greetings.managesieve.get(is_tls, false).as_bytes(),
                            )
                            .await?;
                            break;
                        }
                        Command::Authenticate => {
                            match handle_authenticate(
                                ctx,
                                &mut stream,
                                plain_ok,
                                &req.tokens,
                                &mut it,
                                &mut auth_failures,
                                listener.max_auth_attempts,
                            )
                            .await?
                            {
                                AuthStep::Done {
                                    mech,
                                    raw_challenge,
                                    identifier,
                                    residual,
                                } => {
                                    return Ok(Some(Handoff {
                                        stream,
                                        mech,
                                        raw_challenge,
                                        identifier,
                                        residual,
                                    }));
                                }
                                AuthStep::Continue => {}
                                AuthStep::Close => return Ok(None),
                            }
                        }
                        _ => {
                            write(
                                &mut stream,
                                b"NO \"Command not allowed in this state.\"\r\n",
                            )
                            .await?;
                        }
                    }
                }
                Err(RecvError::NeedsMoreData) => break,
                Err(RecvError::NeedsLiteral { size }) => {
                    write(&mut stream, format!("{{{size}}}\r\n").as_bytes()).await?;
                    break;
                }
                Err(RecvError::Parse { message }) => {
                    write(
                        &mut stream,
                        format!("NO \"{}\"\r\n", sanitize(&message)).as_bytes(),
                    )
                    .await?;
                    auth_failures += 1;
                    if auth_failures >= listener.max_auth_attempts {
                        return Ok(None);
                    }
                }
            }
        }
    }
}

enum AuthStep {
    Done {
        mech: Mechanism,
        raw_challenge: Vec<u8>,
        identifier: Option<String>,
        residual: Vec<u8>,
    },
    Continue,
    Close,
}

async fn handle_authenticate(
    ctx: &Ctx,
    stream: &mut BoxedStream,
    plain_ok: bool,
    tokens: &[crate::imap_receiver::Token],
    it: &mut std::slice::Iter<'_, u8>,
    auth_failures: &mut u32,
    max_attempts: u32,
) -> Result<AuthStep> {
    let Some(mech_tok) = tokens.first() else {
        write(&mut *stream, b"NO \"Missing mechanism\"\r\n").await?;
        return Ok(AuthStep::Continue);
    };
    let mech = Mechanism::parse(mech_tok.as_bytes());
    match mech {
        Mechanism::Plain | Mechanism::OAuthBearer | Mechanism::XOauth2 => {}
        _ => return fail(stream, "Unsupported mechanism", auth_failures, max_attempts).await,
    }
    if matches!(mech, Mechanism::Plain) && !plain_ok {
        write(
            &mut *stream,
            b"NO \"Cleartext authentication requires TLS\"\r\n",
        )
        .await?;
        return Ok(AuthStep::Continue);
    }

    let (raw_b64, residual): (Vec<u8>, Vec<u8>) = if let Some(ir) = tokens.get(1) {
        (ir.as_bytes().to_vec(), it.as_slice().to_vec())
    } else {
        write(&mut *stream, b"{0}\r\n").await?;
        let seed = it.as_slice().to_vec();
        read_sasl_response(stream, seed).await?
    };

    let Some(raw) = decode_sasl_ir(&raw_b64) else {
        return fail(stream, "Invalid base64", auth_failures, max_attempts).await;
    };
    let Some(cred) = credential_from_sasl(&mech, &raw) else {
        return fail(stream, "Malformed credentials", auth_failures, max_attempts).await;
    };
    let identifier = identifier_from_credential(&cred, &ctx.config.oauth.jwt_username_claim);

    Ok(AuthStep::Done {
        mech,
        raw_challenge: raw,
        identifier,
        residual,
    })
}

async fn fail(
    stream: &mut BoxedStream,
    message: &str,
    auth_failures: &mut u32,
    max_attempts: u32,
) -> Result<AuthStep> {
    write(&mut *stream, format!("NO \"{message}\"\r\n").as_bytes()).await?;
    *auth_failures += 1;
    if *auth_failures >= max_attempts {
        Ok(AuthStep::Close)
    } else {
        Ok(AuthStep::Continue)
    }
}

async fn read_sasl_response(stream: &mut BoxedStream, seed: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {
    let (line, residual) = common::read_crlf_line(stream, seed, MAX_PREAUTH).await?;
    if line.first() == Some(&b'{') && line.last() == Some(&b'}') {
        let inner = &line[1..line.len() - 1];
        let inner = inner.strip_suffix(b"+").unwrap_or(inner);
        let size: usize = std::str::from_utf8(inner)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| ProxyError::preauth("invalid literal size"))?;
        if size > MAX_PREAUTH {
            return Err(ProxyError::preauth("literal too large"));
        }
        let (data, mut rest) = read_exact_from(stream, residual, size).await?;
        if rest.starts_with(b"\r\n") {
            rest.drain(..2);
        } else if rest.starts_with(b"\n") {
            rest.drain(..1);
        }
        Ok((data, rest))
    } else {
        Ok((line, residual))
    }
}

async fn read_exact_from(
    stream: &mut BoxedStream,
    mut seed: Vec<u8>,
    n: usize,
) -> Result<(Vec<u8>, Vec<u8>)> {
    while seed.len() < n {
        let got = common::fill(stream, &mut seed, n + 8192).await?;
        if got == 0 {
            return Err(ProxyError::Closed);
        }
    }
    let residual = seed.split_off(n);
    Ok((seed, residual))
}

fn sanitize(s: &str) -> String {
    s.replace(['"', '\r', '\n'], " ")
}

fn noop_response(tokens: &[crate::imap_receiver::Token]) -> Vec<u8> {
    match tokens
        .first()
        .map(|t| t.as_bytes())
        .filter(|t| !t.is_empty())
    {
        Some(tag) => {
            let mut out = Vec::with_capacity(tag.len() + 24);
            out.extend_from_slice(b"OK (TAG {");
            out.extend_from_slice(tag.len().to_string().as_bytes());
            out.extend_from_slice(b"}\r\n");
            out.extend_from_slice(tag);
            out.extend_from_slice(b") \"Done\"\r\n");
            out
        }
        None => b"OK \"NOOP completed.\"\r\n".to_vec(),
    }
}

pub(crate) fn capability_block(
    caps: &ManageSieveCapabilities,
    offer_starttls: bool,
    is_tls: bool,
) -> String {
    let plain_ok = plain_auth_allowed(caps.allow_plain_auth_without_tls, is_tls);
    use std::fmt::Write;
    let sasl = common::advertised_sasl(&caps.sasl, plain_ok);
    let mut s = String::new();
    let _ = write!(s, "\"IMPLEMENTATION\" \"{}\"\r\n", caps.implementation);
    s.push_str("\"VERSION\" \"1.0\"\r\n");
    let _ = write!(s, "\"SASL\" \"{}\"\r\n", sasl.join(" "));
    let _ = write!(s, "\"SIEVE\" \"{}\"\r\n", caps.sieve.join(" "));
    if offer_starttls {
        s.push_str("\"STARTTLS\"\r\n");
    }
    s.push_str("OK \"Stalwart ManageSieve ready.\"\r\n");
    s
}

async fn open_backend(
    ctx: &Ctx,
    dest_id: &str,
    fwd: &forward::ForwardInfo,
) -> Result<(BoxedStream, Vec<u8>)> {
    let common::DialedEndpoint {
        dest,
        ep,
        tls_cfg,
        forwarding,
        mut backend,
    } = ctx
        .dial_endpoint(dest_id, Protocol::ManageSieve, fwd.peer, fwd.local)
        .await?;
    let mut residual = Vec::new();

    let mut capabilities = read_capabilities(&mut backend, &mut residual).await?;

    if ep.tls == TlsMode::Starttls {
        if !common::advertises_token(&capabilities, "STARTTLS") {
            return Err(ProxyError::backend("backend did not advertise STARTTLS"));
        }
        outbound::write_all(&mut backend, b"STARTTLS\r\n").await?;
        let resp = outbound::read_line(&mut backend, &mut residual, MAX_PREAUTH).await?;
        if !resp.to_ascii_uppercase().starts_with(b"OK") {
            return Err(ProxyError::backend("backend refused STARTTLS"));
        }
        backend = outbound::tls_connect(backend, &tls_cfg, dest).await?;
        capabilities = read_capabilities(&mut backend, &mut residual).await?;
    }

    assert_egress_encrypted(dest, ep, backend.is_tls())?;

    if forwarding == Forwarding::Xclient {
        let advertised = common::advertises_token(&capabilities, "XCLIENT");
        forward::send_managesieve_xclient(
            &mut backend,
            &mut residual,
            advertised,
            fwd,
            MAX_PREAUTH,
        )
        .await?;
    }

    Ok((backend, residual))
}

async fn read_capabilities(stream: &mut BoxedStream, residual: &mut Vec<u8>) -> Result<Vec<u8>> {
    let mut capabilities = Vec::new();
    for _ in 0..256 {
        let line = outbound::read_line(stream, residual, MAX_PREAUTH).await?;
        let upper = line.to_ascii_uppercase();
        let done =
            upper.starts_with(b"OK") || upper.starts_with(b"NO") || upper.starts_with(b"BYE");
        capabilities.extend_from_slice(&line);
        capabilities.push(b'\n');
        if done {
            return Ok(capabilities);
        }
    }
    Err(ProxyError::backend(
        "backend sent too many capability lines",
    ))
}
