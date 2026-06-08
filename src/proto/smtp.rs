/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::SocketAddr;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use smtp_proto::{AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2, Error as SmtpError, Request};
use tokio::time::timeout;

use crate::config::{Forwarding, ListenerConfig, Protocol, SubmissionCapabilities, TlsMode};
use crate::error::{ProxyError, Result};
use crate::imap_receiver::Mechanism;
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

struct SubmissionHandoff {
    handoff: Handoff,
    ehlo_host: String,
}

pub async fn handle_submission(
    ctx: &Ctx,
    listener: &ListenerConfig,
    stream: BoxedStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let caps = &ctx.config.capabilities.submission;

    let sh = match timeout(
        listener.preauth_timeout,
        preauth(ctx, listener, caps, stream, local),
    )
    .await
    {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Ok(()),
    };

    let SubmissionHandoff { handoff, ehlo_host } = sh;
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
        Some(ehlo_host),
        ctx.config.server.proxy_ttl,
    );

    let auth_frame = format!(
        "AUTH {} {}\r\n",
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
        "submission",
        common::AuthWire::Smtp,
        auth_frame.as_bytes(),
        b"421 4.3.0 backend unavailable\r\n",
        MAX_PREAUTH,
        || open_backend(ctx, &dest_id, &fwd),
    )
    .await
}

async fn preauth(
    ctx: &Ctx,
    listener: &ListenerConfig,
    caps: &SubmissionCapabilities,
    mut stream: BoxedStream,
    local: SocketAddr,
) -> Result<Option<SubmissionHandoff>> {
    let mut is_tls = stream.is_tls();
    let starttls_listener = listener.tls == TlsMode::Starttls;
    let hostname = ctx.config.server.hostname_for(local);

    write(
        &mut stream,
        format!("220 {hostname} ESMTP {}\r\n", caps.banner).as_bytes(),
    )
    .await?;

    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut ehlo_host = String::new();
    let mut auth_failures = 0u32;

    loop {
        let mut it = buf.iter();
        let parsed = Request::parse(&mut it);
        let consumed = buf.len() - it.as_slice().len();
        drop(it);

        match parsed {
            Ok(req) => {
                let plain_ok = plain_auth_allowed(caps.allow_plain_auth_without_tls, is_tls);
                match req {
                    Request::Ehlo { host } | Request::Lhlo { host } => {
                        ehlo_host = host.to_string();
                        let resp = ehlo_response(
                            &hostname,
                            &ehlo_host,
                            caps,
                            starttls_listener && !is_tls,
                            plain_ok,
                        );
                        write(&mut stream, resp.as_bytes()).await?;
                        buf.drain(..consumed);
                    }
                    Request::Helo { host } => {
                        ehlo_host = host.to_string();
                        write(&mut stream, format!("250 {hostname}\r\n").as_bytes()).await?;
                        buf.drain(..consumed);
                    }
                    Request::Noop { .. } => {
                        write(&mut stream, b"250 2.0.0 OK\r\n").await?;
                        buf.drain(..consumed);
                    }
                    Request::Rset => {
                        write(&mut stream, b"250 2.0.0 OK\r\n").await?;
                        buf.drain(..consumed);
                    }
                    Request::Quit => {
                        write(&mut stream, b"221 2.0.0 Bye\r\n").await?;
                        return Ok(None);
                    }
                    Request::StartTls => {
                        if !starttls_listener || is_tls {
                            write(&mut stream, b"503 5.5.1 STARTTLS not available\r\n").await?;
                            buf.drain(..consumed);
                            continue;
                        }
                        let Some(acceptor) = ctx.tls_acceptor.as_ref() else {
                            write(&mut stream, b"454 4.7.0 STARTTLS not configured\r\n").await?;
                            buf.drain(..consumed);
                            continue;
                        };
                        write(&mut stream, b"220 2.0.0 Ready to start TLS\r\n").await?;
                        buf.clear();
                        stream = common::upgrade_tls_inbound(stream, acceptor).await?;
                        is_tls = true;
                        ehlo_host.clear();
                    }
                    Request::Auth {
                        mechanism,
                        initial_response,
                    } => {
                        let ir = initial_response.into_owned();
                        let params = AuthParams {
                            ctx,
                            plain_ok,
                            ehlo_host: &ehlo_host,
                            max_attempts: listener.max_auth_attempts,
                        };
                        match handle_auth(
                            &params,
                            &mut stream,
                            &mut buf,
                            consumed,
                            mechanism,
                            &ir,
                            &mut auth_failures,
                        )
                        .await?
                        {
                            AuthStep::Done {
                                mech,
                                raw_challenge,
                                identifier,
                                residual,
                                ehlo_host,
                            } => {
                                return Ok(Some(SubmissionHandoff {
                                    handoff: Handoff {
                                        stream,
                                        mech,
                                        raw_challenge,
                                        identifier,
                                        residual,
                                    },
                                    ehlo_host,
                                }));
                            }
                            AuthStep::Continue => {}
                            AuthStep::Close => return Ok(None),
                        }
                    }
                    _ => {
                        write(&mut stream, b"503 5.5.1 Command not allowed here\r\n").await?;
                        buf.drain(..consumed);
                    }
                }
            }
            Err(SmtpError::NeedsMoreData { .. }) => {
                if buf.len() > MAX_PREAUTH {
                    return Err(ProxyError::preauth("smtp line too long"));
                }
                let n = common::fill(&mut stream, &mut buf, MAX_PREAUTH + 8192).await?;
                if n == 0 {
                    return Ok(None);
                }
            }
            Err(_) => {
                let drop_to = if consumed == 0 { buf.len() } else { consumed };
                buf.drain(..drop_to);
                write(&mut stream, b"500 5.5.2 Syntax error\r\n").await?;
                auth_failures += 1;
                if auth_failures >= listener.max_auth_attempts {
                    return Ok(None);
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
        ehlo_host: String,
    },
    Continue,
    Close,
}

struct AuthParams<'a> {
    ctx: &'a Ctx,
    plain_ok: bool,
    ehlo_host: &'a str,
    max_attempts: u32,
}

async fn handle_auth(
    params: &AuthParams<'_>,
    stream: &mut BoxedStream,
    buf: &mut Vec<u8>,
    consumed: usize,
    mechanism: u64,
    initial_response: &str,
    auth_failures: &mut u32,
) -> Result<AuthStep> {
    let max_attempts = params.max_attempts;

    let Some(mech) = mech_from_flag(mechanism) else {
        return fail(
            stream,
            buf,
            consumed,
            "5.7.0 Unsupported authentication mechanism",
            auth_failures,
            max_attempts,
        )
        .await;
    };
    if matches!(mech, Mechanism::Plain) && !params.plain_ok {
        write(
            &mut *stream,
            b"538 5.7.11 Encryption required for requested authentication mechanism\r\n",
        )
        .await?;
        buf.drain(..consumed);
        return Ok(AuthStep::Continue);
    }

    let raw_b64: Vec<u8> = if !initial_response.is_empty() {
        let ir = initial_response.as_bytes().to_vec();
        buf.drain(..consumed);
        ir
    } else {
        write(&mut *stream, b"334 \r\n").await?;
        buf.drain(..consumed);
        let seed = std::mem::take(buf);
        let (line, rest) = common::read_crlf_line(stream, seed, MAX_PREAUTH).await?;
        *buf = rest;
        line
    };

    let Some(raw) = decode_sasl_ir(&raw_b64) else {
        return fail(
            stream,
            buf,
            0,
            "5.7.8 Invalid base64",
            auth_failures,
            max_attempts,
        )
        .await;
    };
    let Some(cred) = credential_from_sasl(&mech, &raw) else {
        return fail(
            stream,
            buf,
            0,
            "5.7.8 Malformed credentials",
            auth_failures,
            max_attempts,
        )
        .await;
    };
    let identifier = identifier_from_credential(&cred, &params.ctx.config.oauth.jwt_username_claim);
    let residual = std::mem::take(buf);

    Ok(AuthStep::Done {
        mech,
        raw_challenge: raw,
        identifier,
        residual,
        ehlo_host: params.ehlo_host.to_string(),
    })
}

async fn fail(
    stream: &mut BoxedStream,
    buf: &mut Vec<u8>,
    drain: usize,
    message: &str,
    auth_failures: &mut u32,
    max_attempts: u32,
) -> Result<AuthStep> {
    if drain > 0 {
        buf.drain(..drain);
    }
    write(&mut *stream, format!("535 {message}\r\n").as_bytes()).await?;
    *auth_failures += 1;
    if *auth_failures >= max_attempts {
        Ok(AuthStep::Close)
    } else {
        Ok(AuthStep::Continue)
    }
}

fn mech_from_flag(flag: u64) -> Option<Mechanism> {
    if flag & AUTH_PLAIN != 0 {
        Some(Mechanism::Plain)
    } else if flag & AUTH_OAUTHBEARER != 0 {
        Some(Mechanism::OAuthBearer)
    } else if flag & AUTH_XOAUTH2 != 0 {
        Some(Mechanism::XOauth2)
    } else {
        None
    }
}

fn ehlo_response(
    hostname: &str,
    client_host: &str,
    caps: &SubmissionCapabilities,
    offer_starttls: bool,
    plain_ok: bool,
) -> String {
    use std::fmt::Write;

    let greeting = format!("{hostname} at your service, [{client_host}]");
    let mechs = common::advertised_sasl(&caps.sasl, plain_ok);
    let auth_line = (!mechs.is_empty()).then(|| format!("AUTH {}", mechs.join(" ")));

    let mut lines: Vec<&str> = Vec::with_capacity(caps.ehlo.len() + 3);
    lines.push(&greeting);
    lines.extend(caps.ehlo.iter().map(String::as_str));
    if offer_starttls {
        lines.push("STARTTLS");
    }
    if let Some(auth) = &auth_line {
        lines.push(auth);
    }

    let last = lines.len().saturating_sub(1);
    let mut out = String::new();
    for (i, line) in lines.iter().enumerate() {
        let sep = if i == last { ' ' } else { '-' };
        let _ = write!(out, "250{sep}{line}\r\n");
    }
    out
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
        .dial_endpoint(dest_id, Protocol::Submission, fwd.peer, fwd.local)
        .await?;
    let mut residual = Vec::new();
    let fallback_helo = ctx.config.server.hostname.as_deref().unwrap_or("proxy");
    let ehlo = match fwd.helo.as_deref() {
        Some(h) if !h.is_empty() => h,
        _ => fallback_helo,
    };

    read_smtp_reply(&mut backend, &mut residual, 220).await?;
    let mut ehlo_reply = send_ehlo_expect(&mut backend, &mut residual, ehlo).await?;

    if ep.tls == TlsMode::Starttls {
        if !common::advertises_token(&ehlo_reply, "STARTTLS") {
            return Err(ProxyError::backend("backend did not advertise STARTTLS"));
        }
        outbound::write_all(&mut backend, b"STARTTLS\r\n").await?;
        read_smtp_reply(&mut backend, &mut residual, 220).await?;
        backend = outbound::tls_connect(backend, &tls_cfg, dest).await?;
        ehlo_reply = send_ehlo_expect(&mut backend, &mut residual, ehlo).await?;
    }

    assert_egress_encrypted(dest, ep, backend.is_tls())?;

    if forwarding == Forwarding::Xclient {
        let attrs = advertised_xclient_attrs(&ehlo_reply);
        if !attrs.is_empty() {
            let cmd = format!(
                "XCLIENT {}\r\n",
                forward::xclient_params_advertised(fwd, &attrs)
            );
            outbound::write_all(&mut backend, cmd.as_bytes()).await?;
            read_smtp_reply_any_2xx(&mut backend, &mut residual).await?;
            send_ehlo_expect(&mut backend, &mut residual, ehlo).await?;
        }
    }

    Ok((backend, residual))
}

fn advertised_xclient_attrs(ehlo_reply: &[u8]) -> Vec<String> {
    for line in ehlo_reply.split(|&b| b == b'\n') {
        let text = String::from_utf8_lossy(line);
        let rest = text.trim().get(4..).unwrap_or("");
        let mut tokens = rest.split_whitespace();
        if tokens
            .next()
            .is_some_and(|t| t.eq_ignore_ascii_case("XCLIENT"))
        {
            return tokens.map(|t| t.to_string()).collect();
        }
    }
    Vec::new()
}

async fn send_ehlo_expect(
    backend: &mut BoxedStream,
    residual: &mut Vec<u8>,
    ehlo_host: &str,
) -> Result<Vec<u8>> {
    outbound::write_all(backend, format!("EHLO {ehlo_host}\r\n").as_bytes()).await?;
    let mut reply = Vec::new();
    read_smtp_reply_with(backend, residual, Some(&mut reply), |code| {
        if code == 250 {
            Ok(())
        } else {
            Err(ProxyError::backend(format!(
                "backend SMTP replied {code}, expected 250"
            )))
        }
    })
    .await?;
    Ok(reply)
}

async fn read_smtp_reply(
    stream: &mut BoxedStream,
    residual: &mut Vec<u8>,
    expected: u16,
) -> Result<()> {
    read_smtp_reply_with(stream, residual, None, |code| {
        if code == expected {
            Ok(())
        } else {
            Err(ProxyError::backend(format!(
                "backend SMTP replied {code}, expected {expected}"
            )))
        }
    })
    .await
}

async fn read_smtp_reply_any_2xx(stream: &mut BoxedStream, residual: &mut Vec<u8>) -> Result<()> {
    read_smtp_reply_with(stream, residual, None, |code| {
        if (200..300).contains(&code) {
            Ok(())
        } else {
            Err(ProxyError::backend("backend rejected XCLIENT"))
        }
    })
    .await
}

async fn read_smtp_reply_with<F>(
    stream: &mut BoxedStream,
    residual: &mut Vec<u8>,
    mut capture: Option<&mut Vec<u8>>,
    mut check: F,
) -> Result<()>
where
    F: FnMut(u16) -> Result<()>,
{
    for _ in 0..256 {
        let line = outbound::read_line(stream, residual, MAX_PREAUTH).await?;
        if line.len() < 3 {
            return Err(ProxyError::backend("malformed SMTP reply"));
        }
        let code: u16 = std::str::from_utf8(&line[..3])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ProxyError::backend("malformed SMTP reply code"))?;
        check(code)?;
        if let Some(reply) = capture.as_deref_mut() {
            reply.extend_from_slice(&line);
            reply.push(b'\n');
        }
        if line.get(3) != Some(&b'-') {
            return Ok(());
        }
    }
    Err(ProxyError::backend("SMTP reply had too many lines"))
}

pub async fn handle_passthrough(
    ctx: &Ctx,
    listener: &ListenerConfig,
    stream: BoxedStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let dest_id = ctx
        .config
        .routing
        .smtp_passthrough_destination
        .clone()
        .ok_or_else(|| ProxyError::config("smtp_passthrough_destination not configured"))?;
    let proto = if listener.protocol == Protocol::Lmtp {
        Protocol::Lmtp
    } else {
        Protocol::Smtp
    };
    let (dest, ep, tls_cfg) = ctx.endpoint(&dest_id, proto)?;
    let fwd = dest.forwarding_for(proto);
    forward::guard_loop(&ctx.self_binds, dest, ep, fwd, ctx.config.server.proxy_ttl)?;
    let backend = common::establish(ctx, &dest_id, || {
        outbound::dial(dest, ep, fwd, &tls_cfg, peer, local)
    })
    .await?;
    outbound::bridge(
        stream,
        backend,
        &[],
        &[],
        ctx.config.server.bridge_idle,
        None,
    )
    .await?;
    Ok(())
}
