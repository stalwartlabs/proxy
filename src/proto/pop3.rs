/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::SocketAddr;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::time::timeout;

use crate::config::{Forwarding, ListenerConfig, Pop3Capabilities, Protocol, TlsMode};
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

pub async fn handle(
    ctx: &Ctx,
    listener: &ListenerConfig,
    stream: BoxedStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let caps = &ctx.config.capabilities.pop3;

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
        "pop3",
        common::AuthWire::Pop3,
        auth_frame.as_bytes(),
        b"-ERR backend unavailable\r\n",
        MAX_PREAUTH,
        || open_backend(ctx, &dest_id, &fwd),
    )
    .await
}

async fn preauth(
    ctx: &Ctx,
    listener: &ListenerConfig,
    caps: &Pop3Capabilities,
    mut stream: BoxedStream,
) -> Result<Option<Handoff>> {
    let mut is_tls = stream.is_tls();
    let starttls_listener = listener.tls == TlsMode::Starttls;

    write(&mut stream, format!("+OK {}\r\n", caps.banner).as_bytes()).await?;

    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut pending_user: Option<Vec<u8>> = None;
    let mut auth_failures = 0u32;

    loop {
        let Some(nl) = buf.iter().position(|&b| b == b'\n') else {
            if buf.len() > MAX_PREAUTH {
                return Err(ProxyError::preauth("pop3 line too long"));
            }
            let n = common::fill(&mut stream, &mut buf, MAX_PREAUTH + 8192).await?;
            if n == 0 {
                return Ok(None);
            }
            continue;
        };

        let mut line = buf[..nl].to_vec();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let consumed = nl + 1;

        let plain_ok = plain_auth_allowed(caps.allow_plain_auth_without_tls, is_tls);
        let (verb, arg) = split_verb(&line);

        match verb.to_ascii_uppercase().as_slice() {
            b"QUIT" => {
                write(&mut stream, b"+OK Bye\r\n").await?;
                return Ok(None);
            }
            b"NOOP" | b"UTF8" => {
                write(&mut stream, b"+OK\r\n").await?;
                buf.drain(..consumed);
            }
            b"CAPA" => {
                write(
                    &mut stream,
                    ctx.greetings
                        .pop3
                        .get(is_tls, starttls_listener && !is_tls)
                        .as_bytes(),
                )
                .await?;
                buf.drain(..consumed);
            }
            b"APOP" => {
                write(&mut stream, b"-ERR APOP not supported\r\n").await?;
                buf.drain(..consumed);
            }
            b"STLS" => {
                if !starttls_listener || is_tls {
                    write(&mut stream, b"-ERR STLS not available\r\n").await?;
                    buf.drain(..consumed);
                    continue;
                }
                let Some(acceptor) = ctx.tls_acceptor.as_ref() else {
                    write(&mut stream, b"-ERR STLS not configured\r\n").await?;
                    buf.drain(..consumed);
                    continue;
                };
                write(&mut stream, b"+OK Begin TLS negotiation\r\n").await?;
                buf.clear();
                stream = common::upgrade_tls_inbound(stream, acceptor).await?;
                is_tls = true;
            }
            b"USER" => {
                if !plain_ok {
                    write(
                        &mut stream,
                        b"-ERR cleartext authentication requires TLS\r\n",
                    )
                    .await?;
                } else if arg.is_empty() {
                    write(&mut stream, b"-ERR USER requires an argument\r\n").await?;
                } else {
                    pending_user = Some(arg.to_vec());
                    write(&mut stream, b"+OK\r\n").await?;
                }
                buf.drain(..consumed);
            }
            b"PASS" => {
                if !plain_ok {
                    write(
                        &mut stream,
                        b"-ERR cleartext authentication requires TLS\r\n",
                    )
                    .await?;
                    buf.drain(..consumed);
                    continue;
                }
                let Some(user) = pending_user.take() else {
                    write(&mut stream, b"-ERR USER required before PASS\r\n").await?;
                    buf.drain(..consumed);
                    continue;
                };
                let mut raw = Vec::with_capacity(user.len() + arg.len() + 2);
                raw.push(0);
                raw.extend_from_slice(&user);
                raw.push(0);
                raw.extend_from_slice(arg);
                let identifier = Some(String::from_utf8_lossy(&user).into_owned());
                let residual = buf[nl + 1..].to_vec();
                return Ok(Some(Handoff {
                    stream,
                    mech: Mechanism::Plain,
                    raw_challenge: raw,
                    identifier,
                    residual,
                }));
            }
            b"AUTH" => {
                if arg.is_empty() {
                    write(&mut stream, auth_list(caps, plain_ok).as_bytes()).await?;
                    buf.drain(..consumed);
                    continue;
                }
                let (mech_bytes, ir) = split_verb(arg);
                let mech = Mechanism::parse(mech_bytes);
                match &mech {
                    Mechanism::Plain | Mechanism::OAuthBearer | Mechanism::XOauth2 => {}
                    _ => {
                        write(&mut stream, b"-ERR unsupported mechanism\r\n").await?;
                        buf.drain(..consumed);
                        if bump(&mut auth_failures, listener.max_auth_attempts) {
                            return Ok(None);
                        }
                        continue;
                    }
                }
                if matches!(mech, Mechanism::Plain) && !plain_ok {
                    write(
                        &mut stream,
                        b"-ERR cleartext authentication requires TLS\r\n",
                    )
                    .await?;
                    buf.drain(..consumed);
                    continue;
                }

                let raw_b64: Vec<u8> = if !ir.is_empty() {
                    let ir = ir.to_vec();
                    buf.drain(..consumed);
                    ir
                } else {
                    write(&mut stream, b"+ \r\n").await?;
                    buf.drain(..consumed);
                    let seed = std::mem::take(&mut buf);
                    let (line, rest) =
                        common::read_crlf_line(&mut stream, seed, MAX_PREAUTH).await?;
                    buf = rest;
                    line
                };

                let Some(raw) = decode_sasl_ir(&raw_b64) else {
                    write(&mut stream, b"-ERR invalid base64\r\n").await?;
                    if bump(&mut auth_failures, listener.max_auth_attempts) {
                        return Ok(None);
                    }
                    continue;
                };
                let Some(cred) = credential_from_sasl(&mech, &raw) else {
                    write(&mut stream, b"-ERR malformed credentials\r\n").await?;
                    if bump(&mut auth_failures, listener.max_auth_attempts) {
                        return Ok(None);
                    }
                    continue;
                };
                let identifier =
                    identifier_from_credential(&cred, &ctx.config.oauth.jwt_username_claim);
                let residual = std::mem::take(&mut buf);
                return Ok(Some(Handoff {
                    stream,
                    mech,
                    raw_challenge: raw,
                    identifier,
                    residual,
                }));
            }
            _ => {
                write(&mut stream, b"-ERR unknown command\r\n").await?;
                buf.drain(..consumed);
            }
        }
    }
}

fn bump(failures: &mut u32, max: u32) -> bool {
    *failures += 1;
    *failures >= max
}

fn split_verb(line: &[u8]) -> (&[u8], &[u8]) {
    match line.iter().position(|&b| b == b' ') {
        Some(pos) => (&line[..pos], trim_leading_space(&line[pos + 1..])),
        None => (line, &[]),
    }
}

fn trim_leading_space(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|&c| c != b' ').unwrap_or(b.len());
    &b[start..]
}

pub(crate) fn capa_response(caps: &Pop3Capabilities, offer_stls: bool, plain_ok: bool) -> String {
    let mut lines = String::from("+OK Capability list follows\r\n");
    if plain_ok {
        lines.push_str("USER\r\n");
    }
    lines.push_str(&sasl_line(caps, plain_ok));
    if offer_stls {
        lines.push_str("STLS\r\n");
    }
    lines.push_str("TOP\r\nRESP-CODES\r\nPIPELINING\r\nEXPIRE NEVER\r\nUIDL\r\nUTF8\r\n");
    lines.push_str("IMPLEMENTATION Stalwart Server\r\n");
    lines.push_str(".\r\n");
    lines
}

fn sasl_line(caps: &Pop3Capabilities, plain_ok: bool) -> String {
    let mechs = common::advertised_sasl(&caps.sasl, plain_ok);
    if mechs.is_empty() {
        String::new()
    } else {
        format!("SASL {}\r\n", mechs.join(" "))
    }
}

fn auth_list(caps: &Pop3Capabilities, plain_ok: bool) -> String {
    let mut out = String::from("+OK\r\n");
    for m in common::advertised_sasl(&caps.sasl, plain_ok) {
        out.push_str(m);
        out.push_str("\r\n");
    }
    out.push_str(".\r\n");
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
        .dial_endpoint(dest_id, Protocol::Pop3, fwd.peer, fwd.local)
        .await?;
    let mut residual = Vec::new();

    let greeting = outbound::read_line(&mut backend, &mut residual, MAX_PREAUTH).await?;
    if !greeting.starts_with(b"+OK") {
        return Err(ProxyError::backend("backend POP3 greeting was not +OK"));
    }
    let xclient_advertised = common::advertises_token(&greeting, "XCLIENT");

    if ep.tls == TlsMode::Starttls {
        if !backend_advertises_stls(&mut backend, &mut residual).await? {
            return Err(ProxyError::backend("backend did not advertise STLS"));
        }
        outbound::write_all(&mut backend, b"STLS\r\n").await?;
        let resp = outbound::read_line(&mut backend, &mut residual, MAX_PREAUTH).await?;
        if !resp.starts_with(b"+OK") {
            return Err(ProxyError::backend("backend refused STLS"));
        }
        backend = outbound::tls_connect(backend, &tls_cfg, dest).await?;
    }

    assert_egress_encrypted(dest, ep, backend.is_tls())?;

    if forwarding == Forwarding::Xclient {
        forward::send_pop3_xclient(
            &mut backend,
            &mut residual,
            xclient_advertised,
            fwd,
            MAX_PREAUTH,
        )
        .await?;
    }

    Ok((backend, residual))
}

async fn backend_advertises_stls(
    backend: &mut BoxedStream,
    residual: &mut Vec<u8>,
) -> Result<bool> {
    outbound::write_all(backend, b"CAPA\r\n").await?;
    let mut advertised = false;
    for _ in 0..256 {
        let line = outbound::read_line(backend, residual, MAX_PREAUTH).await?;
        if line.starts_with(b"-ERR") {
            return Ok(false);
        }
        if line == b"." {
            return Ok(advertised);
        }
        if line.eq_ignore_ascii_case(b"STLS") {
            advertised = true;
        }
    }
    Err(ProxyError::backend("backend CAPA had too many lines"))
}
