/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::SocketAddr;

use encodify::base64::STANDARD as BASE64;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use crate::config::{Forwarding, ImapCapabilities, ListenerConfig, Protocol, TlsMode};
use crate::error::{ProxyError, Result};
use crate::imap_receiver::{Command, Error as RecvError, Mechanism, Receiver, Request, Token};
use crate::net::BoxedStream;
use crate::outbound;
use crate::proto::common::{
    self, Ctx, assert_egress_encrypted, mechanism_name, plain_auth_allowed, read_crlf_line, write,
};
use crate::proto::forward;
use crate::sasl::SASL_RESPONSE;
use crate::token::identifier_from_credential;

const MAX_PREAUTH: usize = 64 * 1024;

enum Decision {
    Authenticate {
        stream: BoxedStream,
        mech: Mechanism,
        tag: String,
        raw_challenge: Vec<u8>,
        identifier: Option<String>,
        residual: Vec<u8>,
    },
    Closed,
}

pub async fn handle(
    ctx: &Ctx,
    listener: &ListenerConfig,
    mut stream: BoxedStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let caps = &ctx.config.capabilities.imap;
    let starttls_listener = listener.tls == TlsMode::Starttls;

    let is_tls = stream.is_tls();
    let greeting = format!(
        "* OK [CAPABILITY {}] {}\r\n",
        ctx.greetings.imap.get(is_tls, starttls_listener && !is_tls),
        caps.banner
    );
    write(&mut stream, greeting.as_bytes()).await?;

    let mut seed = Vec::new();
    let mut auth_failures = 0u32;

    loop {
        let decision = match timeout(
            listener.preauth_timeout,
            preauth(ctx, listener, caps, stream, seed, &mut auth_failures),
        )
        .await
        {
            Ok(Ok(d)) => d,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Ok(()),
        };

        let Decision::Authenticate {
            stream: client,
            mech,
            tag,
            raw_challenge,
            identifier,
            residual,
        } = decision
        else {
            return Ok(());
        };

        let identifier = ctx.routing_identifier(identifier);
        let dest_id = ctx.resolve(identifier.as_deref()).await;
        tracing::debug!(destination = %dest_id, "imap routing decision");

        let started = std::time::Instant::now();
        common::hold_login(ctx, identifier.as_deref()).await;

        let client_tls = client.is_tls();
        let fwd =
            forward::ForwardInfo::new(peer, local, client_tls, None, ctx.config.server.proxy_ttl);

        let mech_name = mechanism_name(&mech);
        let mut response = String::with_capacity(BASE64.encoded_len(raw_challenge.len()) + 2);
        BASE64.encode_append(&raw_challenge, &mut response);
        response.push_str("\r\n");
        let auth = common::AuthFrame::inline(
            format!("{tag} AUTHENTICATE {mech_name} {response}").into_bytes(),
        )
        .with_deferred(
            format!("{tag} AUTHENTICATE {mech_name}\r\n").into_bytes(),
            response.into_bytes(),
        );
        let unavailable = format!("{tag} NO [UNAVAILABLE] backend unavailable\r\n");

        let resume = common::bridge_authenticated(
            ctx,
            &dest_id,
            client,
            peer,
            identifier.as_deref(),
            residual,
            started,
            "imap",
            common::AuthWire::Imap { tag },
            &auth,
            unavailable.as_bytes(),
            MAX_PREAUTH,
            || open_backend(ctx, &dest_id, &fwd),
        )
        .await?;

        let Some(common::Resume {
            stream: client,
            buf,
        }) = resume
        else {
            return Ok(());
        };
        if common::bump(&mut auth_failures, listener.max_auth_attempts) {
            return Ok(());
        }
        stream = client;
        seed = buf;
    }
}

async fn preauth(
    ctx: &Ctx,
    listener: &ListenerConfig,
    caps: &ImapCapabilities,
    mut stream: BoxedStream,
    seed: Vec<u8>,
    auth_failures: &mut u32,
) -> Result<Decision> {
    let starttls_listener = listener.tls == TlsMode::Starttls;
    let mut auth = Auth {
        ctx,
        caps,
        is_tls: stream.is_tls(),
        max_attempts: listener.max_auth_attempts,
        auth_failures,
    };

    let mut receiver = Receiver::<Command>::new();
    receiver.max_request_size = MAX_PREAUTH;
    let mut read = [0u8; 8192];
    let mut pending = seed;

    loop {
        let chunk: &[u8] = if pending.is_empty() {
            let n = stream
                .read(&mut read)
                .await
                .map_err(|e| ProxyError::Protocol(format!("reading client: {e}").into()))?;
            if n == 0 {
                return Ok(Decision::Closed);
            }
            &read[..n]
        } else {
            &pending
        };
        let mut it = chunk.iter();
        let mut carry: Option<Vec<u8>> = None;

        loop {
            match receiver.parse(&mut it) {
                Ok(req) => {
                    let Request {
                        tag,
                        command,
                        tokens,
                    } = req;
                    match command {
                        Command::Capability => {
                            let resp = format!(
                                "* CAPABILITY {}\r\n{tag} OK CAPABILITY completed.\r\n",
                                ctx.greetings
                                    .imap
                                    .get(auth.is_tls, starttls_listener && !auth.is_tls)
                            );
                            write(&mut stream, resp.as_bytes()).await?;
                        }
                        Command::Noop => {
                            write(
                                &mut stream,
                                format!("{tag} OK NOOP completed.\r\n").as_bytes(),
                            )
                            .await?;
                        }
                        Command::Id => {
                            write(
                                &mut stream,
                                format!("* ID NIL\r\n{tag} OK ID completed.\r\n").as_bytes(),
                            )
                            .await?;
                        }
                        Command::Logout => {
                            write(
                                &mut stream,
                                format!("* BYE Logging out\r\n{tag} OK LOGOUT completed.\r\n")
                                    .as_bytes(),
                            )
                            .await?;
                            return Ok(Decision::Closed);
                        }
                        Command::StartTls => {
                            if !starttls_listener || auth.is_tls {
                                write(
                                    &mut stream,
                                    format!("{tag} BAD STARTTLS not available.\r\n").as_bytes(),
                                )
                                .await?;
                                continue;
                            }
                            let Some(acceptor) = ctx.tls_acceptor.as_ref() else {
                                write(
                                    &mut stream,
                                    format!("{tag} NO STARTTLS not configured.\r\n").as_bytes(),
                                )
                                .await?;
                                continue;
                            };
                            write(
                                &mut stream,
                                format!("{tag} OK Begin TLS negotiation now.\r\n").as_bytes(),
                            )
                            .await?;
                            stream = common::upgrade_tls_inbound(stream, acceptor).await?;
                            auth.is_tls = true;
                            receiver = Receiver::<Command>::new();
                            receiver.max_request_size = MAX_PREAUTH;
                            break;
                        }
                        Command::Authenticate => {
                            match auth
                                .authenticate(&mut stream, &tokens, &tag, &mut it)
                                .await?
                            {
                                Step::Finalize {
                                    mech,
                                    raw_challenge,
                                    identifier,
                                    residual,
                                } => {
                                    return Ok(Decision::Authenticate {
                                        stream,
                                        mech,
                                        tag,
                                        raw_challenge,
                                        identifier,
                                        residual,
                                    });
                                }
                                Step::Resume { residual } => {
                                    carry = Some(residual);
                                    break;
                                }
                                Step::Continue => {}
                                Step::Close => return Ok(Decision::Closed),
                            }
                        }
                        Command::Login => {
                            match auth.login(&mut stream, &tokens, &tag, &mut it).await? {
                                Step::Finalize {
                                    mech,
                                    raw_challenge,
                                    identifier,
                                    residual,
                                } => {
                                    return Ok(Decision::Authenticate {
                                        stream,
                                        mech,
                                        tag,
                                        raw_challenge,
                                        identifier,
                                        residual,
                                    });
                                }
                                Step::Resume { residual } => {
                                    carry = Some(residual);
                                    break;
                                }
                                Step::Continue => {}
                                Step::Close => return Ok(Decision::Closed),
                            }
                        }
                        Command::Enable | Command::Unauthenticate | Command::Other => {
                            write(
                                &mut stream,
                                format!("{tag} BAD Command not allowed in this state.\r\n")
                                    .as_bytes(),
                            )
                            .await?;
                        }
                    }
                }
                Err(RecvError::NeedsMoreData) => break,
                Err(RecvError::NeedsLiteral { size }) => {
                    write(
                        &mut stream,
                        format!("+ Ready for {size} bytes.\r\n").as_bytes(),
                    )
                    .await?;
                    break;
                }
                Err(RecvError::Parse { message }) => {
                    write(&mut stream, format!("* BAD {message}\r\n").as_bytes()).await?;
                    if common::bump(auth.auth_failures, auth.max_attempts) {
                        return Ok(Decision::Closed);
                    }
                }
            }
        }
        drop(it);
        match carry {
            Some(rest) => pending = rest,
            None => pending.clear(),
        }
    }
}

struct Auth<'a> {
    ctx: &'a Ctx,
    caps: &'a ImapCapabilities,
    is_tls: bool,
    max_attempts: u32,
    auth_failures: &'a mut u32,
}

enum Step {
    Continue,
    Resume {
        residual: Vec<u8>,
    },
    Close,
    Finalize {
        mech: Mechanism,
        raw_challenge: Vec<u8>,
        identifier: Option<String>,
        residual: Vec<u8>,
    },
}

impl Auth<'_> {
    async fn authenticate(
        &mut self,
        stream: &mut BoxedStream,
        tokens: &[Token],
        tag: &str,
        it: &mut std::slice::Iter<'_, u8>,
    ) -> Result<Step> {
        let Some(mech_tok) = tokens.first() else {
            write(
                &mut *stream,
                format!("{tag} BAD Missing mechanism.\r\n").as_bytes(),
            )
            .await?;
            return Ok(Step::Continue);
        };
        let mech = Mechanism::parse(mech_tok.as_bytes());

        match mech {
            Mechanism::Plain | Mechanism::OAuthBearer | Mechanism::XOauth2 => {}
            Mechanism::Login if common::sasl_offered(&self.caps.sasl, "LOGIN") => {}
            _ => {
                return self
                    .reject(stream, tag, "Unsupported authentication mechanism.", None)
                    .await;
            }
        }

        if matches!(mech, Mechanism::Plain | Mechanism::Login)
            && !plain_auth_allowed(self.caps.allow_plain_auth_without_tls, self.is_tls)
        {
            write(
                &mut *stream,
                format!("{tag} NO [PRIVACYREQUIRED] Cleartext authentication requires TLS.\r\n")
                    .as_bytes(),
            )
            .await?;
            return Ok(Step::Continue);
        }

        if matches!(mech, Mechanism::Login) {
            return self.authenticate_login(stream, tokens, tag, it).await;
        }

        let (raw_b64, residual): (Vec<u8>, Vec<u8>) = if let Some(ir) = tokens.get(1) {
            (ir.as_bytes().to_vec(), common::take_rest(it))
        } else {
            write(&mut *stream, b"+ \r\n").await?;
            let seed = common::take_rest(it);
            read_crlf_line(stream, seed, MAX_PREAUTH).await?
        };

        let Ok(raw) = SASL_RESPONSE.decode(&raw_b64) else {
            return self
                .reject(
                    stream,
                    tag,
                    "Invalid base64 in SASL response.",
                    Some(residual),
                )
                .await;
        };

        self.finish(stream, mech, tag, raw, residual).await
    }

    async fn authenticate_login(
        &mut self,
        stream: &mut BoxedStream,
        tokens: &[Token],
        tag: &str,
        it: &mut std::slice::Iter<'_, u8>,
    ) -> Result<Step> {
        let (user_b64, residual): (Vec<u8>, Vec<u8>) = if let Some(ir) = tokens.get(1) {
            (ir.as_bytes().to_vec(), common::take_rest(it))
        } else {
            write(
                &mut *stream,
                format!("+ {}\r\n", common::LOGIN_USERNAME_CHALLENGE).as_bytes(),
            )
            .await?;
            let seed = common::take_rest(it);
            read_crlf_line(stream, seed, MAX_PREAUTH).await?
        };
        if common::sasl_cancelled(&user_b64) {
            return self
                .reject(stream, tag, "Authentication cancelled.", Some(residual))
                .await;
        }

        write(
            &mut *stream,
            format!("+ {}\r\n", common::LOGIN_PASSWORD_CHALLENGE).as_bytes(),
        )
        .await?;
        let (pass_b64, residual) = read_crlf_line(stream, residual, MAX_PREAUTH).await?;
        if common::sasl_cancelled(&pass_b64) {
            return self
                .reject(stream, tag, "Authentication cancelled.", Some(residual))
                .await;
        }

        let Some(raw) = common::login_challenge(&user_b64, &pass_b64) else {
            return self
                .reject(
                    stream,
                    tag,
                    "Invalid base64 in SASL response.",
                    Some(residual),
                )
                .await;
        };

        self.finish(stream, Mechanism::Plain, tag, raw, residual)
            .await
    }

    async fn login(
        &mut self,
        stream: &mut BoxedStream,
        tokens: &[Token],
        tag: &str,
        it: &mut std::slice::Iter<'_, u8>,
    ) -> Result<Step> {
        if !plain_auth_allowed(self.caps.allow_plain_auth_without_tls, self.is_tls) {
            write(
                &mut *stream,
                format!("{tag} NO [PRIVACYREQUIRED] Cleartext login requires TLS.\r\n").as_bytes(),
            )
            .await?;
            return Ok(Step::Continue);
        }
        let (Some(user), Some(pass)) = (tokens.first(), tokens.get(1)) else {
            return self
                .reject(stream, tag, "LOGIN requires a username and password.", None)
                .await;
        };
        let (user, pass) = (user.as_bytes(), pass.as_bytes());
        let mut raw = Vec::with_capacity(user.len() + pass.len() + 2);
        raw.push(0);
        raw.extend_from_slice(user);
        raw.push(0);
        raw.extend_from_slice(pass);
        let residual = common::take_rest(it);

        self.finish(stream, Mechanism::Plain, tag, raw, residual)
            .await
    }

    async fn finish(
        &mut self,
        stream: &mut BoxedStream,
        mech: Mechanism,
        tag: &str,
        raw: Vec<u8>,
        residual: Vec<u8>,
    ) -> Result<Step> {
        let Some(cred) = common::credential_from_sasl(&mech, &raw) else {
            return self
                .reject(stream, tag, "Malformed credentials.", Some(residual))
                .await;
        };
        let identifier =
            identifier_from_credential(&cred, &self.ctx.config.oauth.jwt_username_claim);

        Ok(Step::Finalize {
            mech,
            raw_challenge: raw,
            identifier,
            residual,
        })
    }

    async fn reject(
        &mut self,
        stream: &mut BoxedStream,
        tag: &str,
        message: &str,
        residual: Option<Vec<u8>>,
    ) -> Result<Step> {
        write(&mut *stream, format!("{tag} NO {message}\r\n").as_bytes()).await?;
        if common::bump(self.auth_failures, self.max_attempts) {
            return Ok(Step::Close);
        }
        Ok(match residual {
            Some(residual) => Step::Resume { residual },
            None => Step::Continue,
        })
    }
}

async fn open_backend(
    ctx: &Ctx,
    dest_id: &str,
    fwd: &forward::ForwardInfo,
) -> Result<common::BackendLeg> {
    let common::DialedEndpoint {
        dest,
        ep,
        tls_cfg,
        forwarding,
        mut backend,
    } = ctx
        .dial_endpoint(dest_id, Protocol::Imap, fwd.peer, fwd.local)
        .await?;
    let mut residual = Vec::new();

    let banner = outbound::read_line(&mut backend, &mut residual, MAX_PREAUTH).await?;
    let mut sasl_ir = common::advertises_token(&banner, "SASL-IR");

    if ep.tls == TlsMode::Starttls {
        if banner.contains(&b'[') && !common::advertises_token(&banner, "STARTTLS") {
            return Err(ProxyError::backend("backend did not advertise STARTTLS"));
        }
        outbound::write_all(&mut backend, b"P1 STARTTLS\r\n").await?;
        let resp = outbound::read_line(&mut backend, &mut residual, MAX_PREAUTH).await?;
        if !tagged_ok(&resp, b"P1") {
            return Err(ProxyError::backend("backend refused STARTTLS"));
        }
        sasl_ir = common::advertises_token(&resp, "SASL-IR");
        backend = outbound::tls_connect(backend, &tls_cfg, dest).await?;
    }

    assert_egress_encrypted(dest, ep, backend.is_tls())?;

    if forwarding == Forwarding::Xclient {
        forward::send_imap_id(&mut backend, &mut residual, &banner, fwd, MAX_PREAUTH).await?;
    }

    Ok(common::BackendLeg::new(backend, residual).with_initial_response(sasl_ir))
}

fn tagged_ok(line: &[u8], tag: &[u8]) -> bool {
    let line = line.trim_ascii();
    line.len() > tag.len()
        && line[..tag.len()].eq_ignore_ascii_case(tag)
        && line[tag.len()..]
            .iter()
            .skip_while(|b| b.is_ascii_whitespace())
            .take(2)
            .copied()
            .eq(b"OK".iter().copied())
}

pub fn capability_string(caps: &ImapCapabilities, offer_starttls: bool, is_tls: bool) -> String {
    let plain_ok = plain_auth_allowed(caps.allow_plain_auth_without_tls, is_tls);
    let mut toks: Vec<String> = caps.advertise.clone();
    for m in common::advertised_sasl(&caps.sasl, plain_ok) {
        toks.push(format!("AUTH={m}"));
    }
    if !plain_ok {
        toks.push("LOGINDISABLED".to_string());
    }
    if offer_starttls {
        toks.push("STARTTLS".to_string());
    }
    toks.join(" ")
}
