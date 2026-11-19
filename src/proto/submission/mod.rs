/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod backend;

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;

use smtp_proto::{
    AUTH_LOGIN, AUTH_OAUTHBEARER, AUTH_PLAIN, AUTH_XOAUTH2, Error as SmtpError, Request,
};

use crate::error::Result;
use crate::net::stream::ClientStream;
use crate::proto::backend::Dialect;
use crate::proto::sasl_exchange::{SaslExchange, Step};
use crate::proto::session::{ClientConn, ExchangeEnd, Flow, Input, Preauth, Resume};
use crate::runtime::{ListenerId, Runtime};
use crate::sasl::SaslMech;

const MAX_PREAUTH: usize = 64 * 1024;
const OK: &[u8] = b"250 2.0.0 OK\r\n";

enum Command {
    Ehlo(Box<str>),
    Helo(Box<str>),
    Lhlo,
    Noop,
    Quit,
    StartTls,
    Auth(SaslExchange, Step),
    Other,
    Invalid,
    Incomplete,
}

pub async fn handle(
    rt: Arc<Runtime>,
    id: ListenerId,
    stream: ClientStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let hostname: Cow<'_, str> = match rt.server.hostname.as_deref() {
        Some(hostname) => Cow::Borrowed(hostname),
        None => Cow::Owned(local.ip().to_string()),
    };
    let mut conn = ClientConn::new(&rt, id, stream, peer, local, MAX_PREAUTH)?;
    rt.capabilities
        .submission
        .write_banner(&mut conn.out, &hostname);
    conn.flush().await?;

    let mut helo: Option<Box<str>> = None;
    loop {
        let (next, outcome) = conn.submission_preauth(&hostname, &mut helo).await?;
        conn = match next.conclude(outcome, Dialect::Submission).await? {
            Resume::Preauth(next) => *next,
            Resume::Bridge(session) => {
                drop(rt);
                return session.run().await;
            }
            Resume::Close => return Ok(()),
        };
    }
}

impl SaslMech {
    fn from_smtp_flag(flag: u64) -> Option<Self> {
        match flag {
            AUTH_PLAIN => Some(SaslMech::Plain),
            AUTH_LOGIN => Some(SaslMech::Login),
            AUTH_OAUTHBEARER => Some(SaslMech::OAuthBearer),
            AUTH_XOAUTH2 => Some(SaslMech::XOAuth2),
            _ => None,
        }
    }
}

impl<'a> ClientConn<'a> {
    async fn submission_preauth(
        mut self,
        hostname: &str,
        helo: &mut Option<Box<str>>,
    ) -> Result<(Self, Preauth)> {
        let rt = self.rt;
        let wire = &rt.capabilities.submission;
        loop {
            let state = self.tls_state();
            let command = if self.buf.has_line() {
                let data = self.buf.data();
                let mut it = data.iter();
                let parsed = Request::parse(&mut it);
                let consumed = data.len() - it.as_slice().len();
                let command = match parsed {
                    Ok(Request::Ehlo { host }) => Command::Ehlo(host.as_ref().into()),
                    Ok(Request::Helo { host }) => Command::Helo(host.as_ref().into()),
                    Ok(Request::Lhlo { .. }) => Command::Lhlo,
                    Ok(Request::Noop { .. } | Request::Rset) => Command::Noop,
                    Ok(Request::Quit) => Command::Quit,
                    Ok(Request::StartTls) => Command::StartTls,
                    Ok(Request::Auth {
                        mechanism: flag,
                        initial_response,
                    }) => {
                        let initial = Some(initial_response.as_bytes()).filter(|ir| !ir.is_empty());
                        let (exchange, step) = SaslExchange::start_mech(
                            *wire.sasl.get(state),
                            SaslMech::from_smtp_flag(flag),
                            initial,
                            &rt.key_rules,
                        );
                        Command::Auth(exchange, step)
                    }
                    Ok(_) => Command::Other,
                    Err(SmtpError::NeedsMoreData { .. }) => Command::Incomplete,
                    Err(_) => Command::Invalid,
                };
                match command {
                    Command::Invalid => {
                        let _ = self.buf.line();
                    }
                    Command::Incomplete => {}
                    _ => self.buf.consume(consumed),
                }
                command
            } else {
                Command::Incomplete
            };

            let flow = match command {
                Command::Incomplete => match self.fill().await? {
                    Input::Data => continue,
                    Input::Eof => return Ok((self, Preauth::Closed)),
                    Input::Expired => return Ok((self, Preauth::Expired)),
                },
                Command::Ehlo(host) => {
                    wire.write_ehlo(&mut self.out, state, hostname, &host);
                    *helo = Some(host);
                    Flow::Next
                }
                Command::Helo(host) => {
                    self.out.reserve(hostname.len() + 6);
                    self.out.extend_from_slice(b"250 ");
                    self.out.extend_from_slice(hostname.as_bytes());
                    self.out.extend_from_slice(b"\r\n");
                    *helo = Some(host);
                    Flow::Next
                }
                Command::Lhlo => {
                    self.out
                        .extend_from_slice(b"502 5.5.1 LHLO is not supported on submission\r\n");
                    Flow::Next
                }
                Command::Noop => {
                    self.out.extend_from_slice(OK);
                    Flow::Next
                }
                Command::Quit => {
                    self.out.extend_from_slice(b"221 2.0.0 Bye\r\n");
                    Flow::Done(Preauth::Closed)
                }
                Command::StartTls => {
                    let acceptor = self.answer_starttls(Dialect::Submission, None);
                    self.flush().await?;
                    if let Some(acceptor) = acceptor {
                        self.stream = self.stream.upgrade(acceptor, &mut self.buf).await?;
                        *helo = None;
                    }
                    continue;
                }
                Command::Auth(exchange, step) => {
                    match self.exchange(Dialect::Submission, exchange, step).await? {
                        ExchangeEnd::Step(mut step) => {
                            if let Step::Done(login) = &mut step {
                                login.helo = helo.as_deref().map(Box::from);
                            }
                            self.finish(Dialect::Submission, step, None)
                        }
                        ExchangeEnd::Ended(end) => Flow::Done(end),
                    }
                }
                Command::Other => {
                    self.out
                        .extend_from_slice(b"503 5.5.1 Command not allowed here\r\n");
                    Flow::Next
                }
                Command::Invalid => {
                    self.out.extend_from_slice(b"500 5.5.2 Syntax error\r\n");
                    self.bump()
                }
            };
            self.flush().await?;
            if let Flow::Done(outcome) = flow {
                return Ok((self, outcome));
            }
        }
    }
}
