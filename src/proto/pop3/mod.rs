/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod backend;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::Result;
use crate::net::stream::ClientStream;
use crate::proto::backend::Dialect;
use crate::proto::sasl_exchange::{Reject, SaslExchange, Step};
use crate::proto::session::{ClientConn, ExchangeEnd, Flow, Input, Preauth, Resume};
use crate::runtime::{ListenerId, Runtime};

const MAX_PREAUTH: usize = 64 * 1024;

#[derive(Clone, Copy)]
enum Command {
    Quit,
    Noop,
    Capa,
    Apop,
    Stls,
    User,
    Pass,
    Auth,
}

impl Command {
    fn parse(verb: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(
            verb,
            Command,
            "QUIT" => Command::Quit,
            "NOOP" => Command::Noop,
            "UTF8" => Command::Noop,
            "CAPA" => Command::Capa,
            "APOP" => Command::Apop,
            "STLS" => Command::Stls,
            "USER" => Command::User,
            "PASS" => Command::Pass,
            "AUTH" => Command::Auth,
        )
        .copied()
    }
}

pub async fn handle(
    rt: Arc<Runtime>,
    id: ListenerId,
    stream: ClientStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let mut conn = ClientConn::new(&rt, id, stream, peer, local, MAX_PREAUTH)?;
    conn.out.extend_from_slice(&rt.capabilities.pop3.banner);
    conn.flush().await?;

    loop {
        let (next, outcome) = conn.pop3_preauth().await?;
        conn = match next.conclude(outcome, Dialect::Pop3).await? {
            Resume::Preauth(next) => *next,
            Resume::Bridge(session) => {
                drop(rt);
                return session.run().await;
            }
            Resume::Close => return Ok(()),
        };
    }
}

fn split_word(line: &[u8]) -> (&[u8], &[u8]) {
    let mut parts = line.splitn(2, |b| *b == b' ');
    let word = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default().trim_ascii_start();
    (word, rest)
}

impl<'a> ClientConn<'a> {
    async fn pop3_preauth(mut self) -> Result<(Self, Preauth)> {
        let rt = self.rt;
        let wire = &rt.capabilities.pop3;
        let mut pending_user: Option<Box<[u8]>> = None;
        loop {
            let state = self.tls_state();
            let sasl = *wire.sasl.get(state);
            let Some(line) = self.buf.line() else {
                match self.fill().await? {
                    Input::Data => continue,
                    Input::Eof => return Ok((self, Preauth::Closed)),
                    Input::Expired => return Ok((self, Preauth::Expired)),
                }
            };
            let (verb, arg) = split_word(line);
            let flow = match Command::parse(verb) {
                Some(Command::Quit) => {
                    self.out.extend_from_slice(b"+OK Bye\r\n");
                    Flow::Done(Preauth::Closed)
                }
                Some(Command::Noop) => {
                    self.out.extend_from_slice(b"+OK\r\n");
                    Flow::Next
                }
                Some(Command::Capa) => {
                    self.out.extend_from_slice(wire.capa.get(state));
                    Flow::Next
                }
                Some(Command::Apop) => {
                    self.out.extend_from_slice(b"-ERR APOP not supported\r\n");
                    Flow::Next
                }
                Some(Command::Stls) => {
                    let acceptor = self.answer_starttls(Dialect::Pop3, None);
                    self.flush().await?;
                    if let Some(acceptor) = acceptor {
                        self.stream = self.stream.upgrade(acceptor, &mut self.buf).await?;
                        pending_user = None;
                    }
                    continue;
                }
                Some(Command::User) => {
                    if !sasl.cleartext_allowed() {
                        Dialect::Pop3.write_reject(&mut self.out, Reject::PrivacyRequired, None);
                    } else if arg.is_empty() {
                        self.out
                            .extend_from_slice(b"-ERR USER requires an argument\r\n");
                    } else {
                        pending_user = Some(arg.into());
                        self.out.extend_from_slice(b"+OK\r\n");
                    }
                    Flow::Next
                }
                Some(Command::Pass) => {
                    if !sasl.cleartext_allowed() {
                        Dialect::Pop3.write_reject(&mut self.out, Reject::PrivacyRequired, None);
                        Flow::Next
                    } else if let Some(user) = pending_user.take() {
                        let step = Step::cleartext_login(&user, arg, &rt.key_rules);
                        self.finish(Dialect::Pop3, step, None)
                    } else {
                        self.out
                            .extend_from_slice(b"-ERR USER required before PASS\r\n");
                        Flow::Next
                    }
                }
                Some(Command::Auth) if arg.is_empty() => {
                    self.out.extend_from_slice(wire.auth_list.get(state));
                    Flow::Next
                }
                Some(Command::Auth) => {
                    let (mech, initial) = split_word(arg);
                    let initial = Some(initial.trim_ascii()).filter(|ir| !ir.is_empty());
                    let (exchange, step) = SaslExchange::start(sasl, mech, initial, &rt.key_rules);
                    match self.exchange(Dialect::Pop3, exchange, step).await? {
                        ExchangeEnd::Step(step) => self.finish(Dialect::Pop3, step, None),
                        ExchangeEnd::Ended(end) => Flow::Done(end),
                    }
                }
                None => {
                    self.out.extend_from_slice(b"-ERR unknown command\r\n");
                    Flow::Next
                }
            };
            self.flush().await?;
            if let Flow::Done(outcome) = flow {
                return Ok((self, outcome));
            }
        }
    }
}
