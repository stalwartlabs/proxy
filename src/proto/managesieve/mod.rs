/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod backend;

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::Result;
use crate::net::stream::ClientStream;
use crate::proto::backend::Dialect;
use crate::proto::imap::receiver::{
    Command, Error as RecvError, Framing, MAX_REQUEST, Receiver, Request,
};
use crate::proto::sasl_exchange::SaslExchange;
use crate::proto::session::{ClientConn, ExchangeEnd, Flow, Input, Preauth, Resume, Verdict};
use crate::runtime::{ListenerId, Runtime};

const MAX_PREAUTH: usize = MAX_REQUEST as usize;

pub async fn handle(
    rt: Arc<Runtime>,
    id: ListenerId,
    stream: ClientStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let mut conn = ClientConn::new(&rt, id, stream, peer, local, MAX_PREAUTH)?;
    conn.out
        .extend_from_slice(rt.capabilities.managesieve.capability.get(conn.tls_state()));
    conn.flush().await?;

    loop {
        let (next, outcome) = conn.managesieve_preauth().await?;
        conn = match next.conclude(outcome, Dialect::ManageSieve).await? {
            Resume::Preauth(next) => *next,
            Resume::Bridge(session) => {
                drop(rt);
                return session.run().await;
            }
            Resume::Close => return Ok(()),
        };
    }
}

impl<'a> ClientConn<'a> {
    async fn managesieve_preauth(mut self) -> Result<(Self, Preauth)> {
        let rt = self.rt;
        let wire = &rt.capabilities.managesieve;
        let mut receiver = Receiver::new(Framing::Untagged, MAX_REQUEST);
        loop {
            let request = match receiver.next_request(&mut self.buf) {
                Ok(request) => request,
                Err(RecvError::NeedsLiteral { .. }) => continue,
                Err(RecvError::NeedsMoreData) => match self.fill().await? {
                    Input::Data => continue,
                    Input::Eof => return Ok((self, Preauth::Closed)),
                    Input::Expired => return Ok((self, Preauth::Expired)),
                },
                Err(RecvError::LiteralTooBig { .. }) => {
                    self.farewell(b"BYE \"Literal exceeds the maximum request size.\"\r\n")
                        .await;
                    return Ok((self, Preauth::Closed));
                }
                Err(RecvError::Parse { message }) => {
                    self.out.extend_from_slice(b"NO \"");
                    self.out.extend(message.bytes().map(|b| match b {
                        b'"' | b'\\' | b'\r' | b'\n' => b' ',
                        b => b,
                    }));
                    self.out.extend_from_slice(b"\"\r\n");
                    self.flush().await?;
                    if self.failures.bump() == Verdict::Close {
                        return Ok((self, Preauth::Closed));
                    }
                    continue;
                }
            };

            let flow = match request.command {
                Command::StartTls => {
                    let acceptor = self.answer_starttls(Dialect::ManageSieve, None);
                    self.flush().await?;
                    let Some(acceptor) = acceptor else {
                        continue;
                    };
                    self.stream = self.stream.upgrade(acceptor, &mut self.buf).await?;
                    receiver = Receiver::new(Framing::Untagged, MAX_REQUEST);
                    let state = self.tls_state();
                    self.out.extend_from_slice(wire.capability.get(state));
                    Flow::Next
                }
                Command::Capability => {
                    let state = self.tls_state();
                    self.out.extend_from_slice(wire.capability.get(state));
                    Flow::Next
                }
                Command::Noop => {
                    match request.args().next().filter(|t| !t.is_empty()) {
                        Some(tag) => {
                            let _ = write!(self.out, "OK (TAG {{{}}}\r\n", tag.len());
                            self.out.extend_from_slice(tag);
                            self.out.extend_from_slice(b") \"Done\"\r\n");
                        }
                        None => self.out.extend_from_slice(b"OK \"NOOP completed.\"\r\n"),
                    }
                    Flow::Next
                }
                Command::Logout => {
                    self.out.extend_from_slice(b"OK \"Logout completed.\"\r\n");
                    Flow::Done(Preauth::Closed)
                }
                Command::Authenticate => self.managesieve_authenticate(&request).await?,
                _ => {
                    self.out
                        .extend_from_slice(b"NO \"Command not allowed in this state.\"\r\n");
                    Flow::Next
                }
            };
            self.flush().await?;
            if let Flow::Done(outcome) = flow {
                return Ok((self, outcome));
            }
        }
    }

    async fn managesieve_authenticate(&mut self, request: &Request) -> Result<Flow> {
        let mut args = request.args();
        let Some(mech) = args.next() else {
            self.out.extend_from_slice(b"NO \"Missing mechanism\"\r\n");
            return Ok(Flow::Next);
        };
        let rt = self.rt;
        let offered = *rt.capabilities.managesieve.sasl.get(self.tls_state());
        let (exchange, step) = SaslExchange::start(offered, mech, args.next(), &rt.key_rules);
        Ok(
            match self.exchange(Dialect::ManageSieve, exchange, step).await? {
                ExchangeEnd::Step(step) => self.finish(Dialect::ManageSieve, step, None),
                ExchangeEnd::Ended(end) => Flow::Done(end),
            },
        )
    }
}
