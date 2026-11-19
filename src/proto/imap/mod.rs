/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod backend;
pub mod receiver;

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::Result;
use crate::net::linebuf::LineBuf;
use crate::net::stream::ClientStream;
use crate::proto::backend::Dialect;
use crate::proto::imap::receiver::{
    Command, Error as RecvError, Framing, MAX_REQUEST, Receiver, Request,
};
use crate::proto::sasl_exchange::{SaslExchange, Step};
use crate::proto::session::{ClientConn, ExchangeEnd, Flow, Input, Preauth, Resume, Tag, Verdict};
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
        .extend_from_slice(rt.capabilities.imap.greeting.get(conn.tls_state()));
    conn.flush().await?;

    loop {
        let (next, outcome) = conn.imap_preauth().await?;
        conn = match next.conclude(outcome, Dialect::Imap).await? {
            Resume::Preauth(next) => *next,
            Resume::Bridge(session) => {
                drop(rt);
                return session.run().await;
            }
            Resume::Close => return Ok(()),
        };
    }
}

impl Receiver {
    pub fn next_request(&mut self, buf: &mut LineBuf) -> std::result::Result<Request, RecvError> {
        let data = buf.data();
        let mut input = data;
        let parsed = self.parse(&mut input);
        let consumed = data.len() - input.len();
        buf.consume(consumed);
        parsed
    }
}

impl<'a> ClientConn<'a> {
    async fn imap_preauth(mut self) -> Result<(Self, Preauth)> {
        let mut receiver = Receiver::new(Framing::Tagged, MAX_REQUEST);
        loop {
            let request = match receiver.next_request(&mut self.buf) {
                Ok(request) => request,
                Err(RecvError::NeedsMoreData) => match self.fill().await? {
                    Input::Data => continue,
                    Input::Eof => return Ok((self, Preauth::Closed)),
                    Input::Expired => return Ok((self, Preauth::Expired)),
                },
                Err(RecvError::NeedsLiteral { size }) => {
                    let _ = write!(self.out, "+ Ready for {size} bytes.\r\n");
                    self.flush().await?;
                    continue;
                }
                Err(RecvError::LiteralTooBig { non_sync: true }) => {
                    self.farewell(b"* BYE [TOOBIG] Literal exceeds the maximum request size.\r\n")
                        .await;
                    return Ok((self, Preauth::Closed));
                }
                Err(RecvError::LiteralTooBig { non_sync: false }) => {
                    self.tagged(
                        receiver.tag(),
                        " BAD [TOOBIG] Literal exceeds the maximum request size.\r\n",
                    );
                    self.flush().await?;
                    if self.failures.bump() == Verdict::Close {
                        return Ok((self, Preauth::Closed));
                    }
                    continue;
                }
                Err(RecvError::Parse { message }) => {
                    self.out.extend_from_slice(b"* BAD ");
                    self.out.extend_from_slice(message.as_bytes());
                    self.out.extend_from_slice(b"\r\n");
                    self.flush().await?;
                    if self.failures.bump() == Verdict::Close {
                        return Ok((self, Preauth::Closed));
                    }
                    continue;
                }
            };

            let tag = request.tag();
            let flow = match request.command {
                Command::StartTls => {
                    let acceptor = self.answer_starttls(Dialect::Imap, Some(tag));
                    self.flush().await?;
                    if let Some(acceptor) = acceptor {
                        self.stream = self.stream.upgrade(acceptor, &mut self.buf).await?;
                        receiver = Receiver::new(Framing::Tagged, MAX_REQUEST);
                    }
                    continue;
                }
                Command::Capability => {
                    let state = self.tls_state();
                    self.out
                        .extend_from_slice(self.rt.capabilities.imap.capability.get(state));
                    self.tagged(tag, " OK CAPABILITY completed.\r\n");
                    Flow::Next
                }
                Command::Noop => {
                    self.tagged(tag, " OK NOOP completed.\r\n");
                    Flow::Next
                }
                Command::Id => {
                    self.out.extend_from_slice(b"* ID NIL\r\n");
                    self.tagged(tag, " OK ID completed.\r\n");
                    Flow::Next
                }
                Command::Logout => {
                    self.out.extend_from_slice(b"* BYE Logging out\r\n");
                    self.tagged(tag, " OK LOGOUT completed.\r\n");
                    Flow::Done(Preauth::Closed)
                }
                Command::Authenticate => self.imap_authenticate(tag, &request).await?,
                Command::Login => self.imap_login(tag, &request),
                Command::Enable | Command::Unauthenticate | Command::Other => {
                    self.tagged(tag, " BAD Command not allowed in this state.\r\n");
                    Flow::Next
                }
            };
            self.flush().await?;
            if let Flow::Done(outcome) = flow {
                return Ok((self, outcome));
            }
        }
    }

    fn tagged(&mut self, tag: &str, rest: &str) {
        self.out.reserve(tag.len() + rest.len());
        self.out.extend_from_slice(tag.as_bytes());
        self.out.extend_from_slice(rest.as_bytes());
    }

    fn imap_login(&mut self, tag: &str, request: &Request) -> Flow {
        let state = self.tls_state();
        if !self
            .rt
            .capabilities
            .imap
            .sasl
            .get(state)
            .cleartext_allowed()
        {
            self.tagged(
                tag,
                " NO [PRIVACYREQUIRED] Cleartext login requires TLS.\r\n",
            );
            return Flow::Next;
        }
        let mut args = request.args();
        let step = match (args.next(), args.next()) {
            (Some(user), Some(pass)) => Step::cleartext_login(user, pass, &self.rt.key_rules),
            _ => {
                self.tagged(tag, " NO LOGIN requires a username and password.\r\n");
                return self.bump();
            }
        };
        self.imap_finish(tag, step)
    }

    async fn imap_authenticate(&mut self, tag: &str, request: &Request) -> Result<Flow> {
        let mut args = request.args();
        let Some(mech) = args.next() else {
            self.tagged(tag, " BAD Missing mechanism.\r\n");
            return Ok(Flow::Next);
        };
        let rt = self.rt;
        let offered = *rt.capabilities.imap.sasl.get(self.tls_state());
        let (exchange, step) = SaslExchange::start(offered, mech, args.next(), &rt.key_rules);
        Ok(match self.exchange(Dialect::Imap, exchange, step).await? {
            ExchangeEnd::Step(step) => self.imap_finish(tag, step),
            ExchangeEnd::Ended(end) => Flow::Done(end),
        })
    }

    fn imap_finish(&mut self, tag: &str, step: Step) -> Flow {
        let Some(tag) = Tag::new(tag) else {
            self.out.extend_from_slice(b"* BAD Tag too long.\r\n");
            return Flow::Next;
        };
        self.finish(Dialect::Imap, step, Some(tag))
    }
}
