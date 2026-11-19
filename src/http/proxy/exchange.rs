/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::IoSlice;
use std::net::IpAddr;
use std::pin::pin;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, split};

use crate::error::{ErrorKind, ProxyError, Result, Side, Stage};
use crate::http::head::{BodyFraming, Head, MessageKind, Method};
use crate::http::serialize::ConnectionHeader;
use crate::net::stream::{BackendStream, ClientStream};
use crate::runtime::registry::ConnInfo;

use super::body::{Direction, Pipe, count, flush, send, send_parts};
use crate::http::reader::Reader;

const SWITCHING_PROTOCOLS: u16 = 101;

#[derive(Clone, Copy)]
pub(super) struct Idle {
    pub body: Duration,
    pub stream: Duration,
}

#[derive(Clone, Copy)]
pub(super) struct ExchangeOpts {
    pub forwarded_for: Option<IpAddr>,
    pub max_head: usize,
    pub idle: Idle,
    pub force_close: bool,
}

pub(super) enum ExchangeResult {
    KeepAlive,
    Hijack {
        to_backend: Vec<u8>,
        to_client: Vec<u8>,
    },
    Close,
}

pub(super) struct Exchange<'a> {
    pub client: &'a mut ClientStream,
    pub client_reader: &'a mut Reader,
    pub backend: &'a mut BackendStream,
    pub backend_reader: &'a mut Reader,
    pub out: &'a mut Vec<u8>,
    pub info: Option<&'a ConnInfo>,
    pub opts: ExchangeOpts,
    pub responded: bool,
}

impl<'a> Exchange<'a> {
    pub(super) async fn run(&mut self, head: &Head, body: Option<&[u8]>) -> Result<ExchangeResult> {
        let flags = head.flags();
        let client_close = self.opts.force_close || flags.close;
        let method = head.method();
        let idle = self.opts.idle.body;
        let connection = match flags.websocket {
            true => ConnectionHeader::Upgrade,
            false => ConnectionHeader::Omit,
        };
        self.out.clear();
        head.write_to(self.out, connection, self.opts.forwarded_for);
        let body = body.unwrap_or_default();
        let mut parts = [IoSlice::new(self.out.as_slice()), IoSlice::new(body)];
        send_parts(self.backend, &mut parts, Side::Backend, idle).await?;
        count(self.up(), self.out.len() + body.len());

        if flags.websocket {
            return self.upgrade(method, client_close).await;
        }

        let framing = head.framing();
        let pending = match framing {
            BodyFraming::Length(n) => n > body.len() as u64,
            BodyFraming::Chunked => true,
            BodyFraming::None | BodyFraming::UntilClose => false,
        };
        if !pending {
            flush(self.backend, Side::Backend, idle).await?;
            return self.relay_response(method, client_close).await;
        }
        match self.upload(framing, body.len()).await? {
            None => self.relay_response(method, client_close).await,
            Some(early) => self.finish(method, early, true).await,
        }
    }

    fn up(&self) -> Option<&'a AtomicU64> {
        self.info.map(|info| &info.bytes_up)
    }

    fn down(&self) -> Option<&'a AtomicU64> {
        self.info.map(|info| &info.bytes_down)
    }

    async fn upload(&mut self, framing: BodyFraming, already: usize) -> Result<Option<Head>> {
        let idle = self.opts.idle.body;
        let max_head = self.opts.max_head;
        let up = self.up();
        let down = self.down();
        let (mut client_rd, mut client_wr) = split(&mut *self.client);
        let (mut backend_rd, mut backend_wr) = split(&mut *self.backend);
        let client_reader = &mut *self.client_reader;
        let backend_reader = &mut *self.backend_reader;
        let out = &mut *self.out;

        let mut sending = pin!(async {
            Pipe {
                src: &mut client_rd,
                reader: client_reader,
                dst: &mut backend_wr,
                dir: Direction::ToBackend,
                idle,
                meter: up,
            }
            .body(framing, already)
            .await?;
            flush(&mut backend_wr, Side::Backend, idle).await
        });

        loop {
            tokio::select! {
                biased;
                sent = &mut sending => {
                    sent?;
                    return Ok(None);
                }
                resp = backend_reader.read_response_head(&mut backend_rd, max_head, None) => {
                    let resp = resp?;
                    if !resp.is_interim() {
                        return Ok(Some(resp));
                    }
                    resp.relay_interim(&mut client_wr, out, idle, down).await?;
                }
            }
        }
    }

    async fn upgrade(&mut self, method: Method, client_close: bool) -> Result<ExchangeResult> {
        let idle = self.opts.idle.body;
        flush(self.backend, Side::Backend, idle).await?;
        let resp = self
            .backend_reader
            .read_response_head(self.backend, self.opts.max_head, Some(idle))
            .await?;
        if resp.status() != SWITCHING_PROTOCOLS {
            return self.finish(method, resp, client_close).await;
        }
        self.out.clear();
        resp.write_to(self.out, ConnectionHeader::Upgrade, None);
        self.responded = true;
        send(self.client, self.out, Side::Client, idle).await?;
        flush(self.client, Side::Client, idle).await?;
        count(self.down(), self.out.len());
        Ok(ExchangeResult::Hijack {
            to_backend: self.client_reader.take_rest(),
            to_client: self.backend_reader.take_rest(),
        })
    }

    async fn relay_response(&mut self, method: Method, close: bool) -> Result<ExchangeResult> {
        let idle = self.opts.idle.body;
        loop {
            let resp = self
                .backend_reader
                .read_response_head(self.backend, self.opts.max_head, Some(idle))
                .await?;
            if !resp.is_interim() {
                return self.finish(method, resp, close).await;
            }
            resp.relay_interim(self.client, self.out, idle, self.down())
                .await?;
        }
    }

    async fn finish(
        &mut self,
        method: Method,
        resp: Head,
        force_close: bool,
    ) -> Result<ExchangeResult> {
        let flags = resp.flags();
        let framing = match method {
            Method::Head => BodyFraming::None,
            _ => resp.framing(),
        };
        let streaming = (flags.sse || matches!(framing, BodyFraming::UntilClose))
            && !matches!(framing, BodyFraming::None);
        let close = force_close || flags.close || streaming;
        let idle = self.opts.idle;
        let connection = match close {
            true => ConnectionHeader::Close,
            false => ConnectionHeader::Omit,
        };
        self.out.clear();
        resp.write_to(self.out, connection, None);
        self.responded = true;
        send(self.client, self.out, Side::Client, idle.body).await?;
        count(self.down(), self.out.len());

        let meter = self.down();
        let mut pipe = Pipe {
            src: &mut *self.backend,
            reader: &mut *self.backend_reader,
            dst: &mut *self.client,
            dir: Direction::ToClient,
            idle: idle.body,
            meter,
        };
        if streaming {
            flush(pipe.dst, Side::Client, idle.body).await?;
            pipe.idle = idle.stream;
            pipe.until_close().await?;
            return Ok(ExchangeResult::Close);
        }
        match framing {
            BodyFraming::Length(n) => pipe.length(n).await?,
            BodyFraming::Chunked => pipe.chunked().await?,
            BodyFraming::None | BodyFraming::UntilClose => {}
        }
        flush(self.client, Side::Client, idle.body).await?;
        Ok(match close {
            true => ExchangeResult::Close,
            false => ExchangeResult::KeepAlive,
        })
    }
}

impl Head {
    fn is_interim(&self) -> bool {
        matches!(self.status(), 100..=199) && self.status() != SWITCHING_PROTOCOLS
    }

    async fn relay_interim(
        &self,
        client: &mut (impl AsyncWrite + Unpin),
        out: &mut Vec<u8>,
        idle: Duration,
        meter: Option<&AtomicU64>,
    ) -> Result<()> {
        out.clear();
        self.write_to(out, ConnectionHeader::Omit, None);
        send(client, out, Side::Client, idle).await?;
        flush(client, Side::Client, idle).await?;
        count(meter, out.len());
        Ok(())
    }
}

impl Reader {
    async fn read_response_head(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
        max_head: usize,
        idle: Option<Duration>,
    ) -> Result<Head> {
        loop {
            match self.parse_head(max_head, MessageKind::Response) {
                Ok(Some(head)) => return Ok(head),
                Ok(None) => {}
                Err(_) => return Err(ProxyError::bad_backend_head()),
            }
            let filled = match idle {
                Some(idle) => self.fill(stream, idle).await?,
                None => self.fill_untimed(stream).await?,
            };
            if filled == 0 {
                return Err(ProxyError::new(
                    Stage::Relay,
                    Side::Backend,
                    ErrorKind::Closed,
                ));
            }
        }
    }
}

impl ProxyError {
    #[cold]
    #[inline(never)]
    fn bad_backend_head() -> ProxyError {
        ProxyError::new(
            Stage::Relay,
            Side::Backend,
            ErrorKind::Protocol("malformed backend response head".into()),
        )
    }
}
