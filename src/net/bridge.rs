/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::{Future, pending, poll_fn};
use std::io;
use std::mem;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep};

use crate::error::{ErrorKind, ProxyError, Side, Stage};
use crate::net::stream::{BackendStream, ClientStream};
use crate::runtime::registry::{ConnInfo, Kick};

pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

const IDLE_TICKS: u32 = 4;
const MIN_TICK: Duration = Duration::from_millis(1);

#[derive(Clone, Copy, Debug)]
pub struct BufferSizes {
    pub initial: usize,
    pub max: usize,
}

pub const BUFFER_SIZES: BufferSizes = BufferSizes {
    initial: 4 * 1024,
    max: 64 * 1024,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Totals {
    pub to_backend: u64,
    pub to_client: u64,
}

#[derive(Debug)]
pub enum BridgeEnd {
    Idle,
    Kicked,
    Failed(ProxyError),
}

impl BridgeEnd {
    pub fn label(&self) -> &'static str {
        match self {
            BridgeEnd::Idle => "idle",
            BridgeEnd::Kicked => "kicked",
            BridgeEnd::Failed(_) => "failed",
        }
    }
}

impl From<BridgeEnd> for ProxyError {
    #[cold]
    fn from(end: BridgeEnd) -> Self {
        match end {
            BridgeEnd::Idle => ProxyError::timeout(Stage::Relay, Side::Client),
            BridgeEnd::Kicked => ProxyError::new(
                Stage::Relay,
                Side::Client,
                ErrorKind::Unavailable("disconnected by admin".into()),
            ),
            BridgeEnd::Failed(err) => err,
        }
    }
}

pub struct BridgeArgs {
    pub client: ClientStream,
    pub backend: BackendStream,
    pub to_backend: Vec<u8>,
    pub to_client: Vec<u8>,
    pub idle: Duration,
    pub kick: Option<Kick>,
    pub info: Option<Arc<ConnInfo>>,
    pub sizes: BufferSizes,
}

impl BridgeArgs {
    pub fn new(client: ClientStream, backend: BackendStream, idle: Duration) -> Self {
        BridgeArgs {
            client,
            backend,
            to_backend: Vec::new(),
            to_client: Vec::new(),
            idle,
            kick: None,
            info: None,
            sizes: BUFFER_SIZES,
        }
    }

    pub async fn run(self) -> Result<Totals, BridgeEnd> {
        let BridgeArgs {
            mut client,
            mut backend,
            to_backend,
            to_client,
            idle,
            kick,
            info,
            sizes,
        } = self;
        let (up_counter, down_counter) = match &info {
            Some(info) => (Some(&info.bytes_up), Some(&info.bytes_down)),
            None => (None, None),
        };
        let mut up = CopyDir::new(to_backend, sizes, Side::Client, up_counter);
        let mut down = CopyDir::new(to_client, sizes, Side::Backend, down_counter);
        let tick = (idle / IDLE_TICKS).max(MIN_TICK);
        let mut ticker = pin!(sleep(tick));
        let mut kicked = pin!(wait_kick(kick));
        let mut empty_ticks = 0u32;

        poll_fn(|cx| {
            if kicked.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Err(BridgeEnd::Kicked));
            }
            let up_state = up.poll(cx, &mut client, &mut backend);
            let down_state = down.poll(cx, &mut backend, &mut client);
            match (up_state, down_state) {
                (Poll::Ready(Err(e)), _) | (_, Poll::Ready(Err(e))) => {
                    return Poll::Ready(Err(BridgeEnd::Failed(e)));
                }
                (Poll::Ready(Ok(())), Poll::Ready(Ok(()))) => return Poll::Ready(Ok(())),
                _ => {}
            }
            while ticker.as_mut().poll(cx).is_ready() {
                if up.take_activity() | down.take_activity() {
                    empty_ticks = 0;
                } else {
                    empty_ticks += 1;
                    if empty_ticks >= IDLE_TICKS {
                        return Poll::Ready(Err(BridgeEnd::Idle));
                    }
                }
                up.on_tick();
                down.on_tick();
                ticker.as_mut().reset(Instant::now() + tick);
            }
            Poll::Pending
        })
        .await?;

        Ok(Totals {
            to_backend: up.total,
            to_client: down.total,
        })
    }
}

pub async fn wait_kick(kick: Option<Kick>) {
    let Some(mut rx) = kick else {
        return pending().await;
    };
    while rx.changed().await.is_ok() {
        if *rx.borrow() {
            return;
        }
    }
    pending().await
}

enum DirState {
    Copying,
    ShuttingDown(Pin<Box<Sleep>>),
    Done,
}

struct CopyDir<'a> {
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    sizes: BufferSizes,
    total: u64,
    reader: Side,
    writer: Side,
    read_done: bool,
    need_flush: bool,
    grow: bool,
    activity: bool,
    filled: bool,
    counter_base: u64,
    state: DirState,
    counter: Option<&'a AtomicU64>,
}

impl<'a> CopyDir<'a> {
    fn new(
        seed: Vec<u8>,
        sizes: BufferSizes,
        reader: Side,
        counter: Option<&'a AtomicU64>,
    ) -> Self {
        let writer = match reader {
            Side::Client => Side::Backend,
            Side::Backend => Side::Client,
        };
        let seed = if seed.is_empty() { Vec::new() } else { seed };
        let total = seed.len() as u64;
        let counter_base = match counter {
            Some(counter) => {
                let base = counter.load(Ordering::Relaxed);
                counter.store(base + total, Ordering::Relaxed);
                base
            }
            None => 0,
        };
        CopyDir {
            len: seed.len(),
            buf: seed,
            pos: 0,
            sizes,
            total,
            reader,
            writer,
            read_done: false,
            need_flush: false,
            grow: false,
            activity: false,
            filled: false,
            counter_base,
            state: DirState::Copying,
            counter,
        }
    }

    fn take_activity(&mut self) -> bool {
        mem::take(&mut self.activity)
    }

    fn on_tick(&mut self) {
        if !mem::take(&mut self.filled) {
            self.shrink();
        }
    }

    fn poll<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        writer: &mut W,
    ) -> Poll<Result<(), ProxyError>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            match &mut self.state {
                DirState::Done => return Poll::Ready(Ok(())),
                DirState::ShuttingDown(grace) => {
                    let finished = Pin::new(&mut *writer).poll_shutdown(cx).is_ready()
                        || grace.as_mut().poll(cx).is_ready();
                    if !finished {
                        return Poll::Pending;
                    }
                    self.state = DirState::Done;
                    self.buf = Vec::new();
                }
                DirState::Copying => {
                    ready!(self.poll_copy(cx, reader, writer))?;
                    self.state = DirState::ShuttingDown(Box::pin(sleep(SHUTDOWN_GRACE)));
                }
            }
        }
    }

    fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        reader: &mut R,
        writer: &mut W,
    ) -> Poll<Result<(), ProxyError>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            while let Some(pending) = self.buf.get(self.pos..self.len).filter(|p| !p.is_empty()) {
                let n = ready!(Pin::new(&mut *writer).poll_write(cx, pending))
                    .map_err(|e| self.error(self.writer, e))?;
                if n == 0 {
                    return Poll::Ready(Err(
                        self.error(self.writer, io::ErrorKind::WriteZero.into())
                    ));
                }
                self.pos += n;
                self.need_flush = true;
            }
            if self.read_done {
                ready!(Pin::new(&mut *writer).poll_flush(cx))
                    .map_err(|e| self.error(self.writer, e))?;
                return Poll::Ready(Ok(()));
            }
            self.prepare_read();
            let mut rb = ReadBuf::new(&mut self.buf);
            match Pin::new(&mut *reader).poll_read(cx, &mut rb) {
                Poll::Pending => {
                    if self.need_flush {
                        ready!(Pin::new(&mut *writer).poll_flush(cx))
                            .map_err(|e| self.error(self.writer, e))?;
                        self.need_flush = false;
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(self.error(self.reader, e))),
                Poll::Ready(Ok(())) => {
                    let n = rb.filled().len();
                    if n == 0 {
                        self.read_done = true;
                        continue;
                    }
                    let full = n == self.buf.len();
                    self.filled |= full;
                    self.grow = full && n < self.sizes.max;
                    self.len = n;
                    self.total += n as u64;
                    self.activity = true;
                    if let Some(counter) = self.counter {
                        counter.store(self.counter_base + self.total, Ordering::Relaxed);
                    }
                }
            }
        }
    }

    fn shrink(&mut self) {
        if self.buf.capacity() > self.sizes.initial
            && self.pos >= self.len
            && matches!(self.state, DirState::Copying)
        {
            self.pos = 0;
            self.len = 0;
            self.buf.truncate(self.sizes.initial);
            self.buf.shrink_to(self.sizes.initial);
        }
    }

    fn prepare_read(&mut self) {
        self.pos = 0;
        self.len = 0;
        let want = if self.grow {
            self.grow = false;
            (self.buf.len() * 2).min(self.sizes.max)
        } else {
            self.sizes.initial
        };
        if self.buf.len() < want {
            self.buf.resize(want, 0);
        }
    }

    #[cold]
    #[inline(never)]
    fn error(&self, side: Side, err: io::Error) -> ProxyError {
        ProxyError::new(Stage::Relay, side, ErrorKind::Io(err))
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/net/bridge/tests.rs"]
mod tests;
