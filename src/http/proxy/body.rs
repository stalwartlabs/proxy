/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::{self, IoSlice};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use memchr::memchr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::error::{ErrorKind, Limit, ProxyError, Result, Side, Stage};
use crate::http::head::{BodyFraming, ParseError};

use crate::http::reader::{Reader, wire_len};

const MAX_CHUNK_LINE: usize = 16 * 1024;
const LAST_CHUNK: &[u8] = b"0\r\n";
const EMPTY_LAST_CHUNK: &[u8] = b"0\r\n\r\n";
const CRLF: &[u8] = b"\r\n";
const MAX_CHUNK_HEADER: usize = 18;

pub(super) async fn send(
    dst: &mut (impl AsyncWrite + Unpin),
    bytes: &[u8],
    side: Side,
    idle: Duration,
) -> Result<()> {
    bounded(timeout(idle, dst.write_all(bytes)).await, side)
}

pub(super) async fn send_parts(
    dst: &mut (impl AsyncWrite + Unpin),
    parts: &mut [IoSlice<'_>],
    side: Side,
    idle: Duration,
) -> Result<()> {
    bounded(timeout(idle, write_all_vectored(dst, parts)).await, side)
}

pub(super) async fn flush(
    dst: &mut (impl AsyncWrite + Unpin),
    side: Side,
    idle: Duration,
) -> Result<()> {
    bounded(timeout(idle, dst.flush()).await, side)
}

fn bounded(
    outcome: std::result::Result<io::Result<()>, tokio::time::error::Elapsed>,
    side: Side,
) -> Result<()> {
    match outcome {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(ProxyError::io(Stage::Relay, side, err)),
        Err(_) => Err(ProxyError::timeout(Stage::Relay, side)),
    }
}

async fn write_all_vectored(
    dst: &mut (impl AsyncWrite + Unpin),
    mut parts: &mut [IoSlice<'_>],
) -> io::Result<()> {
    IoSlice::advance_slices(&mut parts, 0);
    while !parts.is_empty() {
        let n = dst.write_vectored(parts).await?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        IoSlice::advance_slices(&mut parts, n);
    }
    Ok(())
}

pub(super) fn count(meter: Option<&AtomicU64>, bytes: usize) {
    if let Some(meter) = meter {
        meter.fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

fn parse_chunk_size(line: &[u8]) -> Option<u64> {
    let size = line.split(|&b| b == b';').next()?.trim_ascii();
    if size.is_empty() {
        return None;
    }
    size.iter().try_fold(0u64, |acc, &b| {
        let digit = u64::from(char::from(b).to_digit(16)?);
        acc.checked_mul(16)?.checked_add(digit)
    })
}

struct ChunkHeader {
    buf: [u8; MAX_CHUNK_HEADER],
    start: usize,
}

impl ChunkHeader {
    fn new(mut size: u64) -> Self {
        let mut buf = [0u8; MAX_CHUNK_HEADER];
        let mut start = MAX_CHUNK_HEADER - CRLF.len();
        if let Some(tail) = buf.get_mut(start..) {
            tail.copy_from_slice(CRLF);
        }
        for slot in buf.iter_mut().take(start).rev() {
            *slot = char::from_digit((size & 0xf) as u32, 16).map_or(b'0', |c| c as u8);
            size >>= 4;
            start -= 1;
            if size == 0 {
                break;
            }
        }
        ChunkHeader { buf, start }
    }

    fn as_bytes(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or_default()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    ToBackend,
    ToClient,
}

impl Direction {
    fn dst(self) -> Side {
        match self {
            Direction::ToBackend => Side::Backend,
            Direction::ToClient => Side::Client,
        }
    }
}

pub(super) struct Pipe<'a, S, D> {
    pub src: &'a mut S,
    pub reader: &'a mut Reader,
    pub dst: &'a mut D,
    pub dir: Direction,
    pub idle: Duration,
    pub meter: Option<&'a AtomicU64>,
}

impl<S, D> Pipe<'_, S, D>
where
    S: AsyncRead + Unpin,
    D: AsyncWrite + Unpin,
{
    pub(super) async fn body(&mut self, framing: BodyFraming, already: usize) -> Result<()> {
        match framing {
            BodyFraming::None | BodyFraming::UntilClose => Ok(()),
            BodyFraming::Length(n) => self.length(n.saturating_sub(already as u64)).await,
            BodyFraming::Chunked => self.chunked().await,
        }
    }

    pub(super) async fn length(&mut self, remaining: u64) -> Result<()> {
        self.reader.grow_for_body(remaining);
        let relayed = self.length_inner(remaining).await;
        self.reader.shrink_idle();
        relayed
    }

    async fn length_inner(&mut self, mut remaining: u64) -> Result<()> {
        while remaining > 0 {
            if self.reader.is_empty() {
                self.fill().await?;
            }
            let take = wire_len(remaining).min(self.reader.data().len());
            self.forward(take).await?;
            remaining = remaining.saturating_sub(take as u64);
        }
        Ok(())
    }

    pub(super) async fn chunked(&mut self) -> Result<()> {
        let relayed = self.chunked_inner().await;
        self.reader.shrink_idle();
        relayed
    }

    async fn chunked_inner(&mut self) -> Result<()> {
        loop {
            let size = self.chunk_size().await?;
            if size == 0 {
                return self.trailers().await;
            }
            self.reader.grow_for_body(size);
            let header = ChunkHeader::new(size);
            let mut remaining = size;
            let mut first = true;
            while remaining > 0 {
                if self.reader.is_empty() {
                    self.fill().await?;
                }
                let take = wire_len(remaining).min(self.reader.data().len());
                let last = take as u64 == remaining;
                if first || last {
                    let data = self.reader.data().get(..take).unwrap_or_default();
                    let mut parts = [
                        IoSlice::new(if first { header.as_bytes() } else { &[] }),
                        IoSlice::new(data),
                        IoSlice::new(if last { CRLF } else { &[] }),
                    ];
                    let wire = parts.iter().map(|p| p.len()).sum();
                    send_parts(self.dst, &mut parts, self.dir.dst(), self.idle).await?;
                    count(self.meter, wire);
                    self.reader.consume(take);
                } else {
                    self.forward(take).await?;
                }
                first = false;
                remaining -= take as u64;
            }
            let end = self.line_end().await?;
            let line = self.reader.data().get(..end).unwrap_or_default();
            if !matches!(line, [] | [b'\r']) {
                return Err(ProxyError::relay_malformed(
                    self.reader.side(),
                    "malformed chunk terminator",
                ));
            }
            self.reader.consume(end + 1);
        }
    }

    pub(super) async fn until_close(&mut self) -> Result<()> {
        self.reader.shrink_idle();
        loop {
            if !self.reader.is_empty() {
                self.forward(self.reader.data().len()).await?;
                flush(self.dst, self.dir.dst(), self.idle).await?;
            }
            if self.reader.fill(self.src, self.idle).await? == 0 {
                return Ok(());
            }
        }
    }

    async fn forward(&mut self, take: usize) -> Result<()> {
        let data = self.reader.data().get(..take).unwrap_or_default();
        send(self.dst, data, self.dir.dst(), self.idle).await?;
        count(self.meter, data.len());
        self.reader.consume(take);
        Ok(())
    }

    async fn fill(&mut self) -> Result<()> {
        match self.reader.fill(self.src, self.idle).await? {
            0 => Err(ProxyError::relay_closed(self.reader.side())),
            _ => Ok(()),
        }
    }

    async fn line_end(&mut self) -> Result<usize> {
        loop {
            if let Some(end) = memchr(b'\n', self.reader.data()) {
                return Ok(end);
            }
            if self.reader.data().len() > MAX_CHUNK_LINE {
                return Err(ProxyError::limit(
                    Stage::Relay,
                    self.reader.side(),
                    Limit::Chunk,
                ));
            }
            self.fill().await?;
        }
    }

    async fn chunk_size(&mut self) -> Result<u64> {
        let end = self.line_end().await?;
        let line = self.reader.data().get(..end).unwrap_or_default();
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let size = parse_chunk_size(line)
            .ok_or_else(|| ProxyError::relay_malformed(self.reader.side(), "invalid chunk size"))?;
        self.reader.consume(end + 1);
        Ok(size)
    }

    async fn trailers(&mut self) -> Result<()> {
        let mut frame = Vec::new();
        loop {
            if frame.is_empty() && self.reader.data().starts_with(CRLF) {
                self.reader.consume(CRLF.len());
                send(self.dst, EMPTY_LAST_CHUNK, self.dir.dst(), self.idle).await?;
                count(self.meter, EMPTY_LAST_CHUNK.len());
                return Ok(());
            }
            if frame.is_empty() {
                frame.extend_from_slice(LAST_CHUNK);
            }
            match self.reader.parse_trailers(&mut frame) {
                Ok(true) => {
                    send(self.dst, &frame, self.dir.dst(), self.idle).await?;
                    count(self.meter, frame.len());
                    return Ok(());
                }
                Ok(false) => self.fill().await?,
                Err(ParseError::TooLarge) => {
                    return Err(ProxyError::limit(
                        Stage::Relay,
                        self.reader.side(),
                        Limit::Trailers,
                    ));
                }
                Err(_) => {
                    return Err(ProxyError::relay_malformed(
                        self.reader.side(),
                        "invalid chunked trailer section",
                    ));
                }
            }
        }
    }
}

impl ProxyError {
    #[cold]
    #[inline(never)]
    fn relay_malformed(side: Side, what: &'static str) -> ProxyError {
        ProxyError::new(Stage::Relay, side, ErrorKind::Protocol(what.into()))
    }

    #[cold]
    #[inline(never)]
    fn relay_closed(side: Side) -> ProxyError {
        ProxyError::new(Stage::Relay, side, ErrorKind::Closed)
    }
}
