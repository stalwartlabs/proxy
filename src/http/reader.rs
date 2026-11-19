/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::mem;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::time::timeout;

use crate::error::{ProxyError, Result, Side, Stage};
use crate::http::head::{Head, HeadScan, MessageKind, ParseError};

const READ_CHUNK: usize = 16 * 1024;
const BODY_CHUNK: usize = 64 * 1024;
const MIN_SPARE: usize = 4 * 1024;

pub struct Reader {
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
    scan: HeadScan,
    max_trailers: usize,
    side: Side,
}

impl Reader {
    pub fn new(side: Side, max_trailers: usize) -> Self {
        Reader {
            buf: Vec::with_capacity(READ_CHUNK),
            pos: 0,
            eof: false,
            scan: HeadScan::default(),
            max_trailers,
            side,
        }
    }

    pub fn parse_head(
        &mut self,
        max_head: usize,
        kind: MessageKind,
    ) -> std::result::Result<Option<Head>, ParseError> {
        let data = self.buf.get(self.pos..).unwrap_or_default();
        let head = self.scan.parse(data, max_head, kind)?;
        if let Some(head) = &head {
            self.consume(head.raw().len());
        }
        Ok(head)
    }

    pub fn parse_trailers(&mut self, out: &mut Vec<u8>) -> std::result::Result<bool, ParseError> {
        let data = self.buf.get(self.pos..).unwrap_or_default();
        let Some(trailers) = self.scan.trailers(data, self.max_trailers)? else {
            return Ok(false);
        };
        trailers.write_to(out)?;
        let consumed = trailers.wire_len();
        self.consume(consumed);
        Ok(true)
    }

    pub fn data(&self) -> &[u8] {
        self.buf.get(self.pos..).unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn is_eof(&self) -> bool {
        self.eof
    }

    pub fn side(&self) -> Side {
        self.side
    }

    pub fn consume(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n).min(self.buf.len());
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        }
    }

    pub fn grow_for_body(&mut self, remaining: u64) {
        if remaining > READ_CHUNK as u64 && self.buf.capacity() < BODY_CHUNK {
            self.buf.reserve(BODY_CHUNK.saturating_sub(self.buf.len()));
        }
    }

    pub fn shrink_idle(&mut self) {
        if self.buf.capacity() <= READ_CHUNK || self.data().len() > READ_CHUNK {
            return;
        }
        self.buf.drain(..self.pos);
        self.pos = 0;
        self.buf.shrink_to(READ_CHUNK);
    }

    pub fn take_rest(&mut self) -> Vec<u8> {
        self.buf.drain(..self.pos);
        self.pos = 0;
        mem::take(&mut self.buf)
    }

    pub async fn fill(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
        idle: Duration,
    ) -> Result<usize> {
        match timeout(idle, self.fill_untimed(stream)).await {
            Ok(filled) => filled,
            Err(_) => Err(ProxyError::timeout(Stage::Relay, self.side)),
        }
    }

    pub async fn fill_untimed(&mut self, stream: &mut (impl AsyncRead + Unpin)) -> Result<usize> {
        self.make_room();
        let n = stream
            .read_buf(&mut self.buf)
            .await
            .map_err(|err| ProxyError::io(Stage::Relay, self.side, err))?;
        if n == 0 {
            self.eof = true;
        }
        Ok(n)
    }

    pub async fn discard(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
        mut remaining: u64,
        idle: Duration,
    ) -> Result<()> {
        while remaining > 0 {
            if self.is_empty() && self.fill(stream, idle).await? == 0 {
                return Ok(());
            }
            let take = wire_len(remaining).min(self.data().len());
            self.consume(take);
            remaining = remaining.saturating_sub(take as u64);
        }
        Ok(())
    }

    fn make_room(&mut self) {
        if self.buf.capacity() - self.buf.len() >= MIN_SPARE {
            return;
        }
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.reserve(READ_CHUNK);
    }
}

pub fn wire_len(value: u64) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/http/reader/tests.rs"]
mod tests;
