/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::mem;
use std::ops::Range;

use memchr::memchr;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{ErrorKind, Limit, ProxyError, Result, Side, Stage};

const READ_CHUNK: usize = 8192;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminator {
    Lf,
    Crlf,
}

pub struct LineBuf {
    buf: Vec<u8>,
    start: usize,
    scanned: usize,
    cap: usize,
    terminator: Terminator,
    side: Side,
    stage: Stage,
}

impl LineBuf {
    pub fn client(cap: usize) -> Self {
        Self::with_data(Vec::new(), cap, Terminator::Lf, Side::Client)
    }

    pub fn backend(cap: usize) -> Self {
        Self::with_data(Vec::new(), cap, Terminator::Crlf, Side::Backend)
    }

    pub fn with_data(data: Vec<u8>, cap: usize, terminator: Terminator, side: Side) -> Self {
        let stage = match side {
            Side::Client => Stage::Preauth,
            Side::Backend => Stage::Greeting,
        };
        LineBuf {
            buf: data,
            start: 0,
            scanned: 0,
            cap,
            terminator,
            side,
            stage,
        }
    }

    pub fn set_stage(&mut self, stage: Stage) {
        self.stage = stage;
    }

    pub fn data(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or_default()
    }

    pub fn consume(&mut self, n: usize) {
        self.start = self.start.saturating_add(n).min(self.buf.len());
        self.scanned = self.scanned.max(self.start);
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
            self.scanned = 0;
        }
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.start = 0;
        self.scanned = 0;
    }

    pub fn take_residual(&mut self) -> Vec<u8> {
        if self.start > 0 {
            self.buf.drain(..self.start);
        }
        self.start = 0;
        self.scanned = 0;
        mem::take(&mut self.buf)
    }

    pub fn has_line(&mut self) -> bool {
        self.find_line().is_some()
    }

    pub fn line(&mut self) -> Option<&[u8]> {
        let range = self.next_line()?;
        self.buf.get(range)
    }

    pub async fn read_line<S: AsyncRead + Unpin + ?Sized>(&mut self, s: &mut S) -> Result<&[u8]> {
        loop {
            if let Some(range) = self.next_line() {
                return Ok(self.buf.get(range).unwrap_or_default());
            }
            if self.fill(s).await? == 0 {
                return Err(ProxyError::new(self.stage, self.side, ErrorKind::Closed));
            }
        }
    }

    pub async fn fill<S: AsyncRead + Unpin + ?Sized>(&mut self, s: &mut S) -> Result<usize> {
        let pending = self.buf.len() - self.start;
        if pending >= self.cap {
            return Err(ProxyError::limit(self.stage, self.side, Limit::Line));
        }
        self.compact();
        let want = (self.cap - pending).min(READ_CHUNK);
        self.buf.reserve(want);
        s.take(want as u64)
            .read_buf(&mut self.buf)
            .await
            .map_err(|e| ProxyError::io(self.stage, self.side, e))
    }

    fn compact(&mut self) {
        if self.start == 0 {
            return;
        }
        if self.start == self.buf.len() {
            self.buf.clear();
            self.scanned = 0;
        } else if self.start >= self.buf.capacity() / 2 {
            self.buf.copy_within(self.start.., 0);
            self.buf.truncate(self.buf.len() - self.start);
            self.scanned -= self.start;
        } else {
            return;
        }
        self.start = 0;
    }

    fn find_line(&mut self) -> Option<(usize, usize)> {
        let mut from = self.scanned.max(self.start);
        loop {
            let tail = self.buf.get(from..).unwrap_or_default();
            let Some(pos) = memchr(b'\n', tail) else {
                self.scanned = self.buf.len();
                return None;
            };
            let nl = from + pos;
            let cr = nl > self.start && self.buf.get(nl - 1) == Some(&b'\r');
            match (self.terminator, cr) {
                (_, true) => return Some((nl - 1, nl + 1)),
                (Terminator::Lf, false) => return Some((nl, nl + 1)),
                (Terminator::Crlf, false) => from = nl + 1,
            }
        }
    }

    fn next_line(&mut self) -> Option<Range<usize>> {
        let (end, next) = self.find_line()?;
        let range = self.start..end;
        self.start = next;
        self.scanned = next;
        Some(range)
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/net/linebuf/tests.rs"]
mod tests;
