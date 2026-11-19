/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::{Forwarding, Protocol};
use crate::error::{ProxyError, Result, Stage};
use crate::net::linebuf::LineBuf;
use crate::net::stream::BackendStream;
use crate::proto::backend::{EncryptedLeg, InitialResponse};
use crate::proto::forward::{ForwardInfo, XclientAttrs, XclientDialect};
use crate::runtime::Runtime;
use crate::runtime::destination::{Destination, Endpoint, LegTls};

const MAX_REPLY_LINES: usize = 256;
const MAX_REPLY_BYTES: usize = 64 * 1024;
const FALLBACK_HELO: &str = "proxy";
const READY: u16 = 220;
const COMPLETED: u16 = 250;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct EhloCaps {
    pub starttls: bool,
    pub xclient: XclientAttrs,
}

#[derive(Clone, Copy)]
enum Extension {
    StartTls,
    Xclient,
}

#[derive(Debug, Default)]
pub struct Reply {
    lines: usize,
    bytes: usize,
}

impl Reply {
    pub fn feed(&mut self, line: &[u8], caps: &mut EhloCaps, stage: Stage) -> Result<Option<u16>> {
        self.lines += 1;
        self.bytes = self.bytes.saturating_add(line.len());
        if self.lines > MAX_REPLY_LINES || self.bytes > MAX_REPLY_BYTES {
            return Err(ProxyError::unavailable(
                stage,
                "backend SMTP reply too long",
            ));
        }
        let Some((code, rest)) = line.split_first_chunk::<3>() else {
            return Err(ProxyError::malformed_smtp_reply(stage));
        };
        if !code.iter().all(u8::is_ascii_digit) {
            return Err(ProxyError::malformed_smtp_reply(stage));
        }
        let (last, text) = match rest.split_first() {
            Some((b'-', text)) => (false, text),
            Some((_, text)) => (true, text),
            None => (true, rest),
        };
        caps.scan(text);
        Ok(last.then(|| code.iter().fold(0u16, |n, d| n * 10 + u16::from(d - b'0'))))
    }
}

impl EhloCaps {
    fn scan(&mut self, text: &[u8]) {
        let mut words = text
            .split(u8::is_ascii_whitespace)
            .filter(|word| !word.is_empty());
        let Some(name) = words.next() else {
            return;
        };
        match hashify::map_ignore_case!(
            name,
            Extension,
            "STARTTLS" => Extension::StartTls,
            "XCLIENT" => Extension::Xclient,
        ) {
            Some(Extension::StartTls) => self.starttls = true,
            Some(Extension::Xclient) => {
                self.xclient = XclientAttrs::parse(words);
            }
            None => {}
        }
    }
}

impl EncryptedLeg {
    pub async fn open_submission(
        rt: &Runtime,
        dest: &Destination,
        ep: &Endpoint,
        fwd: &ForwardInfo<'_>,
    ) -> Result<Self> {
        let helo = match fwd.helo {
            Some(helo) if !helo.is_empty() => helo,
            _ => rt.server.hostname.as_deref().unwrap_or(FALLBACK_HELO),
        };
        let mut ehlo = Vec::with_capacity(helo.len() + 7);
        ehlo.extend_from_slice(b"EHLO ");
        ehlo.extend_from_slice(helo.as_bytes());
        ehlo.extend_from_slice(b"\r\n");

        let (mut stream, mut buf) = dest.connect_backend(rt, ep, fwd).await?;
        let mut caps = EhloCaps::default();
        expect(
            caps.read_reply(&mut stream, &mut buf, Stage::Greeting)
                .await?,
            READY,
            Stage::Greeting,
        )?;
        stream.send(&ehlo, Stage::Greeting).await?;
        expect(
            caps.read_reply(&mut stream, &mut buf, Stage::Greeting)
                .await?,
            COMPLETED,
            Stage::Greeting,
        )?;

        if let LegTls::Starttls(config) = &ep.leg {
            if !caps.starttls {
                return Err(ProxyError::unavailable(
                    Stage::Starttls,
                    "backend did not advertise STARTTLS",
                ));
            }
            stream.send(b"STARTTLS\r\n", Stage::Starttls).await?;
            expect(
                caps.read_reply(&mut stream, &mut buf, Stage::Starttls)
                    .await?,
                READY,
                Stage::Starttls,
            )?;
            stream = stream
                .upgrade(config, dest.server_name.as_ref(), &buf)
                .await?;
            caps = EhloCaps::default();
            stream.send(&ehlo, Stage::Greeting).await?;
            expect(
                caps.read_reply(&mut stream, &mut buf, Stage::Greeting)
                    .await?,
                COMPLETED,
                Stage::Greeting,
            )?;
        }

        let mut leg = Self::new(stream, buf, ep, InitialResponse::Inline)?;
        if ep.forwarding == Forwarding::Xclient && caps.xclient.is_empty() {
            dest.warn_unadvertised(Protocol::Submission);
        } else if ep.forwarding == Forwarding::Xclient {
            let cmd = fwd.xclient_command(XclientDialect::Smtp(caps.xclient));
            leg.send(cmd.as_bytes(), Stage::Forwarding).await?;
            let code = leg.smtp_reply(&mut caps).await?;
            if !(200..300).contains(&code) {
                return Err(ProxyError::unavailable(
                    Stage::Forwarding,
                    "backend rejected XCLIENT",
                ));
            }
            leg.send(&ehlo, Stage::Forwarding).await?;
            expect(
                leg.smtp_reply(&mut caps).await?,
                COMPLETED,
                Stage::Forwarding,
            )?;
        }
        Ok(leg)
    }

    async fn smtp_reply(&mut self, caps: &mut EhloCaps) -> Result<u16> {
        let mut reply = Reply::default();
        loop {
            let line = self.read_line(Stage::Forwarding).await?;
            if let Some(code) = reply.feed(line, caps, Stage::Forwarding)? {
                return Ok(code);
            }
        }
    }
}

impl EhloCaps {
    async fn read_reply(
        &mut self,
        stream: &mut BackendStream,
        buf: &mut LineBuf,
        stage: Stage,
    ) -> Result<u16> {
        buf.set_stage(stage);
        let mut reply = Reply::default();
        loop {
            if let Some(code) = reply.feed(buf.read_line(&mut *stream).await?, self, stage)? {
                return Ok(code);
            }
        }
    }
}

fn expect(code: u16, want: u16, stage: Stage) -> Result<()> {
    if code == want {
        Ok(())
    } else {
        Err(ProxyError::unexpected_smtp_reply(code, want, stage))
    }
}

impl ProxyError {
    #[cold]
    #[inline(never)]
    fn unexpected_smtp_reply(code: u16, want: u16, stage: Stage) -> ProxyError {
        ProxyError::unavailable(
            stage,
            format!("backend SMTP replied {code}, expected {want}"),
        )
    }

    #[cold]
    #[inline(never)]
    fn malformed_smtp_reply(stage: Stage) -> ProxyError {
        ProxyError::unavailable(stage, "malformed backend SMTP reply")
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../../proxy-tests/unit/src/proto/submission/backend/tests.rs"]
mod tests;
