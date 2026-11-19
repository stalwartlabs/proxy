/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::{Forwarding, Protocol};
use crate::error::{ProxyError, Result, Stage};
use crate::net::linebuf::LineBuf;
use crate::net::stream::BackendStream;
use crate::proto::backend::{EncryptedLeg, InitialResponse, starts_with_ci};
use crate::proto::forward::ForwardInfo;
use crate::runtime::Runtime;
use crate::runtime::destination::{Destination, Endpoint, LegTls};

const MAX_CAPABILITY_LINES: usize = 256;
const MAX_CAPABILITY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendCaps {
    pub starttls: bool,
    pub xclient: bool,
}

#[derive(Clone, Copy)]
enum CapToken {
    StartTls,
    Xclient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapLine {
    Capability,
    Ok,
    Refused,
}

impl BackendCaps {
    pub fn scan(&mut self, line: &[u8]) -> CapLine {
        let line = line.trim_ascii_start();
        let Some(quoted) = line.strip_prefix(b"\"") else {
            let word = line
                .split(u8::is_ascii_whitespace)
                .next()
                .unwrap_or_default();
            return hashify::map_ignore_case!(
                word,
                CapLine,
                "OK" => CapLine::Ok,
                "NO" => CapLine::Refused,
                "BYE" => CapLine::Refused,
            )
            .copied()
            .unwrap_or(CapLine::Capability);
        };
        let name = quoted.split(|b| *b == b'"').next().unwrap_or_default();
        match hashify::map_ignore_case!(
            name,
            CapToken,
            "STARTTLS" => CapToken::StartTls,
            "XCLIENT" => CapToken::Xclient,
        ) {
            Some(CapToken::StartTls) => self.starttls = true,
            Some(CapToken::Xclient) => self.xclient = true,
            None => {}
        }
        CapLine::Capability
    }
}

impl EncryptedLeg {
    pub async fn open_managesieve(
        rt: &Runtime,
        dest: &Destination,
        ep: &Endpoint,
        fwd: &ForwardInfo<'_>,
    ) -> Result<Self> {
        let (mut stream, mut buf) = dest.connect_backend(rt, ep, fwd).await?;
        let mut caps = BackendCaps::read(&mut stream, &mut buf, Stage::Greeting).await?;

        if let LegTls::Starttls(config) = &ep.leg {
            if !caps.starttls {
                return Err(ProxyError::unavailable(
                    Stage::Starttls,
                    "backend did not advertise STARTTLS",
                ));
            }
            stream.send(b"STARTTLS\r\n", Stage::Starttls).await?;
            buf.set_stage(Stage::Starttls);
            if !starts_with_ci(buf.read_line(&mut stream).await?.trim_ascii_start(), b"OK") {
                return Err(ProxyError::unavailable(
                    Stage::Starttls,
                    "backend refused STARTTLS",
                ));
            }
            stream = stream
                .upgrade(config, dest.server_name.as_ref(), &buf)
                .await?;
            caps = BackendCaps::read(&mut stream, &mut buf, Stage::Greeting).await?;
        }

        let mut leg = Self::new(stream, buf, ep, InitialResponse::Inline)?;
        match (ep.forwarding, caps.xclient) {
            (Forwarding::Xclient, true) => fwd.send_managesieve_xclient(&mut leg).await?,
            (Forwarding::Xclient, false) => dest.warn_unadvertised(Protocol::ManageSieve),
            _ => {}
        }
        Ok(leg)
    }
}

impl BackendCaps {
    async fn read(stream: &mut BackendStream, buf: &mut LineBuf, stage: Stage) -> Result<Self> {
        buf.set_stage(stage);
        let mut caps = Self::default();
        let mut total = 0usize;
        for _ in 0..MAX_CAPABILITY_LINES {
            let line = buf.read_line(&mut *stream).await?;
            total = total.saturating_add(line.len());
            if total > MAX_CAPABILITY_BYTES {
                break;
            }
            match caps.scan(line) {
                CapLine::Capability => {}
                CapLine::Ok => return Ok(caps),
                CapLine::Refused => {
                    return Err(ProxyError::unavailable(
                        stage,
                        "backend refused the ManageSieve session",
                    ));
                }
            }
        }
        Err(ProxyError::unavailable(
            stage,
            "backend capability reply too long",
        ))
    }
}


#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../../proxy-tests/unit/src/proto/managesieve/backend/tests.rs"]
mod tests;
