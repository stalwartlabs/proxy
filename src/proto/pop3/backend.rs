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
use crate::proto::forward::ForwardInfo;
use crate::runtime::Runtime;
use crate::runtime::destination::{Destination, Endpoint, LegTls};

const MAX_CAPA_LINES: usize = 256;
const MAX_CAPA_BYTES: usize = 64 * 1024;
const XCLIENT: &[u8] = b"XCLIENT";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendCaps {
    pub stls: bool,
    pub sasl: bool,
    pub xclient: bool,
}

#[derive(Clone, Copy)]
enum CapToken {
    Stls,
    Sasl,
    Xclient,
}

impl BackendCaps {
    pub fn scan_capa(&mut self, line: &[u8]) {
        let name = line
            .split(u8::is_ascii_whitespace)
            .next()
            .unwrap_or_default();
        match hashify::map_ignore_case!(
            name,
            CapToken,
            "STLS" => CapToken::Stls,
            "SASL" => CapToken::Sasl,
            "XCLIENT" => CapToken::Xclient,
        ) {
            Some(CapToken::Stls) => self.stls = true,
            Some(CapToken::Sasl) => self.sasl = true,
            Some(CapToken::Xclient) => self.xclient = true,
            None => {}
        }
    }

    pub fn greeting_offers_xclient(line: &[u8]) -> bool {
        line.split(|b| matches!(b, b' ' | b'\t' | b'[' | b']'))
            .any(|word| word.eq_ignore_ascii_case(XCLIENT))
    }
}

impl EncryptedLeg {
    pub async fn open_pop3(
        rt: &Runtime,
        dest: &Destination,
        ep: &Endpoint,
        fwd: &ForwardInfo<'_>,
    ) -> Result<Self> {
        let (mut stream, mut buf) = dest.connect_backend(rt, ep, fwd).await?;
        let greeting = buf.read_line(&mut stream).await?;
        if !greeting.starts_with(b"+OK") {
            return Err(ProxyError::unavailable(
                Stage::Greeting,
                "backend POP3 greeting was not +OK",
            ));
        }
        let mut xclient = BackendCaps::greeting_offers_xclient(greeting);
        let mut initial = InitialResponse::Inline;

        if let LegTls::Starttls(config) = &ep.leg {
            let offered = BackendCaps::query(&mut stream, &mut buf, Stage::Starttls).await?;
            if !offered.is_some_and(|caps| caps.stls) {
                return Err(ProxyError::unavailable(
                    Stage::Starttls,
                    "backend did not advertise STLS",
                ));
            }
            stream.send(b"STLS\r\n", Stage::Starttls).await?;
            if !buf.read_line(&mut stream).await?.starts_with(b"+OK") {
                return Err(ProxyError::unavailable(
                    Stage::Starttls,
                    "backend refused STLS",
                ));
            }
            stream = stream
                .upgrade(config, dest.server_name.as_ref(), &buf)
                .await?;
            let caps = BackendCaps::query(&mut stream, &mut buf, Stage::Greeting).await?;
            xclient |= caps.is_some_and(|caps| caps.xclient);
            initial = if caps.is_some_and(|caps| caps.sasl) {
                InitialResponse::Inline
            } else {
                InitialResponse::Deferred
            };
        }

        let mut leg = Self::new(stream, buf, ep, initial)?;
        match (ep.forwarding, xclient) {
            (Forwarding::Xclient, true) => fwd.send_pop3_xclient(&mut leg).await?,
            (Forwarding::Xclient, false) => dest.warn_unadvertised(Protocol::Pop3),
            _ => {}
        }
        Ok(leg)
    }
}

impl BackendCaps {
    async fn query(
        stream: &mut BackendStream,
        buf: &mut LineBuf,
        stage: Stage,
    ) -> Result<Option<Self>> {
        stream.send(b"CAPA\r\n", stage).await?;
        buf.set_stage(stage);
        if !buf.read_line(&mut *stream).await?.starts_with(b"+OK") {
            return Ok(None);
        }
        let mut caps = Self::default();
        let mut total = 0usize;
        for _ in 0..MAX_CAPA_LINES {
            let line = buf.read_line(&mut *stream).await?;
            if line == b"." {
                return Ok(Some(caps));
            }
            total = total.saturating_add(line.len());
            if total > MAX_CAPA_BYTES {
                break;
            }
            caps.scan_capa(line);
        }
        Err(ProxyError::unavailable(
            stage,
            "backend CAPA reply too long",
        ))
    }
}


#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../../proxy-tests/unit/src/proto/pop3/backend/tests.rs"]
mod tests;
