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

const STARTTLS_TAG: &[u8] = b"P1";
const CAPABILITY_TAG: &[u8] = b"P2";
const MAX_REPLY_LINES: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendCaps {
    pub listed: bool,
    pub sasl_ir: bool,
    pub id: bool,
    pub starttls: bool,
}

#[derive(Clone, Copy)]
enum CapToken {
    Capability,
    SaslIr,
    Id,
    StartTls,
}

impl BackendCaps {
    pub fn scan(&mut self, line: &[u8]) {
        for word in line.split(|b| matches!(b, b' ' | b'\t' | b'[' | b']' | b'"')) {
            match hashify::map_ignore_case!(
                word,
                CapToken,
                "CAPABILITY" => CapToken::Capability,
                "SASL-IR" => CapToken::SaslIr,
                "ID" => CapToken::Id,
                "STARTTLS" => CapToken::StartTls,
            ) {
                Some(CapToken::Capability) => self.listed = true,
                Some(CapToken::SaslIr) => self.sasl_ir = true,
                Some(CapToken::Id) => self.id = true,
                Some(CapToken::StartTls) => self.starttls = true,
                None => {}
            }
        }
    }

    pub fn initial_response(&self) -> InitialResponse {
        if self.sasl_ir {
            InitialResponse::Inline
        } else {
            InitialResponse::Deferred
        }
    }
}

impl EncryptedLeg {
    pub async fn open_imap(
        rt: &Runtime,
        dest: &Destination,
        ep: &Endpoint,
        fwd: &ForwardInfo<'_>,
    ) -> Result<Self> {
        let (mut stream, mut buf) = dest.connect_backend(rt, ep, fwd).await?;
        let mut caps = BackendCaps::default();
        caps.scan(buf.read_line(&mut stream).await?);

        if let LegTls::Starttls(config) = &ep.leg {
            if caps.listed && !caps.starttls {
                return Err(ProxyError::unavailable(
                    Stage::Starttls,
                    "backend did not advertise STARTTLS",
                ));
            }
            stream.send(b"P1 STARTTLS\r\n", Stage::Starttls).await?;
            buf.set_stage(Stage::Starttls);
            if !read_tagged(&mut stream, &mut buf, STARTTLS_TAG, None).await? {
                return Err(ProxyError::unavailable(
                    Stage::Starttls,
                    "backend refused STARTTLS",
                ));
            }
            stream = stream
                .upgrade(config, dest.server_name.as_ref(), &buf)
                .await?;
            caps = BackendCaps::default();
            stream.send(b"P2 CAPABILITY\r\n", Stage::Greeting).await?;
            buf.set_stage(Stage::Greeting);
            if !read_tagged(&mut stream, &mut buf, CAPABILITY_TAG, Some(&mut caps)).await? {
                return Err(ProxyError::unavailable(
                    Stage::Greeting,
                    "backend refused CAPABILITY",
                ));
            }
        }

        let mut leg = Self::new(stream, buf, ep, caps.initial_response())?;
        match (ep.forwarding, caps.id) {
            (Forwarding::Xclient, true) => fwd.send_imap_id(&mut leg).await?,
            (Forwarding::Xclient, false) => dest.warn_unadvertised(Protocol::Imap),
            _ => {}
        }
        Ok(leg)
    }
}

async fn read_tagged(
    stream: &mut BackendStream,
    buf: &mut LineBuf,
    tag: &[u8],
    mut caps: Option<&mut BackendCaps>,
) -> Result<bool> {
    for _ in 0..MAX_REPLY_LINES {
        let line = buf.read_line(&mut *stream).await?;
        if let Some(status) = tagged_status(line, tag) {
            return Ok(status);
        }
        if let Some(caps) = caps.as_deref_mut() {
            caps.scan(line);
        }
    }
    Err(ProxyError::unavailable(
        Stage::Greeting,
        "backend reply was not tagged",
    ))
}

pub fn tagged_status(line: &[u8], tag: &[u8]) -> Option<bool> {
    let rest = line
        .trim_ascii()
        .strip_prefix(tag)
        .filter(|rest| rest.first().is_some_and(u8::is_ascii_whitespace))?;
    Some(starts_with_ci(rest.trim_ascii_start(), b"OK"))
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../../proxy-tests/unit/src/proto/imap/backend/tests.rs"]
mod tests;
