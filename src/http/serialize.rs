/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io::Write;
use std::net::IpAddr;

use memchr::memmem;

use super::head::{BodyFraming, Head, HeaderKind, ParseError, StartLine, Trailers};

const SERIALIZE_SLACK: usize = 160;
const CRLF: &[u8] = b"\r\n";
const LIST_SEPARATOR: &[u8] = b", ";
const MAX_U64_DIGITS: usize = 20;
const COOKIE_SEPARATOR: &[u8] = b"; ";

pub const ADMIN_SESSION_COOKIE: &str = "__Host-proxy_session";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionHeader {
    Omit,
    Close,
    Upgrade,
}

fn push_u64(out: &mut Vec<u8>, mut value: u64) {
    let mut digits = [0u8; MAX_U64_DIGITS];
    let mut used = 0;
    for slot in digits.iter_mut().rev() {
        *slot = b'0' + (value % 10) as u8;
        value /= 10;
        used += 1;
        if value == 0 {
            break;
        }
    }
    out.extend_from_slice(digits.get(MAX_U64_DIGITS - used..).unwrap_or_default());
}

fn push_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    out.extend_from_slice(value);
    out.extend_from_slice(CRLF);
}

fn push_cookie(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    let admin = ADMIN_SESSION_COOKIE.as_bytes();
    if memmem::find(value, admin).is_none() {
        push_field(out, name, value);
        return;
    }
    let start = out.len();
    out.extend_from_slice(name);
    out.extend_from_slice(b": ");
    let first = out.len();
    for pair in value.split(|&b| b == b';').map(<[u8]>::trim_ascii) {
        let is_admin = pair
            .strip_prefix(admin)
            .is_some_and(|rest| matches!(rest.trim_ascii_start(), [] | [b'=', ..]));
        if pair.is_empty() || is_admin {
            continue;
        }
        if out.len() > first {
            out.extend_from_slice(COOKIE_SEPARATOR);
        }
        out.extend_from_slice(pair);
    }
    match out.len() > first {
        true => out.extend_from_slice(CRLF),
        false => out.truncate(start),
    }
}

fn forbidden_in_trailers(name: &[u8]) -> bool {
    hashify::set_ignore_case!(
        name,
        "age",
        "cache-control",
        "content-encoding",
        "content-range",
        "content-type",
        "date",
        "expires",
        "if-match",
        "if-modified-since",
        "if-none-match",
        "if-range",
        "if-unmodified-since",
        "location",
        "max-forwards",
        "pragma",
        "range",
        "retry-after",
        "set-cookie",
        "vary",
        "warning",
        "www-authenticate",
    )
}

impl Trailers<'_> {
    pub fn write_to(&self, out: &mut Vec<u8>) -> Result<(), ParseError> {
        let start = out.len();
        out.reserve(self.wire_len());
        for field in self.fields() {
            let (name, value, kind) = match field {
                Ok(field) => field,
                Err(err) => {
                    out.truncate(start);
                    return Err(err);
                }
            };
            if kind == HeaderKind::Other && !forbidden_in_trailers(name) {
                push_field(out, name, value);
            }
        }
        out.extend_from_slice(CRLF);
        Ok(())
    }
}

impl Head {
    pub fn write_to(
        &self,
        out: &mut Vec<u8>,
        connection: ConnectionHeader,
        forwarded_for: Option<IpAddr>,
    ) {
        out.reserve(self.raw.len() + SERIALIZE_SLACK);
        self.write_start_line(out);

        for header in self.headers.iter().filter(|h| {
            !h.drop
                && !h.kind.is_never_forwarded()
                && !(forwarded_for.is_some()
                    && matches!(h.kind, HeaderKind::Forwarded | HeaderKind::XForwardedFor))
        }) {
            let (name, value) = (header.name.slice(&self.raw), header.value.slice(&self.raw));
            match header.kind {
                HeaderKind::Cookie => push_cookie(out, name, value),
                _ => push_field(out, name, value),
            }
        }

        if let Some(peer) = forwarded_for {
            self.write_forwarded(out, peer);
        }

        match self.framing {
            BodyFraming::Chunked if self.flags.te_codings => {
                out.extend_from_slice(b"Transfer-Encoding: ");
                self.write_joined(out, HeaderKind::TransferEncoding);
                out.extend_from_slice(CRLF);
            }
            BodyFraming::Chunked => out.extend_from_slice(b"Transfer-Encoding: chunked\r\n"),
            BodyFraming::Length(length) => {
                out.extend_from_slice(b"Content-Length: ");
                push_u64(out, length);
                out.extend_from_slice(CRLF);
            }
            BodyFraming::None | BodyFraming::UntilClose => {}
        }

        match connection {
            ConnectionHeader::Upgrade => {
                if let Some(upgrade) = self.header(HeaderKind::Upgrade) {
                    push_field(out, b"Upgrade", upgrade);
                }
                out.extend_from_slice(b"Connection: Upgrade\r\n");
            }
            ConnectionHeader::Close => out.extend_from_slice(b"Connection: close\r\n"),
            ConnectionHeader::Omit => {}
        }

        out.extend_from_slice(CRLF);
    }

    fn write_start_line(&self, out: &mut Vec<u8>) {
        match self.line {
            StartLine::Request {
                method_span,
                target,
                ..
            } => {
                out.extend_from_slice(method_span.slice(&self.raw));
                out.push(b' ');
                out.extend_from_slice(target.slice(&self.raw));
                out.extend_from_slice(b" HTTP/1.1\r\n");
            }
            StartLine::Response { status, reason } => {
                out.extend_from_slice(b"HTTP/1.1 ");
                push_u64(out, u64::from(status));
                out.push(b' ');
                out.extend_from_slice(reason.slice(&self.raw));
                out.extend_from_slice(CRLF);
            }
        }
    }

    fn write_joined(&self, out: &mut Vec<u8>, kind: HeaderKind) -> bool {
        let mut any = false;
        for value in self
            .headers
            .iter()
            .filter(|h| h.kind == kind && !h.drop)
            .map(|h| h.value.slice(&self.raw))
            .filter(|v| !v.is_empty())
        {
            if any {
                out.extend_from_slice(LIST_SEPARATOR);
            }
            out.extend_from_slice(value);
            any = true;
        }
        any
    }

    fn write_forwarded(&self, out: &mut Vec<u8>, peer: IpAddr) {
        out.extend_from_slice(b"Forwarded: ");
        if self.write_joined(out, HeaderKind::Forwarded) {
            out.extend_from_slice(LIST_SEPARATOR);
        }
        let _ = match peer {
            IpAddr::V4(v4) => write!(out, "for={v4}"),
            IpAddr::V6(v6) => write!(out, "for=\"[{v6}]\""),
        };
        out.extend_from_slice(CRLF);

        out.extend_from_slice(b"X-Forwarded-For: ");
        if self.write_joined(out, HeaderKind::XForwardedFor) {
            out.extend_from_slice(LIST_SEPARATOR);
        }
        let _ = write!(out, "{peer}");
        out.extend_from_slice(CRLF);
    }
}

pub fn error_response(status: u16, reason: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(reason.len() + 4);
    push_u64(&mut body, u64::from(status));
    body.push(b' ');
    body.extend_from_slice(reason.as_bytes());

    let mut out = Vec::with_capacity(body.len() * 2 + 96);
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(&body);
    out.extend_from_slice(b"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ");
    push_u64(&mut out, body.len() as u64);
    out.extend_from_slice(b"\r\nConnection: close\r\n\r\n");
    out.extend_from_slice(&body);
    out
}

pub fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        411 => "Length Required",
        413 => "Content Too Large",
        421 => "Misdirected Request",
        422 => "Unprocessable Content",
        428 => "Precondition Required",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}
