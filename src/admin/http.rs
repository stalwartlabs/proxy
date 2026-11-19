/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::io::Write;
use std::time::Duration;

use percent_encoding::percent_decode_str;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout};

use crate::error::{ProxyError, Result, Side, Stage};
use crate::http::head::{BodyFraming, Head, HeaderKind, MessageKind, Method};
use crate::http::reader::{Reader, wire_len};
use crate::http::serialize::reason_phrase;

pub const MAX_HEAD: usize = 16 * 1024;
pub const NOT_MODIFIED: u16 = 304;
pub const NO_CONTENT: u16 = 204;
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const CONTINUE: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n";
const NO_STORE: &[u8] = b"Cache-Control: no-store\r\n";
#[cfg(feature = "ui")]
const NO_CACHE: &[u8] = b"Cache-Control: no-cache\r\n";
#[cfg(feature = "ui")]
const IMMUTABLE: &[u8] = b"Cache-Control: public, max-age=31536000, immutable\r\n";
const SECURITY_HEADERS: &[u8] = b"Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'\r\n\
Strict-Transport-Security: max-age=31536000\r\n\
X-Content-Type-Options: nosniff\r\n\
Referrer-Policy: no-referrer\r\n\
Cross-Origin-Opener-Policy: same-origin\r\n\
Cross-Origin-Resource-Policy: same-origin\r\n\
Permissions-Policy: camera=(), microphone=(), geolocation=(), interest-cohort=()\r\n";

pub struct Request {
    head: Head,
    body: Vec<u8>,
}

#[derive(Default)]
pub struct Out {
    pub body: Vec<u8>,
    pub headers: Vec<u8>,
}

impl Out {
    pub fn clear(&mut self) {
        self.body.clear();
        self.headers.clear();
    }
}

pub enum Stop {
    Reject(Reply),
    Closed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Content {
    Text,
    Json,
    #[cfg(feature = "ui")]
    Static(StaticBody),
    #[cfg(feature = "ui")]
    Redirect(&'static str),
}

#[cfg(feature = "ui")]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StaticBody {
    pub content_type: &'static str,
    pub etag: &'static str,
    pub bytes: &'static [u8],
    pub br: bool,
    pub immutable: bool,
}

impl Content {
    fn mime(self) -> &'static [u8] {
        match self {
            Content::Text => b"text/plain",
            #[cfg(feature = "ui")]
            Content::Redirect(_) => b"text/plain",
            Content::Json => b"application/json",
            #[cfg(feature = "ui")]
            Content::Static(asset) => asset.content_type.as_bytes(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum After {
    KeepAlive,
    Close,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Reply {
    pub status: u16,
    pub content: Content,
    pub after: After,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: ErrorDetail<'a>,
}

#[derive(Serialize)]
struct ErrorDetail<'a> {
    code: &'a str,
    message: &'a str,
}

impl Reply {
    pub fn plain(status: u16) -> Reply {
        Reply {
            status,
            content: Content::Text,
            after: After::KeepAlive,
        }
    }

    pub fn text(body: &mut Vec<u8>, status: u16, text: &str) -> Reply {
        body.extend_from_slice(text.as_bytes());
        Reply::plain(status)
    }

    pub fn json(body: &mut Vec<u8>, status: u16, value: &impl Serialize) -> Reply {
        match serde_json::to_writer(&mut *body, value) {
            Ok(()) => Reply {
                status,
                content: Content::Json,
                after: After::KeepAlive,
            },
            Err(err) => Self::serialize_failed(body, err),
        }
    }

    pub fn json_empty(status: u16) -> Reply {
        Reply {
            status,
            content: Content::Json,
            after: After::KeepAlive,
        }
    }

    #[cold]
    #[inline(never)]
    fn serialize_failed(body: &mut Vec<u8>, err: serde_json::Error) -> Reply {
        tracing::warn!(error = %err, "admin response serialization failed");
        body.clear();
        Reply::error(body, 500, "internal", "internal error")
    }

    pub fn error(body: &mut Vec<u8>, status: u16, code: &str, message: &str) -> Reply {
        Reply::json(
            body,
            status,
            &ErrorBody {
                error: ErrorDetail { code, message },
            },
        )
    }

    #[cfg(feature = "ui")]
    pub fn asset(status: u16, asset: StaticBody) -> Reply {
        Reply {
            status,
            content: Content::Static(asset),
            after: After::KeepAlive,
        }
    }

    #[cfg(feature = "ui")]
    pub fn redirect(location: &'static str) -> Reply {
        Reply {
            status: 302,
            content: Content::Redirect(location),
            after: After::KeepAlive,
        }
    }

    pub fn closing(self) -> Reply {
        Reply {
            after: After::Close,
            ..self
        }
    }
}

impl Request {
    pub fn method(&self) -> Method {
        self.head.method()
    }

    pub fn path(&self) -> &str {
        let path = self.head.path();
        match path.trim_end_matches('/') {
            "" => "/",
            trimmed => trimmed,
        }
    }

    pub fn query_param(&self, key: &str) -> Option<Cow<'_, str>> {
        self.head
            .query()?
            .split('&')
            .filter_map(|pair| pair.split_once('='))
            .find(|(name, _)| *name == key)
            .map(|(_, value)| percent_decode_str(value).decode_utf8_lossy())
    }

    pub fn bearer(&self) -> Option<&[u8]> {
        let value = std::str::from_utf8(self.head.header(HeaderKind::Authorization)?).ok()?;
        let (scheme, token) = value.split_once(' ')?;
        scheme
            .eq_ignore_ascii_case("bearer")
            .then(|| token.trim().as_bytes())
    }

    pub fn wants_close(&self) -> bool {
        self.head.flags().close
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn header(&self, name: &[u8]) -> Option<&str> {
        self.head
            .values_named(HeaderKind::Other, name)
            .next()
            .and_then(|value| std::str::from_utf8(value).ok())
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.head
            .values(HeaderKind::Cookie)
            .filter_map(|value| std::str::from_utf8(value).ok())
            .flat_map(|value| value.split(';'))
            .filter_map(|pair| pair.trim().split_once('='))
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value)
    }

    #[cfg(feature = "ui")]
    pub fn accepts_br(&self) -> bool {
        self.list_values(b"accept-encoding").any(|item| {
            let mut params = item.split(';').map(str::trim);
            params.next().is_some_and(|coding| coding.eq_ignore_ascii_case("br"))
                && params.all(|param| !matches!(param.split_once('='), Some((q, "0" | "0.0" | "0.00" | "0.000")) if q.trim().eq_ignore_ascii_case("q")))
        })
    }

    #[cfg(feature = "ui")]
    pub fn matches_etag(&self, etag: &str) -> bool {
        self.list_values(b"if-none-match")
            .any(|item| item == etag || item == "*" || item.strip_prefix("W/") == Some(etag))
    }

    #[cfg(feature = "ui")]
    fn list_values<'s>(&'s self, name: &'s [u8]) -> impl Iterator<Item = &'s str> {
        self.head
            .values_named(HeaderKind::Other, name)
            .filter_map(|value| std::str::from_utf8(value).ok())
            .flat_map(|value| value.split(','))
            .map(str::trim)
    }
}

pub async fn close(stream: &mut (impl AsyncWrite + Unpin)) {
    let _ = timeout(WRITE_TIMEOUT, stream.shutdown()).await;
}

async fn send(stream: &mut (impl AsyncWrite + Unpin), bytes: &[u8]) -> Result<()> {
    timeout(WRITE_TIMEOUT, async {
        stream.write_all(bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| ProxyError::timeout(Stage::Relay, Side::Client))?
    .map_err(|err| ProxyError::io(Stage::Relay, Side::Client, err))
}

impl Request {
    pub async fn read<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut S,
        reader: &mut Reader,
        reply_body: &mut Vec<u8>,
        max_body: usize,
        wait: Duration,
    ) -> std::result::Result<Request, Stop> {
        let deadline = Instant::now() + wait;
        let head = loop {
            match reader.parse_head(MAX_HEAD, MessageKind::Request) {
                Ok(Some(head)) => break head,
                Ok(None) => {}
                Err(err) => {
                    return Err(Stop::reject(
                        reply_body,
                        err.status(),
                        "bad_request",
                        "malformed request",
                    ));
                }
            }
            if reader.is_eof() {
                return Err(match reader.is_empty() {
                    true => Stop::Closed,
                    false => Stop::reject(reply_body, 400, "bad_request", "truncated request"),
                });
            }
            if reader.fill_until(stream, deadline).await.is_err() {
                return Err(Stop::Closed);
            }
        };
        let length = match head.framing() {
            BodyFraming::None => 0,
            BodyFraming::Length(length) => wire_len(length),
            BodyFraming::Chunked | BodyFraming::UntilClose => {
                return Err(Stop::reject(
                    reply_body,
                    411,
                    "length_required",
                    "length required",
                ));
            }
        };
        if length > max_body {
            return Err(Stop::reject(
                reply_body,
                413,
                "payload_too_large",
                "payload too large",
            ));
        }
        if length > 0
            && head.flags().expect_continue
            && reader.data().len() < length
            && send(stream, CONTINUE).await.is_err()
        {
            return Err(Stop::Closed);
        }
        while reader.data().len() < length {
            if reader.is_eof() || reader.fill_until(stream, deadline).await.is_err() {
                return Err(Stop::Closed);
            }
        }
        let body = reader
            .data()
            .get(..length)
            .map(<[u8]>::to_vec)
            .unwrap_or_default();
        reader.consume(length);
        Ok(Request { head, body })
    }
}

impl Stop {
    fn reject(reply_body: &mut Vec<u8>, status: u16, code: &str, message: &str) -> Stop {
        Stop::Reject(Reply::error(reply_body, status, code, message).closing())
    }
}

impl Reader {
    async fn fill_until(
        &mut self,
        stream: &mut (impl AsyncRead + Unpin),
        deadline: Instant,
    ) -> Result<usize> {
        let left = deadline.saturating_duration_since(Instant::now());
        self.fill(stream, left).await
    }
}

impl Reply {
    pub async fn write_to<S: AsyncWrite + Unpin>(
        self,
        stream: &mut S,
        head: &mut Vec<u8>,
        out: &Out,
    ) -> Result<()> {
        head.clear();
        let _ = write!(
            head,
            "HTTP/1.1 {} {}\r\n",
            self.status,
            reason_phrase(self.status)
        );
        let body = match self.content {
            #[cfg(feature = "ui")]
            Content::Static(asset) => asset.bytes,
            _ => &out.body,
        };
        if self.status != NOT_MODIFIED && self.status != NO_CONTENT {
            head.extend_from_slice(b"Content-Type: ");
            head.extend_from_slice(self.content.mime());
            let _ = write!(head, "\r\nContent-Length: {}\r\n", body.len());
        }
        head.extend_from_slice(match self.after {
            After::KeepAlive => b"Connection: keep-alive\r\n",
            After::Close => b"Connection: close\r\n",
        });
        match self.content {
            #[cfg(feature = "ui")]
            Content::Static(asset) => {
                head.extend_from_slice(if asset.immutable { IMMUTABLE } else { NO_CACHE });
                head.extend_from_slice(b"ETag: ");
                head.extend_from_slice(asset.etag.as_bytes());
                head.extend_from_slice(b"\r\nVary: Accept-Encoding\r\n");
                if asset.br {
                    head.extend_from_slice(b"Content-Encoding: br\r\n");
                }
            }
            #[cfg(feature = "ui")]
            Content::Redirect(location) => {
                head.extend_from_slice(NO_STORE);
                head.extend_from_slice(b"Location: ");
                head.extend_from_slice(location.as_bytes());
                head.extend_from_slice(b"\r\n");
            }
            Content::Text | Content::Json => head.extend_from_slice(NO_STORE),
        }
        head.extend_from_slice(&out.headers);
        head.extend_from_slice(SECURITY_HEADERS);
        head.extend_from_slice(b"\r\n");
        timeout(WRITE_TIMEOUT, async {
            stream.write_all(head).await?;
            stream.write_all(body).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| ProxyError::timeout(Stage::Relay, Side::Client))?
        .map_err(|err| ProxyError::io(Stage::Relay, Side::Client, err))
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/admin/http/tests.rs"]
mod tests;
