/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

const MAX_HEADERS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnFlags {
    pub is_websocket_upgrade: bool,
    pub close: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "upgrade",
    "proxy-connection",
    "trailer",
    "proxy-authenticate",
    "proxy-authorization",
];

fn is_hop_by_hop(name: &str) -> bool {
    HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub is_response: bool,
    pub method: String,
    pub target: String,
    pub version: String,
    pub status: u16,
    pub reason: String,
    pub headers: Vec<Header>,
    pub framing: BodyFraming,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    BadRequest,
    MethodNotAllowed,
    TooLarge,
    VersionNotSupported,
}

impl ParseError {
    pub fn status(self) -> u16 {
        match self {
            ParseError::BadRequest => 400,
            ParseError::MethodNotAllowed => 405,
            ParseError::TooLarge => 431,
            ParseError::VersionNotSupported => 505,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseOutcome {
    NeedMore,
    Done { head: Head, consumed: usize },
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn reject_bare_cr_lf(head: &[u8]) -> bool {
    let mut i = 0;
    while i < head.len() {
        match head[i] {
            b'\r' => {
                if head.get(i + 1) != Some(&b'\n') {
                    return true;
                }
                i += 2;
            }
            b'\n' => return true,
            _ => i += 1,
        }
    }
    false
}

fn split_lines(head: &[u8]) -> Vec<&[u8]> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < head.len() {
        if head[i] == b'\n' {
            let mut end = i;
            if end > start && head[end - 1] == b'\r' {
                end -= 1;
            }
            lines.push(&head[start..end]);
            start = i + 1;
        }
        i += 1;
    }
    lines
}

fn header_value_has_forbidden(value: &str) -> bool {
    value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n')
}

fn parse_content_length(value: &str) -> std::result::Result<u64, ParseError> {
    value
        .trim()
        .parse::<u64>()
        .map_err(|_| ParseError::BadRequest)
}

fn transfer_encoding_is_chunked(value: &str) -> std::result::Result<bool, ParseError> {
    let codings: Vec<&str> = value
        .split(',')
        .map(|c| c.trim())
        .filter(|c| !c.is_empty())
        .collect();
    if codings.is_empty() {
        return Ok(false);
    }
    let last = codings[codings.len() - 1];
    if last.eq_ignore_ascii_case("chunked") {
        Ok(true)
    } else {
        Err(ParseError::BadRequest)
    }
}

fn status_has_no_body(status: u16) -> bool {
    (100..200).contains(&status) || status == 204 || status == 205 || status == 304
}

impl Head {
    pub fn parse(
        buf: &[u8],
        max_head_size: usize,
    ) -> std::result::Result<ParseOutcome, ParseError> {
        Self::parse_inner(buf, max_head_size, false)
    }

    pub fn parse_response(
        buf: &[u8],
        max_head_size: usize,
    ) -> std::result::Result<ParseOutcome, ParseError> {
        Self::parse_inner(buf, max_head_size, true)
    }

    fn parse_inner(
        buf: &[u8],
        max_head_size: usize,
        is_response: bool,
    ) -> std::result::Result<ParseOutcome, ParseError> {
        let end = match find_head_end(buf) {
            Some(e) => e,
            None => {
                if buf.len() > max_head_size {
                    return Err(ParseError::TooLarge);
                }
                return Ok(ParseOutcome::NeedMore);
            }
        };
        if end > max_head_size {
            return Err(ParseError::TooLarge);
        }

        let head_bytes = &buf[..end];
        if reject_bare_cr_lf(head_bytes) {
            return Err(ParseError::BadRequest);
        }

        let lines = split_lines(head_bytes);
        if lines.is_empty() || lines[0].is_empty() {
            return Err(ParseError::BadRequest);
        }

        let start_line = std::str::from_utf8(lines[0]).map_err(|_| ParseError::BadRequest)?;

        let mut head = if is_response {
            Self::parse_status_line(start_line)?
        } else {
            Self::parse_request_line(start_line)?
        };

        if lines.len() - 1 > MAX_HEADERS {
            return Err(ParseError::TooLarge);
        }

        let mut content_length: Option<u64> = None;
        let mut has_te = false;
        let mut te_chunked = false;
        let mut host_count = 0u32;

        for raw in &lines[1..] {
            if raw.is_empty() {
                continue;
            }
            if raw[0] == b' ' || raw[0] == b'\t' {
                return Err(ParseError::BadRequest);
            }
            let line = std::str::from_utf8(raw).map_err(|_| ParseError::BadRequest)?;
            let (name, value) = match line.split_once(':') {
                Some((n, v)) => (n, v),
                None => return Err(ParseError::BadRequest),
            };
            if name.is_empty() || name.bytes().any(|b| b == b' ' || b == b'\t') {
                return Err(ParseError::BadRequest);
            }
            let value = value.trim();
            if header_value_has_forbidden(value) {
                return Err(ParseError::BadRequest);
            }

            if name.eq_ignore_ascii_case("content-length") {
                let parsed = parse_content_length(value)?;
                if let Some(existing) = content_length {
                    if existing != parsed {
                        return Err(ParseError::BadRequest);
                    }
                } else {
                    content_length = Some(parsed);
                }
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                has_te = true;
                if transfer_encoding_is_chunked(value)? {
                    te_chunked = true;
                }
            } else if name.eq_ignore_ascii_case("host") {
                host_count += 1;
            }

            head.headers.push(Header {
                name: name.to_string(),
                value: value.to_string(),
            });
        }

        if has_te && content_length.is_some() {
            return Err(ParseError::BadRequest);
        }

        if !is_response && host_count != 1 {
            return Err(ParseError::BadRequest);
        }

        head.framing = if is_response && status_has_no_body(head.status) {
            BodyFraming::None
        } else if has_te {
            if !te_chunked {
                return Err(ParseError::BadRequest);
            }
            BodyFraming::Chunked
        } else if let Some(n) = content_length {
            BodyFraming::Length(n)
        } else if is_response {
            BodyFraming::UntilClose
        } else {
            BodyFraming::None
        };

        Ok(ParseOutcome::Done {
            head,
            consumed: end,
        })
    }

    fn parse_request_line(line: &str) -> std::result::Result<Head, ParseError> {
        let mut parts = line.split(' ');
        let method = parts.next().ok_or(ParseError::BadRequest)?;
        let target = parts.next().ok_or(ParseError::BadRequest)?;
        let version = parts.next().ok_or(ParseError::BadRequest)?;
        if parts.next().is_some() {
            return Err(ParseError::BadRequest);
        }
        if method.is_empty() || target.is_empty() {
            return Err(ParseError::BadRequest);
        }
        if target.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(ParseError::BadRequest);
        }
        if version != "HTTP/1.1" {
            return Err(ParseError::VersionNotSupported);
        }
        if method.eq_ignore_ascii_case("CONNECT") {
            return Err(ParseError::MethodNotAllowed);
        }
        Ok(Head {
            is_response: false,
            method: method.to_string(),
            target: target.to_string(),
            version: version.to_string(),
            status: 0,
            reason: String::new(),
            headers: Vec::new(),
            framing: BodyFraming::None,
        })
    }

    fn parse_status_line(line: &str) -> std::result::Result<Head, ParseError> {
        let mut parts = line.splitn(3, ' ');
        let version = parts.next().ok_or(ParseError::BadRequest)?;
        let code = parts.next().ok_or(ParseError::BadRequest)?;
        let reason = parts.next().unwrap_or("");
        if !version.starts_with("HTTP/1.") {
            return Err(ParseError::BadRequest);
        }
        let status = code.parse::<u16>().map_err(|_| ParseError::BadRequest)?;
        if !(100..=599).contains(&status) {
            return Err(ParseError::BadRequest);
        }
        Ok(Head {
            is_response: true,
            method: String::new(),
            target: String::new(),
            version: version.to_string(),
            status,
            reason: reason.to_string(),
            headers: Vec::new(),
            framing: BodyFraming::None,
        })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }

    pub fn set_header(&mut self, name: &str, value: &str) {
        self.headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
        self.headers.push(Header {
            name: name.to_string(),
            value: value.to_string(),
        });
    }

    pub fn remove_header(&mut self, name: &str) {
        self.headers.retain(|h| !h.name.eq_ignore_ascii_case(name));
    }

    pub fn path(&self) -> &str {
        match self.target.split_once('?') {
            Some((p, _)) => p,
            None => self.target.as_str(),
        }
    }

    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, q)| q)
    }

    pub fn conn_flags(&self) -> ConnFlags {
        let tokens = self.connection_tokens();
        let is_websocket_upgrade = self
            .header("upgrade")
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
            && tokens.iter().any(|t| t.eq_ignore_ascii_case("upgrade"));
        let close = tokens.iter().any(|t| t.eq_ignore_ascii_case("close"));
        ConnFlags {
            is_websocket_upgrade,
            close,
        }
    }

    pub fn is_sse(&self) -> bool {
        self.header("content-type").is_some_and(|v| {
            v.trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
        })
    }

    pub fn expects_continue(&self) -> bool {
        self.header("expect")
            .is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
    }

    fn connection_tokens(&self) -> Vec<&str> {
        let mut tokens = Vec::new();
        for h in &self.headers {
            if h.name.eq_ignore_ascii_case("connection") {
                for token in h.value.split(',') {
                    let token = token.trim();
                    if !token.is_empty() {
                        tokens.push(token);
                    }
                }
            }
        }
        tokens
    }

    pub fn serialize(&self, force_close: bool, preserve_upgrade: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        if self.is_response {
            out.extend_from_slice(b"HTTP/1.1 ");
            out.extend_from_slice(self.status.to_string().as_bytes());
            out.push(b' ');
            out.extend_from_slice(self.reason.as_bytes());
            out.extend_from_slice(b"\r\n");
        } else {
            out.extend_from_slice(self.method.as_bytes());
            out.push(b' ');
            out.extend_from_slice(self.target.as_bytes());
            out.extend_from_slice(b" HTTP/1.1\r\n");
        }

        let conn_tokens = self.connection_tokens();

        for header in &self.headers {
            if is_hop_by_hop(&header.name)
                || conn_tokens
                    .iter()
                    .any(|t| header.name.eq_ignore_ascii_case(t))
            {
                continue;
            }
            if header.name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            out.extend_from_slice(header.name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(header.value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }

        match self.framing {
            BodyFraming::Chunked => {
                out.extend_from_slice(b"Transfer-Encoding: chunked\r\n");
            }
            BodyFraming::Length(n) => {
                out.extend_from_slice(b"Content-Length: ");
                out.extend_from_slice(n.to_string().as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            BodyFraming::None | BodyFraming::UntilClose => {}
        }

        if preserve_upgrade {
            if let Some(v) = self.header("upgrade") {
                out.extend_from_slice(b"Upgrade: ");
                out.extend_from_slice(v.as_bytes());
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"Connection: Upgrade\r\n");
        } else if force_close {
            out.extend_from_slice(b"Connection: close\r\n");
        }

        out.extend_from_slice(b"\r\n");
        out
    }
}

pub fn error_response(status: u16, reason: &str) -> Vec<u8> {
    use std::fmt::Write;
    let body = format!("{status} {reason}");
    let mut out = String::with_capacity(body.len() + 96);
    let _ = write!(
        out,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(buf: &[u8]) -> Head {
        match Head::parse(buf, 64 * 1024).unwrap() {
            ParseOutcome::Done { head, .. } => head,
            ParseOutcome::NeedMore => panic!("need more"),
        }
    }

    #[test]
    fn parse_simple_get() {
        let buf = b"GET /foo?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let head = done(buf);
        assert!(!head.is_response);
        assert_eq!(head.method, "GET");
        assert_eq!(head.target, "/foo?x=1");
        assert_eq!(head.path(), "/foo");
        assert_eq!(head.query(), Some("x=1"));
        assert_eq!(head.header("host"), Some("example.com"));
        assert_eq!(head.framing, BodyFraming::None);
    }

    #[test]
    fn need_more_until_crlfcrlf() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n";
        assert!(matches!(
            Head::parse(buf, 64 * 1024).unwrap(),
            ParseOutcome::NeedMore
        ));
    }

    #[test]
    fn reject_te_and_cl() {
        let buf = b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert_eq!(Head::parse(buf, 64 * 1024), Err(ParseError::BadRequest));
    }

    #[test]
    fn reject_double_conflicting_cl() {
        let buf = b"POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
        assert_eq!(Head::parse(buf, 64 * 1024), Err(ParseError::BadRequest));
    }

    #[test]
    fn accept_duplicate_equal_cl() {
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n";
        let head = done(buf);
        assert_eq!(head.framing, BodyFraming::Length(5));
    }

    #[test]
    fn reject_te_not_chunked() {
        let buf = b"POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert_eq!(Head::parse(buf, 64 * 1024), Err(ParseError::BadRequest));
    }

    #[test]
    fn accept_te_gzip_then_chunked() {
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        let head = done(buf);
        assert_eq!(head.framing, BodyFraming::Chunked);
    }

    #[test]
    fn reject_bare_lf() {
        let buf = b"GET / HTTP/1.1\nHost: x\r\n\r\n";
        assert_eq!(Head::parse(buf, 64 * 1024), Err(ParseError::BadRequest));
    }

    #[test]
    fn reject_nul_in_value() {
        let buf = b"GET / HTTP/1.1\r\nHost: a\x00b\r\n\r\n";
        assert_eq!(Head::parse(buf, 64 * 1024), Err(ParseError::BadRequest));
    }

    #[test]
    fn reject_obs_fold() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n more\r\n\r\n";
        assert_eq!(Head::parse(buf, 64 * 1024), Err(ParseError::BadRequest));
    }

    #[test]
    fn reject_connect() {
        let buf = b"CONNECT example.com:443 HTTP/1.1\r\n\r\n";
        assert_eq!(
            Head::parse(buf, 64 * 1024),
            Err(ParseError::MethodNotAllowed)
        );
    }

    #[test]
    fn reject_missing_host() {
        let buf = b"GET / HTTP/1.1\r\n\r\n";
        assert_eq!(Head::parse(buf, 64 * 1024), Err(ParseError::BadRequest));
    }

    #[test]
    fn reject_duplicate_host() {
        let buf = b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n";
        assert_eq!(Head::parse(buf, 64 * 1024), Err(ParseError::BadRequest));
    }

    #[test]
    fn reject_control_in_target() {
        let buf = b"GET /a\x01b HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(Head::parse(buf, 64 * 1024), Err(ParseError::BadRequest));
    }

    #[test]
    fn serialize_strips_hop_by_hop() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive, X-Drop\r\nKeep-Alive: timeout=5\r\nX-Drop: secret\r\nX-Keep: yes\r\n\r\n";
        let head = done(buf);
        let out = head.serialize(false, false);
        let text = String::from_utf8(out).unwrap();
        assert!(!text.to_lowercase().contains("keep-alive"));
        assert!(!text.contains("X-Drop"));
        assert!(!text.to_lowercase().contains("connection:"));
        assert!(text.contains("X-Keep: yes"));
        assert!(text.contains("Host: x"));
    }

    #[test]
    fn serialize_single_framing_header() {
        let buf = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\n";
        let head = done(buf);
        let text = String::from_utf8(head.serialize(false, false)).unwrap();
        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert!(text.contains("Content-Length: 3"));
    }

    #[test]
    fn serialize_force_close() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let head = done(buf);
        let text = String::from_utf8(head.serialize(true, false)).unwrap();
        assert!(text.contains("Connection: close"));
    }

    #[test]
    fn response_until_close() {
        let buf = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n";
        let head = match Head::parse_response(buf, 64 * 1024).unwrap() {
            ParseOutcome::Done { head, .. } => head,
            _ => panic!(),
        };
        assert_eq!(head.framing, BodyFraming::UntilClose);
    }

    #[test]
    fn response_204_no_body() {
        let buf = b"HTTP/1.1 204 No Content\r\n\r\n";
        let head = match Head::parse_response(buf, 64 * 1024).unwrap() {
            ParseOutcome::Done { head, .. } => head,
            _ => panic!(),
        };
        assert_eq!(head.framing, BodyFraming::None);
    }

    #[test]
    fn websocket_detection() {
        let buf =
            b"GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        let head = done(buf);
        assert!(head.conn_flags().is_websocket_upgrade);
    }
}
