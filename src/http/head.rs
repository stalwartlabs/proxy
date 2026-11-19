/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use memchr::{memchr, memchr_iter, memchr2};
use smallvec::SmallVec;

const MAX_HEADERS: usize = 100;
const INLINE_HEADERS: usize = 24;
const SPAN_LIMIT: usize = u32::MAX as usize;
const HTTP_11: &[u8] = b"HTTP/1.1";
const HTTP_1_PREFIX: &[u8] = b"HTTP/1.";
const CHUNKED: &[u8] = b"chunked";
const EVENT_STREAM: &[u8] = b"text/event-stream";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyFraming {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Trace,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    ContentLength,
    TransferEncoding,
    Host,
    Connection,
    Upgrade,
    Expect,
    Authorization,
    ContentType,
    Cookie,
    Forwarded,
    XForwardedFor,
    HopByHop,
    Other,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Span {
    start: u32,
    end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub(super) name: Span,
    pub(super) value: Span,
    pub(super) kind: HeaderKind,
    pub(super) drop: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StartLine {
    Request {
        method: Method,
        method_span: Span,
        target: Span,
    },
    Response {
        status: u16,
        reason: Span,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionToken {
    Close,
    Upgrade,
}

impl ConnectionToken {
    fn parse(token: &[u8]) -> Option<ConnectionToken> {
        hashify::map_ignore_case!(
            token,
            ConnectionToken,
            "close" => ConnectionToken::Close,
            "upgrade" => ConnectionToken::Upgrade,
        )
        .copied()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeadFlags {
    pub close: bool,
    pub websocket: bool,
    pub expect_continue: bool,
    pub sse: bool,
    pub te_codings: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub(super) raw: Box<[u8]>,
    pub(super) line: StartLine,
    pub(super) headers: SmallVec<[Header; INLINE_HEADERS]>,
    pub(super) framing: BodyFraming,
    pub(super) flags: HeadFlags,
}

const _: () = assert!(size_of::<Head>() <= 560);

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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HeadScan {
    line_start: usize,
    pos: usize,
    lines: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Head,
    Trailers,
}

#[derive(Debug, Clone, Copy)]
pub struct Trailers<'a> {
    raw: &'a [u8],
}

impl<'a> Trailers<'a> {
    pub fn wire_len(&self) -> usize {
        self.raw.len()
    }

    pub fn fields(
        &self,
    ) -> impl Iterator<Item = Result<(&'a [u8], &'a [u8], HeaderKind), ParseError>> {
        let raw = self.raw;
        Span::lines(raw)
            .take_while(|span| !span.is_empty())
            .map(move |span| {
                Header::parse(raw, span)
                    .map(|header| (header.name.slice(raw), header.value.slice(raw), header.kind))
            })
    }
}

#[derive(Default)]
struct TransferCodings {
    seen: bool,
    chunked: u32,
    last_chunked: bool,
    other: bool,
}

static TCHAR: [bool; 256] = tchar_table();

const fn tchar_table() -> [bool; 256] {
    let mut table = [false; 256];
    let mut byte = 0u8;
    loop {
        table[byte as usize] = byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            );
        if byte == u8::MAX {
            break;
        }
        byte += 1;
    }
    table
}

fn is_token(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|&b| TCHAR[usize::from(b)])
}

fn is_field_content(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

fn is_ows(byte: &u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn ows_bounds(bytes: &[u8]) -> (usize, usize) {
    let start = bytes.iter().position(|b| !is_ows(b)).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !is_ows(b))
        .map_or(start, |p| p + 1);
    (start, end)
}

pub(super) fn trim_ows(bytes: &[u8]) -> &[u8] {
    let (start, end) = ows_bounds(bytes);
    bytes.get(start..end).unwrap_or_default()
}

pub(super) fn list_items(value: &[u8]) -> impl Iterator<Item = &[u8]> {
    value
        .split(|&b| b == b',')
        .map(trim_ows)
        .filter(|item| !item.is_empty())
}

fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u64, |acc, &b| {
        if b.is_ascii_digit() {
            acc.checked_mul(10)?.checked_add(u64::from(b - b'0'))
        } else {
            None
        }
    })
}

fn status_has_no_body(status: u16) -> bool {
    (100..200).contains(&status) || matches!(status, 204 | 304)
}

impl Span {
    fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= SPAN_LIMIT && end <= SPAN_LIMIT);
        Span {
            start: start.min(SPAN_LIMIT) as u32,
            end: end.min(SPAN_LIMIT) as u32,
        }
    }

    fn offset(self, base: usize) -> Self {
        Span::new(self.start as usize + base, self.end as usize + base)
    }

    pub fn is_empty(self) -> bool {
        self.start >= self.end
    }

    pub fn slice(self, raw: &[u8]) -> &[u8] {
        raw.get(self.start as usize..self.end as usize)
            .unwrap_or_default()
    }
}

impl Method {
    fn parse(bytes: &[u8]) -> Method {
        hashify::map!(
            bytes,
            Method,
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "PATCH" => Method::Patch,
            "DELETE" => Method::Delete,
            "OPTIONS" => Method::Options,
            "TRACE" => Method::Trace,
        )
        .copied()
        .unwrap_or(Method::Other)
    }
}

impl HeaderKind {
    pub fn classify(name: &[u8]) -> HeaderKind {
        hashify::map_ignore_case!(
            name,
            HeaderKind,
            "content-length" => HeaderKind::ContentLength,
            "transfer-encoding" => HeaderKind::TransferEncoding,
            "host" => HeaderKind::Host,
            "connection" => HeaderKind::Connection,
            "upgrade" => HeaderKind::Upgrade,
            "expect" => HeaderKind::Expect,
            "authorization" => HeaderKind::Authorization,
            "content-type" => HeaderKind::ContentType,
            "cookie" => HeaderKind::Cookie,
            "forwarded" => HeaderKind::Forwarded,
            "x-forwarded-for" => HeaderKind::XForwardedFor,
            "keep-alive" => HeaderKind::HopByHop,
            "te" => HeaderKind::HopByHop,
            "proxy-connection" => HeaderKind::HopByHop,
            "trailer" => HeaderKind::HopByHop,
            "proxy-authenticate" => HeaderKind::HopByHop,
            "proxy-authorization" => HeaderKind::HopByHop,
        )
        .copied()
        .unwrap_or(HeaderKind::Other)
    }

    pub fn is_single_name(self) -> bool {
        !matches!(self, HeaderKind::HopByHop | HeaderKind::Other)
    }

    pub fn is_never_forwarded(self) -> bool {
        matches!(
            self,
            HeaderKind::ContentLength
                | HeaderKind::TransferEncoding
                | HeaderKind::Connection
                | HeaderKind::Upgrade
                | HeaderKind::HopByHop
        )
    }
}

impl Header {
    pub(super) fn parse(raw: &[u8], line: Span) -> Result<Header, ParseError> {
        let bytes = line.slice(raw);
        if bytes.first().is_some_and(is_ows) {
            return Err(ParseError::BadRequest);
        }
        let colon = memchr(b':', bytes).ok_or(ParseError::BadRequest)?;
        let name = bytes.get(..colon).unwrap_or_default();
        let value = bytes.get(colon + 1..).unwrap_or_default();
        if !is_token(name) {
            return Err(ParseError::BadRequest);
        }
        let (start, end) = ows_bounds(value);
        let trimmed = value.get(start..end).unwrap_or_default();
        if !is_field_content(trimmed) {
            return Err(ParseError::BadRequest);
        }
        let base = line.start as usize;
        let value_base = base + colon + 1;
        Ok(Header {
            name: Span::new(base, base + colon),
            value: Span::new(value_base + start, value_base + end),
            kind: HeaderKind::classify(name),
            drop: false,
        })
    }
}

impl TransferCodings {
    fn observe(&mut self, value: &[u8]) -> Result<(), ParseError> {
        self.seen = true;
        for coding in list_items(value) {
            if coding.eq_ignore_ascii_case(CHUNKED) {
                self.chunked += 1;
                self.last_chunked = true;
            } else if is_token(coding) {
                self.other = true;
                self.last_chunked = false;
            } else {
                return Err(ParseError::BadRequest);
            }
        }
        Ok(())
    }

    fn validate(&self, kind: MessageKind) -> Result<(), ParseError> {
        if !self.seen {
            return Ok(());
        }
        if !self.last_chunked || self.chunked != 1 {
            return Err(ParseError::BadRequest);
        }
        if kind == MessageKind::Request && self.other {
            return Err(ParseError::BadRequest);
        }
        Ok(())
    }
}

impl Section {
    fn max_lines(self) -> usize {
        match self {
            Section::Head => MAX_HEADERS + 1,
            Section::Trailers => MAX_HEADERS,
        }
    }
}

impl HeadScan {
    pub fn trailers<'a>(
        &mut self,
        buf: &'a [u8],
        max_size: usize,
    ) -> Result<Option<Trailers<'a>>, ParseError> {
        let scanned = self.scan_inner(buf, max_size.min(SPAN_LIMIT), Section::Trailers);
        if !matches!(scanned, Ok(None)) {
            *self = HeadScan::default();
        }
        let Some(end) = scanned? else {
            return Ok(None);
        };
        let raw = buf.get(..end).ok_or(ParseError::BadRequest)?;
        Ok(Some(Trailers { raw }))
    }

    fn scan_inner(
        &mut self,
        buf: &[u8],
        max: usize,
        section: Section,
    ) -> Result<Option<usize>, ParseError> {
        loop {
            let rest = buf.get(self.pos..).ok_or(ParseError::BadRequest)?;
            let Some(found) = memchr2(b'\r', b'\n', rest) else {
                self.pos = buf.len();
                return if buf.len() > max {
                    Err(ParseError::TooLarge)
                } else {
                    Ok(None)
                };
            };
            let cr = self.pos + found;
            match rest.get(found..).unwrap_or_default() {
                [b'\r', b'\n', ..] => {}
                [b'\r'] => {
                    self.pos = cr;
                    return if buf.len() > max {
                        Err(ParseError::TooLarge)
                    } else {
                        Ok(None)
                    };
                }
                _ => return Err(ParseError::BadRequest),
            }
            let next = cr + 2;
            if next > max {
                return Err(ParseError::TooLarge);
            }
            if cr == self.line_start {
                return if cr == 0 && section == Section::Head {
                    Err(ParseError::BadRequest)
                } else {
                    Ok(Some(next))
                };
            }
            self.lines += 1;
            if self.lines > section.max_lines() {
                return Err(ParseError::TooLarge);
            }
            self.line_start = next;
            self.pos = next;
        }
    }

    pub fn parse(
        &mut self,
        buf: &[u8],
        max_head_size: usize,
        kind: MessageKind,
    ) -> Result<Option<Head>, ParseError> {
        let scanned = self.scan_inner(buf, max_head_size.min(SPAN_LIMIT), Section::Head);
        let header_lines = self.lines.saturating_sub(1);
        if !matches!(scanned, Ok(None)) {
            *self = HeadScan::default();
        }
        let Some(end) = scanned? else {
            return Ok(None);
        };
        let raw = buf.get(..end).ok_or(ParseError::BadRequest)?;
        Head::from_raw(raw.into(), kind, header_lines).map(Some)
    }
}

impl Head {
    fn from_raw(
        raw: Box<[u8]>,
        kind: MessageKind,
        header_lines: usize,
    ) -> Result<Head, ParseError> {
        let mut lines = Span::lines(&raw);
        let first = lines.next().ok_or(ParseError::BadRequest)?;
        let line = match kind {
            MessageKind::Request => StartLine::parse_request(&raw, first)?,
            MessageKind::Response => StartLine::parse_response(&raw, first)?,
        };

        let mut headers = SmallVec::<[Header; INLINE_HEADERS]>::with_capacity(header_lines);
        let mut content_length: Option<u64> = None;
        let mut codings = TransferCodings::default();
        let mut hosts = 0u32;
        let mut authorizations = 0u32;
        for span in lines.take_while(|span| !span.is_empty()) {
            if headers.len() == MAX_HEADERS {
                return Err(ParseError::TooLarge);
            }
            let header = Header::parse(&raw, span)?;
            let value = header.value.slice(&raw);
            match header.kind {
                HeaderKind::ContentLength => {
                    let parsed = parse_decimal(value).ok_or(ParseError::BadRequest)?;
                    if content_length.is_some_and(|existing| existing != parsed) {
                        return Err(ParseError::BadRequest);
                    }
                    content_length = Some(parsed);
                }
                HeaderKind::TransferEncoding => codings.observe(value)?,
                HeaderKind::Host => hosts += 1,
                HeaderKind::Authorization => authorizations += 1,
                _ => {}
            }
            headers.push(header);
        }

        if codings.seen && content_length.is_some() {
            return Err(ParseError::BadRequest);
        }
        if kind == MessageKind::Request && (hosts != 1 || authorizations > 1) {
            return Err(ParseError::BadRequest);
        }
        let no_body =
            matches!(line, StartLine::Response { status, .. } if status_has_no_body(status));
        if !no_body {
            codings.validate(kind)?;
        }

        let framing = match line {
            _ if no_body => BodyFraming::None,
            _ if codings.seen => BodyFraming::Chunked,
            _ => match (content_length, kind) {
                (Some(length), _) => BodyFraming::Length(length),
                (None, MessageKind::Response) => BodyFraming::UntilClose,
                (None, MessageKind::Request) => BodyFraming::None,
            },
        };

        let mut flags = HeadFlags {
            te_codings: codings.other && framing == BodyFraming::Chunked,
            ..HeadFlags::default()
        };
        let mut upgrade_token = false;
        let mut tokens = 0usize;
        let connection_values: SmallVec<[Span; 2]> = headers
            .iter()
            .filter(|h| h.kind == HeaderKind::Connection)
            .map(|h| h.value)
            .collect();
        for token in connection_values
            .iter()
            .flat_map(|span| list_items(span.slice(&raw)))
        {
            tokens += 1;
            if tokens > MAX_HEADERS {
                return Err(ParseError::BadRequest);
            }
            match ConnectionToken::parse(token) {
                Some(ConnectionToken::Close) => flags.close = true,
                Some(ConnectionToken::Upgrade) => upgrade_token = true,
                None => {}
            }
            let token_kind = HeaderKind::classify(token);
            if token_kind.is_never_forwarded() {
                continue;
            }
            if token_kind == HeaderKind::Host && kind == MessageKind::Request {
                return Err(ParseError::BadRequest);
            }
            for header in headers.iter_mut().filter(|h| h.kind == token_kind) {
                if token_kind.is_single_name()
                    || header.name.slice(&raw).eq_ignore_ascii_case(token)
                {
                    header.drop = true;
                }
            }
        }

        let first_value = |kind: HeaderKind| {
            headers
                .iter()
                .find(|h| h.kind == kind)
                .map(|h| h.value.slice(&raw))
        };
        flags.websocket = upgrade_token
            && first_value(HeaderKind::Upgrade)
                .is_some_and(|v| v.eq_ignore_ascii_case(b"websocket"));
        flags.expect_continue = first_value(HeaderKind::Expect)
            .is_some_and(|v| v.eq_ignore_ascii_case(b"100-continue"));
        flags.sse = first_value(HeaderKind::ContentType).is_some_and(|v| {
            v.get(..EVENT_STREAM.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(EVENT_STREAM))
        });

        Ok(Head {
            raw,
            line,
            headers,
            framing,
            flags,
        })
    }

    pub fn method(&self) -> Method {
        match self.line {
            StartLine::Request { method, .. } => method,
            StartLine::Response { .. } => Method::Other,
        }
    }

    pub fn target(&self) -> &str {
        match self.line {
            StartLine::Request { target, .. } => {
                std::str::from_utf8(target.slice(&self.raw)).unwrap_or_default()
            }
            StartLine::Response { .. } => "",
        }
    }

    pub fn path(&self) -> &str {
        let target = self.target();
        target.split_once('?').map_or(target, |(path, _)| path)
    }

    pub fn query(&self) -> Option<&str> {
        self.target().split_once('?').map(|(_, query)| query)
    }

    pub fn status(&self) -> u16 {
        match self.line {
            StartLine::Response { status, .. } => status,
            StartLine::Request { .. } => 0,
        }
    }

    pub fn framing(&self) -> BodyFraming {
        self.framing
    }

    pub fn flags(&self) -> HeadFlags {
        self.flags
    }

    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub fn header(&self, kind: HeaderKind) -> Option<&[u8]> {
        self.values(kind).next()
    }

    pub fn values(&self, kind: HeaderKind) -> impl Iterator<Item = &[u8]> {
        self.headers
            .iter()
            .filter(move |h| h.kind == kind && !h.drop)
            .map(|h| h.value.slice(&self.raw))
    }

    pub fn values_named<'s, 'n>(
        &'s self,
        kind: HeaderKind,
        name: &'n [u8],
    ) -> impl Iterator<Item = &'s [u8]> + use<'s, 'n> {
        self.headers
            .iter()
            .filter(move |h| {
                h.kind == kind
                    && !h.drop
                    && (kind.is_single_name() || h.name.slice(&self.raw).eq_ignore_ascii_case(name))
            })
            .map(|h| h.value.slice(&self.raw))
    }

    pub fn drop_kind(&mut self, kind: HeaderKind) {
        for header in self.headers.iter_mut().filter(|h| h.kind == kind) {
            header.drop = true;
        }
        if kind == HeaderKind::Expect {
            self.flags.expect_continue = false;
        }
    }
}

impl StartLine {
    fn parse_request(raw: &[u8], line: Span) -> Result<StartLine, ParseError> {
        let bytes = line.slice(raw);
        let first_space = memchr(b' ', bytes).ok_or(ParseError::BadRequest)?;
        let method = bytes.get(..first_space).unwrap_or_default();
        let rest = bytes.get(first_space + 1..).unwrap_or_default();
        let second_space = memchr(b' ', rest).ok_or(ParseError::BadRequest)?;
        let target = rest.get(..second_space).unwrap_or_default();
        let version = rest.get(second_space + 1..).unwrap_or_default();
        if !is_token(method)
            || target.is_empty()
            || target.iter().any(|&b| b <= b' ' || b == 0x7f)
            || std::str::from_utf8(target).is_err()
            || memchr(b' ', version).is_some()
        {
            return Err(ParseError::BadRequest);
        }
        if version != HTTP_11 {
            return Err(ParseError::VersionNotSupported);
        }
        if method.eq_ignore_ascii_case(b"CONNECT") {
            return Err(ParseError::MethodNotAllowed);
        }
        let base = line.start as usize;
        let target_start = first_space + 1;
        Ok(StartLine::Request {
            method: Method::parse(method),
            method_span: Span::new(base, base + first_space),
            target: Span::new(base + target_start, base + target_start + second_space),
        })
    }

    fn parse_response(raw: &[u8], line: Span) -> Result<StartLine, ParseError> {
        let bytes = line.slice(raw);
        let first_space = memchr(b' ', bytes).ok_or(ParseError::BadRequest)?;
        let version = bytes.get(..first_space).unwrap_or_default();
        let rest = bytes.get(first_space + 1..).unwrap_or_default();
        if !version.starts_with(HTTP_1_PREFIX) {
            return Err(ParseError::BadRequest);
        }
        let (code, reason) = match memchr(b' ', rest) {
            Some(space) => (
                rest.get(..space).unwrap_or_default(),
                Span::new(first_space + 1 + space + 1, bytes.len()),
            ),
            None => (rest, Span::new(bytes.len(), bytes.len())),
        };
        let status = match code {
            [a, b, c] if code.iter().all(u8::is_ascii_digit) => {
                u16::from(a - b'0') * 100 + u16::from(b - b'0') * 10 + u16::from(c - b'0')
            }
            _ => return Err(ParseError::BadRequest),
        };
        if !(100..=599).contains(&status) || !is_field_content(reason.slice(bytes)) {
            return Err(ParseError::BadRequest);
        }
        Ok(StartLine::Response {
            status,
            reason: reason.offset(line.start as usize),
        })
    }
}

impl Span {
    fn lines(raw: &[u8]) -> impl Iterator<Item = Span> + use<'_> {
        let mut line_start = 0usize;
        memchr_iter(b'\n', raw).map(move |newline| {
            let span = Span::new(line_start, newline.saturating_sub(1));
            line_start = newline + 1;
            span
        })
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/http/head/tests.rs"]
mod tests;

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/http/head/test_support.rs"]
mod test_support;
