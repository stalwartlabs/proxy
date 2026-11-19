/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::fmt;
use std::net::IpAddr;

use crate::runtime::health::Attribution;

pub type Result<T> = std::result::Result<T, ProxyError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Config,
    Accept,
    ProxyHeader,
    InboundTls,
    Preauth,
    Dns,
    Connect,
    BackendTls,
    Greeting,
    Starttls,
    Forwarding,
    Auth,
    Relay,
    Admin,
    Store,
}

impl Stage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Stage::Config => "config",
            Stage::Accept => "accept",
            Stage::ProxyHeader => "proxy_header",
            Stage::InboundTls => "inbound_tls",
            Stage::Preauth => "preauth",
            Stage::Dns => "dns",
            Stage::Connect => "connect",
            Stage::BackendTls => "backend_tls",
            Stage::Greeting => "greeting",
            Stage::Starttls => "starttls",
            Stage::Forwarding => "forwarding",
            Stage::Auth => "auth",
            Stage::Relay => "relay",
            Stage::Admin => "admin",
            Stage::Store => "store",
        }
    }

    const fn is_establishment(self) -> bool {
        matches!(
            self,
            Stage::Dns
                | Stage::Connect
                | Stage::BackendTls
                | Stage::Greeting
                | Stage::Starttls
                | Stage::Forwarding
                | Stage::Auth
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Backend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Line,
    Request,
    Literal,
    Token,
    Head,
    Headers,
    Body,
    Chunk,
    Trailers,
    Reply,
    RoutingKey,
    Connections,
}

impl Limit {
    pub const fn as_str(self) -> &'static str {
        match self {
            Limit::Line => "line",
            Limit::Request => "request",
            Limit::Literal => "literal",
            Limit::Token => "token",
            Limit::Head => "head",
            Limit::Headers => "headers",
            Limit::Body => "body",
            Limit::Chunk => "chunk",
            Limit::Trailers => "trailers",
            Limit::Reply => "reply",
            Limit::RoutingKey => "routing key",
            Limit::Connections => "connections",
        }
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    Io(std::io::Error),
    Tls(Box<rustls::Error>),
    Protocol(Cow<'static, str>),
    Timeout,
    Closed,
    LimitExceeded(Limit),
    Unavailable(Cow<'static, str>),
    Store(Cow<'static, str>),
    Config(Cow<'static, str>),
}

#[derive(Debug)]
pub struct ProxyError {
    pub stage: Stage,
    pub side: Side,
    pub kind: ErrorKind,
}

const _: () = assert!(size_of::<ProxyError>() <= 40);

impl ProxyError {
    #[cold]
    pub fn new(stage: Stage, side: Side, kind: ErrorKind) -> Self {
        ProxyError { stage, side, kind }
    }

    #[cold]
    pub fn io(stage: Stage, side: Side, err: std::io::Error) -> Self {
        Self::new(stage, side, ErrorKind::Io(err))
    }

    #[cold]
    pub fn timeout(stage: Stage, side: Side) -> Self {
        Self::new(stage, side, ErrorKind::Timeout)
    }

    #[cold]
    pub fn limit(stage: Stage, side: Side, limit: Limit) -> Self {
        Self::new(stage, side, ErrorKind::LimitExceeded(limit))
    }

    #[cold]
    pub fn unavailable(stage: Stage, msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(stage, Side::Backend, ErrorKind::Unavailable(msg.into()))
    }

    #[cold]
    pub fn store(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Stage::Store, Side::Backend, ErrorKind::Store(msg.into()))
    }

    #[cold]
    pub fn closed() -> Self {
        Self::new(Stage::Relay, Side::Client, ErrorKind::Closed)
    }

    #[cold]
    pub fn config(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Stage::Config, Side::Client, ErrorKind::Config(msg.into()))
    }

    #[cold]
    pub fn tls(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            Stage::InboundTls,
            Side::Client,
            ErrorKind::Tls(Box::new(rustls::Error::General(msg.into().into_owned()))),
        )
    }

    #[cold]
    pub fn backend(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::unavailable(Stage::Greeting, msg)
    }

    #[cold]
    pub fn backend_connect(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::io(Stage::Connect, Side::Backend, io_other(msg.into()))
    }

    #[cold]
    pub fn backend_session(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::io(Stage::Greeting, Side::Backend, io_other(msg.into()))
    }

    #[cold]
    pub fn protocol(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(Stage::Relay, Side::Client, ErrorKind::Protocol(msg.into()))
    }

    #[cold]
    pub fn preauth(msg: impl Into<Cow<'static, str>>) -> Self {
        Self::new(
            Stage::Preauth,
            Side::Client,
            ErrorKind::Protocol(msg.into()),
        )
    }

    pub fn attribution(&self, peer: IpAddr) -> Attribution {
        match (self.stage, &self.kind) {
            (Stage::Dns | Stage::Connect, _) => Attribution::Host,
            (stage, ErrorKind::Timeout) if stage.is_establishment() => Attribution::Host,
            _ => Attribution::Client(peer),
        }
    }

    pub fn is_retryable(&self) -> bool {
        self.stage.is_establishment()
            && matches!(
                self.kind,
                ErrorKind::Io(_) | ErrorKind::Timeout | ErrorKind::Closed
            )
    }
}

fn io_other(msg: Cow<'static, str>) -> std::io::Error {
    std::io::Error::other(msg.into_owned())
}

impl From<std::io::Error> for ProxyError {
    #[cold]
    fn from(err: std::io::Error) -> Self {
        Self::io(Stage::Relay, Side::Client, err)
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::Io(e) => write!(f, "i/o error: {e}"),
            ErrorKind::Tls(e) => match e.as_ref() {
                rustls::Error::General(msg) => write!(f, "tls error: {msg}"),
                other => write!(f, "tls error: {other}"),
            },
            ErrorKind::Protocol(msg) => write!(f, "protocol error: {msg}"),
            ErrorKind::Timeout => f.write_str("timed out"),
            ErrorKind::Closed => f.write_str("connection closed"),
            ErrorKind::LimitExceeded(limit) => write!(f, "{} limit exceeded", limit.as_str()),
            ErrorKind::Unavailable(msg) => write!(f, "backend unavailable: {msg}"),
            ErrorKind::Store(msg) => write!(f, "mapping store error: {msg}"),
            ErrorKind::Config(msg) => write!(f, "configuration error: {msg}"),
        }
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.kind {
            ErrorKind::Io(e) => Some(e),
            ErrorKind::Tls(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub path: Box<str>,
    pub message: Cow<'static, str>,
    pub line: Option<u32>,
}

impl ConfigError {
    #[cold]
    pub fn new(path: impl Into<Box<str>>, message: impl Into<Cow<'static, str>>) -> Self {
        ConfigError {
            path: path.into(),
            message: message.into(),
            line: None,
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.path.is_empty(), self.line) {
            (true, None) => f.write_str(&self.message),
            (true, Some(line)) => write!(f, "line {line}: {}", self.message),
            (false, Some(line)) => write!(f, "{} (line {line}): {}", self.path, self.message),
            (false, None) => write!(f, "{}: {}", self.path, self.message),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigErrors(pub Vec<ConfigError>);

impl ConfigErrors {
    pub fn push(&mut self, path: impl Into<Box<str>>, message: impl Into<Cow<'static, str>>) {
        self.0.push(ConfigError::new(path, message));
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_result(self) -> std::result::Result<(), ConfigErrors> {
        if self.0.is_empty() { Ok(()) } else { Err(self) }
    }
}

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut errors = self.0.iter();
        if let Some(first) = errors.next() {
            first.fmt(f)?;
        }
        errors.try_for_each(|e| write!(f, "; {e}"))
    }
}

impl std::error::Error for ConfigErrors {}

impl From<ConfigErrors> for ProxyError {
    #[cold]
    fn from(errors: ConfigErrors) -> Self {
        ProxyError::config(errors.to_string())
    }
}
