/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Display;

#[derive(Debug, Clone)]
pub enum Error {
    NeedsMoreData,
    NeedsLiteral { size: u32 },
    Parse { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request<T: CommandParser> {
    pub tag: String,
    pub command: T,
    pub tokens: Vec<Token>,
}

pub trait CommandParser: Sized + Default {
    fn parse(bytes: &[u8], is_uid: bool) -> Option<Self>;
    fn tokenize_brackets(&self) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Argument(Vec<u8>),
    ParenthesisOpen,
    ParenthesisClose,
    BracketOpen,
    BracketClose,
    Lt,
    Gt,
    Dot,
    Nil,
}

impl<T: CommandParser> Default for Request<T> {
    fn default() -> Self {
        Self {
            tag: String::new(),
            command: T::default(),
            tokens: Vec::new(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum State {
    Start,
    Tag,
    Command { is_uid: bool },
    Argument { last_ch: u8 },
    ArgumentQuoted { escaped: bool },
    Literal { non_sync: bool },
    LiteralSeek { size: u32, non_sync: bool },
    LiteralData { remaining: u32 },
}

pub struct Receiver<T: CommandParser> {
    buf: ArgumentBuffer,
    pub request: Request<T>,
    pub state: State,
    pub max_request_size: usize,
    pub current_request_size: usize,
    pub start_state: State,
}

const ARG_MAX_LEN: usize = 8000;

struct ArgumentBuffer {
    buf: Vec<u8>,
}

impl<T: CommandParser> Receiver<T> {
    pub fn new() -> Self {
        Receiver {
            max_request_size: 25 * 1024 * 1024,
            ..Default::default()
        }
    }

    pub fn with_start_state(mut self, state: State) -> Self {
        self.state = state;
        self.start_state = state;
        self
    }

    pub fn error_reset(&mut self, message: impl Into<String>) -> Error {
        let _request = std::mem::take(&mut self.request);
        let err = Error::Parse {
            message: message.into(),
        };
        self.buf = ArgumentBuffer::default();
        self.state = self.start_state;
        self.current_request_size = 0;
        err
    }

    fn push_argument(&mut self, in_quote: bool) -> Result<(), Error> {
        if !self.buf.is_empty() {
            self.current_request_size += self.buf.len();
            if self.current_request_size > self.max_request_size {
                return Err(self.error_reset(format!(
                    "Request exceeds maximum limit of {} bytes.",
                    self.max_request_size
                )));
            }
            self.request.tokens.push(Token::Argument(self.buf.take()));
        } else if in_quote {
            self.request.tokens.push(Token::Nil);
        }
        Ok(())
    }

    fn push_token(&mut self, token: Token) -> Result<(), Error> {
        self.current_request_size += 1;
        if self.current_request_size > self.max_request_size {
            return Err(self.error_reset(format!(
                "Request exceeds maximum limit of {} bytes.",
                self.max_request_size
            )));
        }
        self.request.tokens.push(token);
        Ok(())
    }

    pub fn parse(&mut self, bytes: &mut std::slice::Iter<'_, u8>) -> Result<Request<T>, Error> {
        for &ch in bytes.by_ref() {
            match self.state {
                State::Start => {
                    if !ch.is_ascii_whitespace() {
                        self.buf.push_unchecked(ch);
                        self.state = State::Tag;
                    }
                }
                State::Tag => match ch {
                    b' ' => {
                        if !self.buf.is_empty() {
                            self.request.tag =
                                String::from_utf8(self.buf.take()).map_err(|_| {
                                    self.error_reset("Tag is not a valid UTF-8 string.")
                                })?;
                            self.state = State::Command { is_uid: false };
                        }
                    }
                    b'\t' | b'\r' => {}
                    b'\n' => {
                        return Err(self.error_reset(format!(
                            "Missing command after tag {:?}, found CRLF instead.",
                            self.buf.as_str()
                        )));
                    }
                    _ => {
                        self.buf.push_checked(ch, 128).map_err(|_| {
                            self.error_reset("Tag exceeds maximum length of 128 characters.")
                        })?;
                    }
                },
                State::Command { is_uid } => {
                    if ch.is_ascii_alphanumeric() {
                        self.buf
                            .push_checked(ch.to_ascii_uppercase(), 15)
                            .map_err(|_| {
                                self.error_reset("Command exceeds maximum length of 15 characters.")
                            })?;
                    } else if ch.is_ascii_whitespace() {
                        if !self.buf.is_empty() {
                            if !self.buf.as_ref().eq_ignore_ascii_case(b"UID") {
                                self.request.command = T::parse(self.buf.as_ref(), is_uid)
                                    .ok_or_else(|| {
                                        let err = format!(
                                            "Unrecognized command '{}'.",
                                            String::from_utf8_lossy(self.buf.as_ref())
                                        );
                                        self.error_reset(err)
                                    })?;
                                self.buf.clear();
                                if ch != b'\n' {
                                    self.state = State::Argument { last_ch: b' ' };
                                } else {
                                    self.state = self.start_state;
                                    self.current_request_size = 0;
                                    return Ok(std::mem::take(&mut self.request));
                                }
                            } else {
                                self.buf.clear();
                                self.state = State::Command { is_uid: true };
                            }
                        }
                    } else {
                        return Err(self.error_reset(format!(
                            "Invalid character {:?} in command name.",
                            ch as char
                        )));
                    }
                }
                State::Argument { last_ch } => match ch {
                    b'\"' if last_ch.is_ascii_whitespace() => {
                        self.push_argument(false)?;
                        self.state = State::ArgumentQuoted { escaped: false };
                    }
                    b'{' if last_ch.is_ascii_whitespace()
                        || (last_ch == b'~' && self.buf.len() == 1) =>
                    {
                        if last_ch != b'~' {
                            self.push_argument(false)?;
                        } else {
                            self.buf.clear();
                        }
                        self.state = State::Literal { non_sync: false };
                    }
                    b'(' => {
                        self.push_argument(false)?;
                        self.push_token(Token::ParenthesisOpen)?;
                    }
                    b')' => {
                        self.push_argument(false)?;
                        self.push_token(Token::ParenthesisClose)?;
                    }
                    b'[' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::BracketOpen)?;
                    }
                    b']' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::BracketClose)?;
                    }
                    b'<' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::Lt)?;
                    }
                    b'>' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::Gt)?;
                    }
                    b'.' if self.request.command.tokenize_brackets() => {
                        self.push_argument(false)?;
                        self.push_token(Token::Dot)?;
                    }
                    b'\n' => {
                        self.push_argument(false)?;
                        self.state = self.start_state;
                        self.current_request_size = 0;
                        return Ok(std::mem::take(&mut self.request));
                    }
                    _ if ch.is_ascii_whitespace() => {
                        self.push_argument(false)?;
                        self.state = State::Argument { last_ch: ch };
                    }
                    _ => {
                        self.buf.push_checked(ch, ARG_MAX_LEN).map_err(|_| {
                            self.error_reset("Argument exceeds maximum length of 8000 bytes.")
                        })?;
                        self.state = State::Argument { last_ch: ch };
                    }
                },
                State::ArgumentQuoted { escaped } => match ch {
                    b'\"' => {
                        if !escaped {
                            self.push_argument(true)?;
                            self.state = State::Argument { last_ch: b' ' };
                        } else {
                            self.buf
                                .push_checked(ch, ARG_MAX_LEN)
                                .map_err(|_| self.error_reset("Quoted argument too long."))?;
                            self.state = State::ArgumentQuoted { escaped: false };
                        }
                    }
                    b'\\' => {
                        if escaped {
                            self.buf
                                .push_checked(ch, ARG_MAX_LEN)
                                .map_err(|_| self.error_reset("Quoted argument too long."))?;
                        }
                        self.state = State::ArgumentQuoted { escaped: !escaped };
                    }
                    b'\n' => {
                        return Err(self.error_reset("Unterminated quoted argument."));
                    }
                    _ => {
                        if escaped {
                            self.buf.push_unchecked(b'\\');
                        }
                        self.buf
                            .push_checked(ch, ARG_MAX_LEN)
                            .map_err(|_| self.error_reset("Quoted argument too long."))?;
                        self.state = State::ArgumentQuoted { escaped: false };
                    }
                },
                State::Literal { non_sync } => match ch {
                    b'}' => {
                        if !self.buf.is_empty() {
                            let size = self.buf.as_str().parse::<u32>().map_err(|_| {
                                self.error_reset("Literal size is not a valid number.")
                            })?;
                            if self.current_request_size + size as usize > self.max_request_size {
                                return Err(self.error_reset(format!(
                                    "Literal exceeds the maximum request size of {} bytes.",
                                    self.max_request_size
                                )));
                            }
                            self.state = State::LiteralSeek { size, non_sync };
                            self.buf.resize_buffer(size as usize);
                            self.buf.clear();
                        } else {
                            return Err(self.error_reset("Invalid empty literal."));
                        }
                    }
                    b'+' => {
                        if !self.buf.is_empty() {
                            self.state = State::Literal { non_sync: true };
                        } else {
                            return Err(self.error_reset("Invalid non-sync literal."));
                        }
                    }
                    _ if ch.is_ascii_digit() => {
                        if !non_sync {
                            self.buf.push_checked(ch, 15).map_err(|_| {
                                self.error_reset("Literal size exceeds maximum of 15 digits.")
                            })?;
                        } else {
                            return Err(self.error_reset("Invalid literal."));
                        }
                    }
                    _ => {
                        return Err(self.error_reset(format!(
                            "Invalid character {:?} in literal.",
                            ch as char
                        )));
                    }
                },
                State::LiteralSeek { size, non_sync } => {
                    if ch == b'\n' {
                        if size > 0 {
                            self.state = State::LiteralData { remaining: size };
                        } else {
                            self.state = State::Argument { last_ch: b' ' };
                            self.push_token(Token::Nil)?;
                        }
                        if !non_sync {
                            return Err(Error::NeedsLiteral { size });
                        }
                    } else if !ch.is_ascii_whitespace() {
                        return Err(
                            self.error_reset("Expected CRLF after literal, found an invalid char.")
                        );
                    }
                }
                State::LiteralData { remaining } => {
                    self.buf.push_unchecked(ch);

                    if remaining > 1 {
                        self.state = State::LiteralData {
                            remaining: remaining - 1,
                        };
                    } else {
                        self.push_argument(false)?;
                        self.state = State::Argument { last_ch: b' ' };
                    }
                }
            }
        }

        Err(Error::NeedsMoreData)
    }
}

impl ArgumentBuffer {
    pub fn new() -> Self {
        ArgumentBuffer {
            buf: Vec::with_capacity(10),
        }
    }

    pub fn resize_buffer(&mut self, size: usize) {
        if self.buf.capacity() < size {
            self.buf.reserve(size - self.buf.capacity());
        }
    }

    #[inline(always)]
    pub fn push_checked(&mut self, byte: u8, limit: usize) -> Result<(), ()> {
        if self.buf.len() < limit {
            self.buf.push(byte);
            Ok(())
        } else {
            Err(())
        }
    }

    #[inline(always)]
    pub fn push_unchecked(&mut self, byte: u8) {
        self.buf.push(byte);
    }

    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        self.buf.clear();
    }

    #[inline(always)]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf).unwrap_or_default()
    }
}

impl AsRef<[u8]> for ArgumentBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl Default for ArgumentBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&String::from_utf8_lossy(self.as_bytes()))
    }
}

impl Token {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Token::Argument(value) => value,
            Token::ParenthesisOpen => b"(",
            Token::ParenthesisClose => b")",
            Token::BracketOpen => b"[",
            Token::BracketClose => b"]",
            Token::Gt => b">",
            Token::Lt => b"<",
            Token::Dot => b".",
            Token::Nil => b"",
        }
    }
}

impl<T: CommandParser> Default for Receiver<T> {
    fn default() -> Self {
        Self {
            buf: Default::default(),
            request: Default::default(),
            state: State::Start,
            start_state: State::Start,
            max_request_size: 25 * 1024 * 1024,
            current_request_size: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Command {
    #[default]
    Other,
    Capability,
    Noop,
    Logout,
    Id,
    StartTls,
    Authenticate,
    Login,
    Enable,
    Unauthenticate,
}

impl CommandParser for Command {
    fn parse(bytes: &[u8], _is_uid: bool) -> Option<Self> {
        Some(match bytes {
            b if b.eq_ignore_ascii_case(b"CAPABILITY") => Command::Capability,
            b if b.eq_ignore_ascii_case(b"NOOP") => Command::Noop,
            b if b.eq_ignore_ascii_case(b"LOGOUT") => Command::Logout,
            b if b.eq_ignore_ascii_case(b"ID") => Command::Id,
            b if b.eq_ignore_ascii_case(b"STARTTLS") => Command::StartTls,
            b if b.eq_ignore_ascii_case(b"AUTHENTICATE") => Command::Authenticate,
            b if b.eq_ignore_ascii_case(b"LOGIN") => Command::Login,
            b if b.eq_ignore_ascii_case(b"ENABLE") => Command::Enable,
            b if b.eq_ignore_ascii_case(b"UNAUTHENTICATE") => Command::Unauthenticate,
            _ => Command::Other,
        })
    }

    fn tokenize_brackets(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    Plain,
    OAuthBearer,
    XOauth2,
    Login,
    Other(String),
}

impl Mechanism {
    pub fn parse(bytes: &[u8]) -> Mechanism {
        if bytes.eq_ignore_ascii_case(b"PLAIN") {
            Mechanism::Plain
        } else if bytes.eq_ignore_ascii_case(b"OAUTHBEARER") {
            Mechanism::OAuthBearer
        } else if bytes.eq_ignore_ascii_case(b"XOAUTH2") {
            Mechanism::XOauth2
        } else if bytes.eq_ignore_ascii_case(b"LOGIN") {
            Mechanism::Login
        } else {
            Mechanism::Other(String::from_utf8_lossy(bytes).to_ascii_uppercase())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, Error, Receiver, Request, Token};

    #[test]
    fn receiver_parse_ok() {
        let mut receiver = Receiver::new();

        for (frames, expected_requests) in [
            (
                vec!["abcd CAPABILITY\r\n"],
                vec![Request {
                    tag: "abcd".into(),
                    command: Command::Capability,
                    tokens: vec![],
                }],
            ),
            (
                vec!["A023 LO", "GOUT\r\n"],
                vec![Request {
                    tag: "A023".into(),
                    command: Command::Logout,
                    tokens: vec![],
                }],
            ),
            (
                vec!["  A001 AUTHENTICATE GSSAPI  \r\n"],
                vec![Request {
                    tag: "A001".into(),
                    command: Command::Authenticate,
                    tokens: vec![Token::Argument(b"GSSAPI".to_vec())],
                }],
            ),
            (
                vec!["A03   AUTHENTICATE ", "PLAIN dGVzdAB0ZXN", "0AHRlc3Q=\r\n"],
                vec![Request {
                    tag: "A03".into(),
                    command: Command::Authenticate,
                    tokens: vec![
                        Token::Argument(b"PLAIN".to_vec()),
                        Token::Argument(b"dGVzdAB0ZXN0AHRlc3Q=".to_vec()),
                    ],
                }],
            ),
            (
                vec!["A001 LOGIN {11}\r\n", "FRED FOOBAR {7}\r\n", "fat man\r\n"],
                vec![Request {
                    tag: "A001".into(),
                    command: Command::Login,
                    tokens: vec![
                        Token::Argument(b"FRED FOOBAR".to_vec()),
                        Token::Argument(b"fat man".to_vec()),
                    ],
                }],
            ),
            (
                vec!["abc LOGIN {0}\r\n", "\r\n"],
                vec![Request {
                    tag: "abc".into(),
                    command: Command::Login,
                    tokens: vec![Token::Nil],
                }],
            ),
            (
                vec!["abc LOGIN {0+}\r\n\r\n"],
                vec![Request {
                    tag: "abc".into(),
                    command: Command::Login,
                    tokens: vec![Token::Nil],
                }],
            ),
            (
                vec!["001 NOOP\r\n002 CAPABILITY\r\nabc LOGIN hello world\r\n"],
                vec![
                    Request {
                        tag: "001".into(),
                        command: Command::Noop,
                        tokens: vec![],
                    },
                    Request {
                        tag: "002".into(),
                        command: Command::Capability,
                        tokens: vec![],
                    },
                    Request {
                        tag: "abc".into(),
                        command: Command::Login,
                        tokens: vec![
                            Token::Argument(b"hello".to_vec()),
                            Token::Argument(b"world".to_vec()),
                        ],
                    },
                ],
            ),
        ] {
            let mut requests = Vec::new();
            for frame in &frames {
                let mut bytes = frame.as_bytes().iter();
                loop {
                    match receiver.parse(&mut bytes) {
                        Ok(request) => requests.push(request),
                        Err(Error::NeedsMoreData | Error::NeedsLiteral { .. }) => break,
                        Err(err) => panic!("{:?} for frames {:#?}", err, frames),
                    }
                }
            }
            assert_eq!(requests, expected_requests, "{:#?}", frames);
        }
    }

    #[test]
    fn receiver_parse_invalid() {
        let mut receiver = Receiver::<Command>::new();
        for invalid in [
            "a001 login {abc}\r\n",
            "a001 login {+30}\r\n",
            "a001 login {30} junk\r\n",
        ] {
            match receiver.parse(&mut invalid.as_bytes().iter()) {
                Err(Error::Parse { .. }) => {}
                result => panic!("Expecter error, got: {:?}", result),
            }
        }
    }
}
