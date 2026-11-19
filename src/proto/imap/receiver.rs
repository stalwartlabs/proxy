/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::mem;
use std::ops::Range;
use std::str;

use memchr::{memchr2, memchr3};

use crate::proto::session::MAX_TAG;

pub const MAX_REQUEST: u32 = 64 * 1024;
const MAX_COMMAND: usize = 15;
const INITIAL_ARENA: usize = 128;
const SHORT_ATOM: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    NeedsMoreData,
    NeedsLiteral { size: u32 },
    LiteralTooBig { non_sync: bool },
    Parse { message: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    Tagged,
    Untagged,
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

impl Command {
    fn parse(name: &[u8]) -> Self {
        hashify::map_ignore_case!(
            name,
            Command,
            "CAPABILITY" => Command::Capability,
            "NOOP" => Command::Noop,
            "LOGOUT" => Command::Logout,
            "ID" => Command::Id,
            "STARTTLS" => Command::StartTls,
            "AUTHENTICATE" => Command::Authenticate,
            "LOGIN" => Command::Login,
            "ENABLE" => Command::Enable,
            "UNAUTHENTICATE" => Command::Unauthenticate,
        )
        .copied()
        .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Arg(Range<u32>),
    Nil,
    ParenOpen,
    ParenClose,
}

#[derive(Debug, Default)]
pub struct Request {
    pub command: Command,
    tag_end: u32,
    tokens: Vec<Token>,
    arena: Vec<u8>,
}

impl Request {
    pub fn tag(&self) -> &str {
        self.arena
            .get(..self.tag_end as usize)
            .and_then(|tag| str::from_utf8(tag).ok())
            .unwrap_or_default()
    }

    pub fn tokens(&self) -> &[Token] {
        &self.tokens
    }

    pub fn bytes(&self, token: &Token) -> &[u8] {
        match token {
            Token::Arg(range) => self
                .arena
                .get(range.start as usize..range.end as usize)
                .unwrap_or_default(),
            Token::Nil => b"",
            Token::ParenOpen => b"(",
            Token::ParenClose => b")",
        }
    }

    pub fn args(&self) -> impl Iterator<Item = &[u8]> {
        self.tokens().iter().map(|token| self.bytes(token))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    Tag,
    Command {
        uid: bool,
    },
    Argument {
        boundary: bool,
    },
    Quoted {
        escaped: bool,
    },
    LiteralSize {
        size: u32,
        digits: bool,
        non_sync: bool,
    },
    LiteralEnd {
        size: u32,
        non_sync: bool,
    },
    LiteralData {
        remaining: u32,
    },
    Discard,
}

pub struct Receiver {
    request: Request,
    state: State,
    framing: Framing,
    arg_start: usize,
    max_request_size: usize,
}

impl Receiver {
    pub fn new(framing: Framing, max_request_size: u32) -> Self {
        Receiver {
            request: Request::default(),
            state: State::Start,
            framing,
            arg_start: 0,
            max_request_size: max_request_size as usize,
        }
    }

    pub fn tag(&self) -> &str {
        self.request.tag()
    }

    pub fn parse(&mut self, input: &mut &[u8]) -> Result<Request, Error> {
        while let Some((&ch, rest)) = input.split_first() {
            let run = match self.state {
                State::LiteralData { remaining } => {
                    let take = input.len().min(remaining as usize);
                    let (data, rest) = input.split_at(take);
                    self.request.arena.extend_from_slice(data);
                    *input = rest;
                    let remaining = remaining - take as u32;
                    if remaining == 0 {
                        self.push_argument(false, b' ')?;
                        self.state = State::Argument { boundary: true };
                    } else {
                        self.state = State::LiteralData { remaining };
                    }
                    continue;
                }
                State::Start => {
                    if ch.is_ascii_whitespace() {
                        *input = rest;
                    } else {
                        self.request.arena.clear();
                        self.request.tokens.clear();
                        self.request.tag_end = 0;
                        self.request.command = Command::Other;
                        self.request.arena.reserve(INITIAL_ARENA);
                        self.state = match self.framing {
                            Framing::Tagged => State::Tag,
                            Framing::Untagged => State::Command { uid: false },
                        };
                    }
                    continue;
                }
                State::Tag => run_len(
                    input,
                    MAX_TAG.saturating_sub(self.request.arena.len()),
                    is_tag_delimiter,
                ),
                State::Command { .. } => run_len(
                    input,
                    MAX_COMMAND.saturating_sub(self.pending().len()),
                    |b| !b.is_ascii_alphanumeric(),
                ),
                State::Argument { boundary: false } => atom_run(input),
                State::Quoted { escaped: false } => {
                    memchr3(b'"', b'\\', b'\n', input).unwrap_or(input.len())
                }
                _ => 0,
            };
            if self.take_run(input, run) {
                continue;
            }
            *input = rest;
            if self.step(ch)? {
                return Ok(self.finish());
            }
        }
        Err(Error::NeedsMoreData)
    }

    fn step(&mut self, ch: u8) -> Result<bool, Error> {
        match self.state {
            State::Start | State::LiteralData { .. } => {}
            State::Tag => match ch {
                b' ' => {
                    if str::from_utf8(&self.request.arena).is_err() {
                        return Err(self.fail(ch, "Tag is not a valid UTF-8 string."));
                    }
                    self.request.tag_end = self.request.arena.len() as u32;
                    self.arg_start = self.request.arena.len();
                    self.state = State::Command { uid: false };
                }
                b'\r' | b'\n' => {
                    return Err(self.fail(ch, "Missing command after tag, found CRLF instead."));
                }
                b'\t' => return Err(self.fail(ch, "Invalid character in tag.")),
                _ if self.request.arena.len() >= MAX_TAG => {
                    return Err(self.fail(ch, "Tag exceeds maximum length of 128 characters."));
                }
                _ => self.request.arena.push(ch),
            },
            State::Command { uid } => {
                if ch.is_ascii_alphanumeric() {
                    if self.pending().len() >= MAX_COMMAND {
                        return Err(
                            self.fail(ch, "Command exceeds maximum length of 15 characters.")
                        );
                    }
                    self.request.arena.push(ch);
                } else if ch.is_ascii_whitespace() {
                    let name = self.pending();
                    if name.is_empty() {
                        if ch == b'\n' {
                            return Err(self.fail(ch, "Missing command."));
                        }
                    } else if !uid && name.eq_ignore_ascii_case(b"UID") {
                        self.request.arena.truncate(self.arg_start);
                        if ch == b'\n' {
                            return Err(self.fail(ch, "Missing command."));
                        }
                        self.state = State::Command { uid: true };
                    } else {
                        self.request.command = Command::parse(name);
                        self.request.arena.truncate(self.arg_start);
                        if ch == b'\n' {
                            return Ok(true);
                        }
                        self.state = State::Argument { boundary: true };
                    }
                } else {
                    return Err(self.fail(ch, "Invalid character in command name."));
                }
            }
            State::Argument { boundary } => match ch {
                b'"' if boundary => self.state = State::Quoted { escaped: false },
                b'{' if boundary || self.pending() == b"~" => {
                    self.request.arena.truncate(self.arg_start);
                    self.state = State::LiteralSize {
                        size: 0,
                        digits: false,
                        non_sync: false,
                    };
                }
                b'(' | b')' => {
                    self.push_argument(false, ch)?;
                    let token = if ch == b'(' {
                        Token::ParenOpen
                    } else {
                        Token::ParenClose
                    };
                    self.push_token(token, ch)?;
                    self.state = State::Argument { boundary: true };
                }
                b'\n' => {
                    self.push_argument(false, ch)?;
                    return Ok(true);
                }
                _ if ch.is_ascii_whitespace() => {
                    self.push_argument(false, ch)?;
                    self.state = State::Argument { boundary: true };
                }
                _ => {
                    self.push_byte(ch)?;
                    self.state = State::Argument { boundary: false };
                }
            },
            State::Quoted { escaped } => match ch {
                b'"' if !escaped => {
                    self.push_argument(true, ch)?;
                    self.state = State::Argument { boundary: true };
                }
                b'\\' if !escaped => self.state = State::Quoted { escaped: true },
                b'"' | b'\\' => {
                    self.push_byte(ch)?;
                    self.state = State::Quoted { escaped: false };
                }
                b'\n' => return Err(self.fail(ch, "Unterminated quoted argument.")),
                _ => {
                    if escaped {
                        self.push_byte(b'\\')?;
                    }
                    self.push_byte(ch)?;
                    self.state = State::Quoted { escaped: false };
                }
            },
            State::LiteralSize {
                size,
                digits,
                non_sync,
            } => match ch {
                b'0'..=b'9' if !non_sync => {
                    let size = size.saturating_mul(10).saturating_add(u32::from(ch - b'0'));
                    self.state = State::LiteralSize {
                        size,
                        digits: true,
                        non_sync,
                    };
                }
                b'+' if digits && !non_sync => {
                    self.state = State::LiteralSize {
                        size,
                        digits,
                        non_sync: true,
                    };
                }
                b'}' if digits => {
                    let fits = usize::try_from(size)
                        .ok()
                        .and_then(|size| self.used().checked_add(size))
                        .is_some_and(|total| total < self.max_request_size);
                    if !fits {
                        return Err(self.reject_literal(non_sync));
                    }
                    self.state = State::LiteralEnd { size, non_sync };
                }
                _ => return Err(self.fail(ch, "Invalid literal.")),
            },
            State::LiteralEnd { size, non_sync } => {
                if ch == b'\n' {
                    if size > 0 {
                        self.request.arena.reserve(size as usize);
                        self.state = State::LiteralData { remaining: size };
                    } else {
                        self.push_token(Token::Nil, ch)?;
                        self.state = State::Argument { boundary: true };
                    }
                    if !non_sync {
                        return Err(Error::NeedsLiteral { size });
                    }
                } else if !ch.is_ascii_whitespace() {
                    return Err(
                        self.fail(ch, "Expected CRLF after literal, found an invalid char.")
                    );
                }
            }
            State::Discard => {
                if ch == b'\n' {
                    self.state = State::Start;
                }
            }
        }
        Ok(false)
    }

    fn used(&self) -> usize {
        self.request.arena.len() - self.request.tag_end as usize + self.request.tokens.len()
    }

    fn pending(&self) -> &[u8] {
        self.request.arena.get(self.arg_start..).unwrap_or_default()
    }

    fn take_run(&mut self, input: &mut &[u8], run: usize) -> bool {
        let take = run.min(self.max_request_size.saturating_sub(self.used()));
        let Some((data, rest)) = input.split_at_checked(take).filter(|_| take > 0) else {
            return false;
        };
        self.request.arena.extend_from_slice(data);
        *input = rest;
        true
    }

    fn push_byte(&mut self, ch: u8) -> Result<(), Error> {
        if self.used() >= self.max_request_size {
            return Err(self.fail(ch, "Request exceeds the maximum size."));
        }
        self.request.arena.push(ch);
        Ok(())
    }

    fn push_token(&mut self, token: Token, ch: u8) -> Result<(), Error> {
        if self.used() >= self.max_request_size {
            return Err(self.fail(ch, "Request exceeds the maximum size."));
        }
        self.request.tokens.push(token);
        Ok(())
    }

    fn push_argument(&mut self, quoted: bool, ch: u8) -> Result<(), Error> {
        let end = self.request.arena.len();
        if end > self.arg_start {
            let range = self.arg_start as u32..end as u32;
            self.push_token(Token::Arg(range), ch)?;
        } else if quoted {
            self.push_token(Token::Nil, ch)?;
        }
        self.arg_start = self.request.arena.len();
        Ok(())
    }

    fn finish(&mut self) -> Request {
        self.state = State::Start;
        self.arg_start = 0;
        mem::take(&mut self.request)
    }

    #[cold]
    fn reject_literal(&mut self, non_sync: bool) -> Error {
        self.request.tokens.clear();
        self.request.arena.truncate(self.request.tag_end as usize);
        self.arg_start = self.request.arena.len();
        self.state = State::Discard;
        Error::LiteralTooBig { non_sync }
    }

    #[cold]
    fn fail(&mut self, ch: u8, message: &'static str) -> Error {
        self.request = Request::default();
        self.arg_start = 0;
        self.state = if ch == b'\n' {
            State::Start
        } else {
            State::Discard
        };
        Error::Parse { message }
    }
}

fn run_len(input: &[u8], limit: usize, stop: impl Fn(u8) -> bool) -> usize {
    let window = input.get(..limit).unwrap_or(input);
    window.iter().position(|&b| stop(b)).unwrap_or(window.len())
}

fn is_tag_delimiter(ch: u8) -> bool {
    matches!(ch, b' ' | b'\t' | b'\r' | b'\n')
}

fn atom_run(input: &[u8]) -> usize {
    let (head, tail) = input.split_at(input.len().min(SHORT_ATOM));
    match head.iter().position(|&b| is_argument_delimiter(b)) {
        Some(end) => end,
        None if tail.is_empty() => head.len(),
        None => head.len() + long_atom_run(tail),
    }
}

fn is_argument_delimiter(ch: u8) -> bool {
    matches!(
        ch,
        b'(' | b')' | b'{' | b' ' | b'\t' | b'\n' | b'\r' | b'\x0c'
    )
}

fn long_atom_run(input: &[u8]) -> usize {
    let end = memchr3(b' ', b'\r', b'\n', input).unwrap_or(input.len());
    let head = input.get(..end).unwrap_or(input);
    let end = memchr3(b'(', b')', b'{', head).unwrap_or(end);
    let head = input.get(..end).unwrap_or(input);
    memchr2(b'\t', b'\x0c', head).unwrap_or(end)
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../../proxy-tests/unit/src/proto/imap/receiver/tests.rs"]
mod tests;
