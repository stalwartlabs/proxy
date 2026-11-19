/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::mem;

use crate::proto::session::{BackendMech, Login};
use crate::route::key::{KeyError, KeyRules};
use crate::runtime::capabilities::SaslSet;
use crate::sasl::{Credential, SASL_RESPONSE, SaslMech};

pub const EMPTY_CHALLENGE: &[u8] = b"";
pub const LOGIN_USERNAME_CHALLENGE: &[u8] = b"VXNlcm5hbWU6";
pub const LOGIN_PASSWORD_CHALLENGE: &[u8] = b"UGFzc3dvcmQ6";
const EMPTY_RESPONSE: &[u8] = b"=";
const CANCEL: &[u8] = b"*";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    Unsupported,
    PrivacyRequired,
    InvalidBase64,
    Malformed,
    Cancelled,
    TooLong,
}

#[derive(Debug)]
pub enum Step {
    Challenge(&'static [u8]),
    Done(Login),
    Unroutable(KeyError),
    Reject(Reject),
}

#[derive(Debug)]
pub struct SaslExchange {
    state: ExchangeState,
}

#[derive(Debug)]
enum ExchangeState {
    Response(BackendMech),
    LoginUser,
    LoginPassword(Vec<u8>),
    Finished,
}

impl SaslExchange {
    pub fn start(
        offered: SaslSet,
        mech: &[u8],
        initial: Option<&[u8]>,
        rules: &KeyRules,
    ) -> (Self, Step) {
        Self::start_mech(offered, SaslMech::parse(mech), initial, rules)
    }

    pub fn start_mech(
        offered: SaslSet,
        mech: Option<SaslMech>,
        initial: Option<&[u8]>,
        rules: &KeyRules,
    ) -> (Self, Step) {
        let mut exchange = SaslExchange {
            state: ExchangeState::Finished,
        };
        let mech = match mech {
            Some(mech) if offered.configured(mech) => mech,
            _ => return (exchange, Step::Reject(Reject::Unsupported)),
        };
        if mech.is_cleartext() && !offered.cleartext_allowed() {
            return (exchange, Step::Reject(Reject::PrivacyRequired));
        }
        exchange.state = match mech {
            SaslMech::Login => ExchangeState::LoginUser,
            SaslMech::Plain => ExchangeState::Response(BackendMech::Plain),
            SaslMech::OAuthBearer => ExchangeState::Response(BackendMech::OAuthBearer),
            SaslMech::XOAuth2 => ExchangeState::Response(BackendMech::XOAuth2),
        };
        let step = match initial {
            Some(initial) => exchange.respond(initial, rules),
            None => match exchange.state {
                ExchangeState::LoginUser => Step::Challenge(LOGIN_USERNAME_CHALLENGE),
                _ => Step::Challenge(EMPTY_CHALLENGE),
            },
        };
        (exchange, step)
    }

    pub fn feed(&mut self, response: &[u8], rules: &KeyRules) -> Step {
        if response.trim_ascii() == CANCEL {
            self.state = ExchangeState::Finished;
            return Step::Reject(Reject::Cancelled);
        }
        self.respond(response, rules)
    }

    fn respond(&mut self, b64: &[u8], rules: &KeyRules) -> Step {
        let b64 = match b64.trim_ascii() {
            EMPTY_RESPONSE => &[],
            trimmed => trimmed,
        };
        match mem::replace(&mut self.state, ExchangeState::Finished) {
            ExchangeState::Response(mech) => match SASL_RESPONSE.decode(b64) {
                Ok(response) => mech.finish(response, rules),
                Err(_) => Step::Reject(Reject::InvalidBase64),
            },
            ExchangeState::LoginUser => {
                let mut frame = Vec::with_capacity(
                    SASL_RESPONSE
                        .decoded_len_estimate(b64.len())
                        .saturating_add(2),
                );
                frame.push(0);
                if SASL_RESPONSE.decode_append(b64, &mut frame).is_err() {
                    return Step::Reject(Reject::InvalidBase64);
                }
                frame.push(0);
                self.state = ExchangeState::LoginPassword(frame);
                Step::Challenge(LOGIN_PASSWORD_CHALLENGE)
            }
            ExchangeState::LoginPassword(mut frame) => {
                if SASL_RESPONSE.decode_append(b64, &mut frame).is_err() {
                    return Step::Reject(Reject::InvalidBase64);
                }
                BackendMech::Plain.finish(frame, rules)
            }
            ExchangeState::Finished => Step::Reject(Reject::Malformed),
        }
    }
}

impl Step {
    pub fn cleartext_login(user: &[u8], pass: &[u8], rules: &KeyRules) -> Step {
        let mut frame = Vec::with_capacity(user.len().saturating_add(pass.len()).saturating_add(2));
        frame.push(0);
        frame.extend_from_slice(user);
        frame.push(0);
        frame.extend_from_slice(pass);
        BackendMech::Plain.finish(frame, rules)
    }
}

impl BackendMech {
    fn finish(self, response: Vec<u8>, rules: &KeyRules) -> Step {
        let credential = match self {
            BackendMech::Plain => Credential::plain(&response),
            BackendMech::OAuthBearer | BackendMech::XOAuth2 => Credential::oauth(&response),
        };
        let Some(credential) = credential else {
            return Step::Reject(Reject::Malformed);
        };
        let key = match credential.routing_key(rules) {
            Ok(key) => key,
            Err(err) => return Step::Unroutable(err),
        };
        Step::Done(Login {
            mech: self,
            response,
            key,
            tag: None,
            helo: None,
        })
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/proto/sasl_exchange/tests.rs"]
mod tests;
