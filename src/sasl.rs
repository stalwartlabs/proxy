/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::str;

use encodify::base64::{self, Base64};
use serde::{Serialize, Serializer};

pub const SASL_RESPONSE: Base64 = base64::LENIENT;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SaslMech {
    Plain,
    Login,
    OAuthBearer,
    XOAuth2,
}

impl SaslMech {
    pub fn parse(name: &[u8]) -> Option<Self> {
        hashify::map_ignore_case!(
            name,
            SaslMech,
            "PLAIN" => SaslMech::Plain,
            "LOGIN" => SaslMech::Login,
            "OAUTHBEARER" => SaslMech::OAuthBearer,
            "XOAUTH2" => SaslMech::XOAuth2,
        )
        .copied()
    }

    pub fn as_str(self) -> &'static str {
        match self {
            SaslMech::Plain => "PLAIN",
            SaslMech::Login => "LOGIN",
            SaslMech::OAuthBearer => "OAUTHBEARER",
            SaslMech::XOAuth2 => "XOAUTH2",
        }
    }

    pub fn is_cleartext(self) -> bool {
        matches!(self, SaslMech::Plain | SaslMech::Login)
    }
}

impl Serialize for SaslMech {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

const AUTH_BEARER: &[u8] = b"auth=Bearer ";
const XOAUTH2_USER: &[u8] = b"user=";
const GS2_AUTHZID: &[u8] = b"a=";
const KV_SEPARATOR: u8 = 0x01;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential<'a> {
    Plain { authcid: &'a str, passwd: &'a str },
    OAuth(OAuthFrame<'a>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthFrame<'a> {
    pub authzid: Option<Cow<'a, str>>,
    pub token: &'a str,
}

impl<'a> Credential<'a> {
    pub fn plain(response: &'a [u8]) -> Option<Self> {
        let mut fields = response.split(|&b| b == 0).skip(1);
        let authcid = str::from_utf8(fields.next()?).ok()?;
        let passwd = str::from_utf8(fields.next()?).ok()?;
        (!authcid.is_empty() && !passwd.is_empty()).then_some(Credential::Plain { authcid, passwd })
    }

    pub fn oauth(response: &'a [u8]) -> Option<Self> {
        OAuthFrame::parse(response).map(Credential::OAuth)
    }
}

impl<'a> OAuthFrame<'a> {
    pub fn parse(response: &'a [u8]) -> Option<Self> {
        let mut authzid = None;
        for (index, segment) in response.split(|&b| b == KV_SEPARATOR).enumerate() {
            if let Some(token) = strip_prefix_ignore_case(segment, AUTH_BEARER) {
                return Some(OAuthFrame {
                    authzid,
                    token: str::from_utf8(token).ok()?,
                });
            }
            if authzid.is_some() {
                continue;
            }
            authzid = match strip_prefix_ignore_case(segment, XOAUTH2_USER) {
                Some(user) => str::from_utf8(user).ok().map(Cow::Borrowed),
                None if index == 0 => gs2_authzid(segment),
                None => None,
            };
        }
        None
    }
}

fn gs2_authzid(header: &[u8]) -> Option<Cow<'_, str>> {
    let field = header.split(|&b| b == b',').nth(1)?;
    let name = strip_prefix_ignore_case(field, GS2_AUTHZID)?;
    decode_saslname(str::from_utf8(name).ok()?)
}

fn decode_saslname(name: &str) -> Option<Cow<'_, str>> {
    if !name.contains('=') {
        return Some(Cow::Borrowed(name));
    }
    let mut decoded = String::with_capacity(name.len());
    let mut rest = name;
    while let Some((head, tail)) = rest.split_once('=') {
        decoded.push_str(head);
        let (escape, tail) = tail.split_at_checked(2)?;
        decoded.push(hashify::map!(escape.as_bytes(), char, "2C" => ',', "3D" => '=').copied()?);
        rest = tail;
    }
    decoded.push_str(rest);
    Some(Cow::Owned(decoded))
}

fn strip_prefix_ignore_case<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let (head, rest) = bytes.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(rest)
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../proxy-tests/unit/src/sasl/tests.rs"]
mod tests;
