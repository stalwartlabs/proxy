/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::fmt;

use encodify::base64::URL_SAFE_NO_PAD;
use serde::Deserializer;
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, Visitor};

use crate::route::key::{KeyError, KeyRules, RoutingKey};
use crate::sasl::{Credential, OAuthFrame};

const STALWART_TOKEN_PREFIX: &str = "sw1.";

pub fn bearer_identifier(token: &str, jwt_username_claim: &str) -> Option<String> {
    if let Some(rest) = token.strip_prefix(STALWART_TOKEN_PREFIX) {
        let (_body, footer) = rest.split_once('.')?;
        return URL_SAFE_NO_PAD.decode_to_string(footer).ok();
    }
    let payload = token.split('.').nth(1)?.trim_end_matches('=');
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let mut deserializer = serde_json::Deserializer::from_slice(&decoded);
    ClaimScan {
        configured: jwt_username_claim,
    }
    .deserialize(&mut deserializer)
    .ok()
    .flatten()
}

pub fn valid_routing_identifier(id: &str) -> bool {
    !id.bytes()
        .any(|b| b < 0x20 || b == 0x7f || b == b' ' || b == b'"')
}

impl Credential<'_> {
    pub fn routing_key(&self, rules: &KeyRules) -> Result<Option<RoutingKey>, KeyError> {
        match self {
            Credential::Plain { authcid, .. } => RoutingKey::parse(authcid, rules),
            Credential::OAuth(frame) => frame.routing_key(rules),
        }
    }
}

impl OAuthFrame<'_> {
    fn routing_key(&self, rules: &KeyRules) -> Result<Option<RoutingKey>, KeyError> {
        let mut rejected = None;
        let mut attempt = |candidate: &str| match RoutingKey::parse(candidate, rules) {
            Ok(key) => key,
            Err(err) => {
                rejected.get_or_insert(err);
                None
            }
        };
        let authzid = self.authzid.as_deref().filter(|name| !name.is_empty());
        let (addressed, bare) = match authzid {
            Some(name) if name.contains('@') => (Some(name), None),
            other => (None, other),
        };
        if let Some(key) = addressed.and_then(&mut attempt) {
            return Ok(Some(key));
        }
        if let Some(key) = bearer_identifier(self.token, rules.jwt_claim())
            .as_deref()
            .and_then(&mut attempt)
        {
            return Ok(Some(key));
        }
        if let Some(key) = bare.and_then(&mut attempt) {
            return Ok(Some(key));
        }
        rejected.map_or(Ok(None), Err)
    }
}

struct ClaimScan<'a> {
    configured: &'a str,
}

impl ClaimScan<'_> {
    fn rank(&self, name: &str) -> Option<usize> {
        if name == self.configured {
            return Some(0);
        }
        hashify::map!(
            name.as_bytes(),
            usize,
            "email" => 1,
            "preferred_username" => 2,
            "upn" => 3,
            "unique_name" => 4,
            "sub" => 5,
        )
        .copied()
    }
}

impl<'de> DeserializeSeed<'de> for ClaimScan<'_> {
    type Value = Option<String>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for ClaimScan<'_> {
    type Value = Option<String>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JWT claims object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut best: Option<(usize, String)> = None;
        while let Some(name) = map.next_key::<Text<'de>>()? {
            let rank = self
                .rank(&name.0)
                .filter(|rank| best.as_ref().is_none_or(|(held, _)| rank < held));
            let Some(rank) = rank else {
                map.next_value::<IgnoredAny>()?;
                continue;
            };
            if let Some(value) = map.next_value::<StrValue<'de>>()?.0
                && value.contains('@')
            {
                best = Some((rank, value.into_owned()));
            }
        }
        Ok(best.map(|(_, value)| value))
    }
}

struct Text<'de>(Cow<'de, str>);

impl<'de> de::Deserialize<'de> for Text<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(TextVisitor)
    }
}

struct TextVisitor;

impl<'de> Visitor<'de> for TextVisitor {
    type Value = Text<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }

    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
        Ok(Text(Cow::Borrowed(v)))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(Text(Cow::Owned(v.to_owned())))
    }
}

struct StrValue<'de>(Option<Cow<'de, str>>);

impl<'de> de::Deserialize<'de> for StrValue<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrValueVisitor)
    }
}

struct StrValueVisitor;

impl<'de> Visitor<'de> for StrValueVisitor {
    type Value = StrValue<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
        Ok(StrValue(Some(Cow::Borrowed(v))))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        Ok(StrValue(Some(Cow::Owned(v.to_owned()))))
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Self::Value, E> {
        Ok(StrValue(None))
    }

    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Self::Value, E> {
        Ok(StrValue(None))
    }

    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Self::Value, E> {
        Ok(StrValue(None))
    }

    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Self::Value, E> {
        Ok(StrValue(None))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(StrValue(None))
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(StrValue(None))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
        Ok(StrValue(None))
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../proxy-tests/unit/src/token/tests.rs"]
mod tests;
