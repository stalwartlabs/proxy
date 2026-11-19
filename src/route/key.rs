/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Borrow;
use std::fmt;
use std::sync::Arc;

use memchr::memmem::Finder;

use crate::config::{Config, DEFAULT_JWT_CLAIM, Normalize};
use crate::token::valid_routing_identifier;

pub const MAX_ROUTING_KEY: usize = 320;
const MAX_CASE_FOLD_GROWTH: usize = 3;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RoutingKey(Arc<str>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    Invalid,
    TooLong,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeyError::Invalid => "routing identifier contains invalid characters",
            KeyError::TooLong => "routing identifier is too long",
        })
    }
}

pub struct KeyRules {
    separators: Box<[Finder<'static>]>,
    normalize: Normalize,
    max_len: usize,
    jwt_claim: Box<str>,
}

impl KeyRules {
    pub fn new(separators: &[String], normalize: Normalize, max_len: usize) -> Self {
        KeyRules {
            separators: separators
                .iter()
                .filter(|s| !s.is_empty())
                .map(|s| Finder::new(s.as_bytes()).into_owned())
                .collect(),
            normalize,
            max_len,
            jwt_claim: DEFAULT_JWT_CLAIM.into(),
        }
    }

    pub fn with_jwt_claim(mut self, claim: &str) -> Self {
        self.jwt_claim = claim.into();
        self
    }

    pub fn jwt_claim(&self) -> &str {
        &self.jwt_claim
    }

    pub fn from_config(config: &Config) -> Self {
        Self::new(
            config
                .routing
                .as_ref()
                .map_or(&[], |routing| routing.master_user_separators.as_slice()),
            config
                .mapping
                .as_ref()
                .map_or(Normalize::None, |mapping| mapping.normalize),
            MAX_ROUTING_KEY,
        )
        .with_jwt_claim(&config.oauth.jwt_username_claim)
    }

    pub fn account<'a>(&self, raw: &'a str) -> &'a str {
        let cut = self
            .separators
            .iter()
            .filter_map(|f| f.find(raw.as_bytes()))
            .min()
            .unwrap_or(raw.len());
        raw.get(..cut).unwrap_or(raw)
    }
}

pub struct Explained<'a> {
    pub account: &'a str,
    pub key: RoutingKey,
}

impl RoutingKey {
    pub fn parse(raw: &str, rules: &KeyRules) -> Result<Option<RoutingKey>, KeyError> {
        Ok(Self::parse_explained(raw, rules)?.map(|explained| explained.key))
    }

    pub fn parse_explained<'a>(
        raw: &'a str,
        rules: &KeyRules,
    ) -> Result<Option<Explained<'a>>, KeyError> {
        let account = rules.account(raw);
        if account.is_empty() {
            return Ok(None);
        }
        if !valid_routing_identifier(account) {
            return Err(KeyError::Invalid);
        }
        if account.len() > rules.max_len.saturating_mul(MAX_CASE_FOLD_GROWTH) {
            return Err(KeyError::TooLong);
        }
        let key: Arc<str> = match rules.normalize {
            Normalize::Lowercase if needs_lowercase(account) => Arc::from(account.to_lowercase()),
            Normalize::Lowercase | Normalize::None => Arc::from(account),
        };
        if key.len() > rules.max_len {
            return Err(KeyError::TooLong);
        }
        Ok(Some(Explained {
            account,
            key: RoutingKey(key),
        }))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn shared(&self) -> &Arc<str> {
        &self.0
    }
}

pub fn needs_lowercase(s: &str) -> bool {
    !s.is_ascii() || s.bytes().any(|b| b.is_ascii_uppercase())
}

impl Borrow<str> for RoutingKey {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for RoutingKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RoutingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RoutingKey").field(&self.0).finish()
    }
}
