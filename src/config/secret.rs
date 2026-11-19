/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt;

use serde::{Deserialize, Serialize, Serializer};
use url::Url;

pub const MASK: &str = "********";

#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Secret(value)
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(MASK)
    }
}

impl<T> Serialize for Secret<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(MASK)
    }
}

#[derive(Clone, PartialEq, Deserialize)]
#[serde(transparent)]
pub struct SecretUrl(String);

impl SecretUrl {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretUrl {
    fn from(url: String) -> Self {
        SecretUrl(url)
    }
}

fn is_credential_key(key: &str) -> bool {
    hashify::set_ignore_case!(
        key.as_bytes(),
        "password",
        "passwd",
        "pass",
        "pwd",
        "sslpassword",
        "auth",
        "secret",
        "token",
    )
}

fn masked(mut url: Url) -> Option<Url> {
    if !url.username().is_empty() || url.password().is_some() {
        url.set_password(None).ok()?;
        url.set_username(MASK).ok()?;
    }
    url.set_fragment(None);
    if url.query_pairs().any(|(key, _)| is_credential_key(&key)) {
        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(key, value)| {
                let value = match is_credential_key(&key) {
                    true => MASK.to_string(),
                    false => value.into_owned(),
                };
                (key.into_owned(), value)
            })
            .collect();
        url.query_pairs_mut().clear().extend_pairs(pairs);
    }
    Some(url)
}

impl fmt::Display for SecretUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match Url::parse(&self.0)
            .ok()
            .filter(Url::has_host)
            .and_then(masked)
        {
            Some(url) => f.write_str(url.as_str()),
            None => f.write_str(MASK),
        }
    }
}

impl fmt::Debug for SecretUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{self}\"")
    }
}

impl Serialize for SecretUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/config/secret/tests.rs"]
mod tests;
