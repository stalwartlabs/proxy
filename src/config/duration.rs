/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use serde::{Deserialize, Deserializer, Serializer};

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let num = s.trim_end_matches(|c: char| c.is_ascii_alphabetic());
    let unit = s.strip_prefix(num).unwrap_or_default();
    if unit.is_empty() {
        return Err(format!("missing duration unit in {s:?}"));
    }
    let value: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration value in {s:?}"))?;
    let multiplier: u64 = hashify::fnc_map!(unit.as_bytes(),
        "ms" => {
            return Ok(Duration::from_millis(value));
        },
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => {
            return Err(format!("unknown duration unit {unit:?}"));
        }
    );
    let secs = value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration overflow in {s:?}"))?;
    Ok(Duration::from_secs(secs))
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    parse_duration(&s).map_err(serde::de::Error::custom)
}

const UNITS: [(u64, &str); 4] = [(86400, "d"), (3600, "h"), (60, "m"), (1, "s")];

pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let millis = duration.as_millis();
    if !millis.is_multiple_of(1000) {
        return serializer.collect_str(&format_args!("{millis}ms"));
    }
    let secs = duration.as_secs();
    let (multiplier, unit) = UNITS
        .into_iter()
        .find(|(multiplier, _)| secs.is_multiple_of(*multiplier) && secs >= *multiplier)
        .unwrap_or((1, "s"));
    serializer.collect_str(&format_args!("{}{unit}", secs / multiplier))
}

pub mod option {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        match Option::<String>::deserialize(deserializer)? {
            Some(s) => super::parse_duration(&s)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }

    pub fn serialize<S>(duration: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match duration {
            Some(duration) => super::serialize(duration, serializer),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/config/duration/tests.rs"]
mod tests;
