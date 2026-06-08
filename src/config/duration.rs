/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use serde::{Deserialize, Deserializer};

pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let split = s
        .find(|c: char| c.is_ascii_alphabetic())
        .ok_or_else(|| format!("missing duration unit in {s:?}"))?;
    let (num, unit) = s.split_at(split);
    let value: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid duration value in {s:?}"))?;
    let multiplier = match unit.trim() {
        "ms" => return Ok(Duration::from_millis(value)),
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        other => return Err(format!("unknown duration unit {other:?}")),
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("10m").unwrap(), Duration::from_secs(600));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert!(parse_duration("").is_err());
        assert!(parse_duration("10x").is_err());
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn rejects_overflow_instead_of_wrapping() {
        let err = parse_duration("100000000000000000000d").unwrap_err();
        assert!(err.contains("invalid duration value") || err.contains("overflow"));
        let err = parse_duration("18446744073709551615d").unwrap_err();
        assert!(err.contains("overflow"));
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(parse_duration("  30s ").unwrap(), Duration::from_secs(30));
    }
}
