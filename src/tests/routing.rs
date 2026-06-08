/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::Ordering;

use crate::config::Config;
use crate::route::Router;

use super::harness::*;

fn config(mapping_path: &str) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{mapping_path}"

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"

[destination.primary]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.primary.protocol.imap]
port = 143
tls = "plain"
"#
    )
}

async fn build_router(toml: &str) -> Router {
    let config = Config::parse_and_validate(toml).expect("config should validate");
    let valid: Vec<String> = config.destination.keys().cloned().collect();
    Router::build(&config, valid).await.unwrap()
}

#[tokio::test]
async fn router_resolves_normalizes_and_caches() {
    let mapping = mapping_file("user@example.com\tprimary\n");
    let toml = config(&mapping.path().display().to_string());
    let router = build_router(&toml).await;

    assert_eq!(&*router.resolve(Some("user@example.com")).await, "primary");
    assert_eq!(&*router.resolve(Some("USER@EXAMPLE.COM")).await, "primary");
    assert_eq!(&*router.resolve(Some("nobody@x")).await, "legacy");
    assert_eq!(&*router.resolve(None).await, "legacy");

    router.invalidate("user@example.com").await;
    assert_eq!(&*router.resolve(Some("user@example.com")).await, "primary");
}

#[tokio::test]
async fn router_cache_hits_and_misses() {
    let mapping = mapping_file("user@example.com\tprimary\n");
    let toml = config(&mapping.path().display().to_string());
    let router = build_router(&toml).await;

    let misses_before = router.stats.misses.load(Ordering::Relaxed);
    let hits_before = router.stats.hits.load(Ordering::Relaxed);

    assert_eq!(&*router.resolve(Some("user@example.com")).await, "primary");
    let misses_after_first = router.stats.misses.load(Ordering::Relaxed);
    assert_eq!(misses_after_first, misses_before + 1);

    assert_eq!(&*router.resolve(Some("user@example.com")).await, "primary");
    let hits_after = router.stats.hits.load(Ordering::Relaxed);
    assert_eq!(hits_after, hits_before + 1);
    assert_eq!(
        router.stats.misses.load(Ordering::Relaxed),
        misses_after_first
    );

    assert_eq!(&*router.resolve(Some("nobody@x")).await, "legacy");
    assert_eq!(&*router.resolve(Some("nobody@x")).await, "legacy");
    assert_eq!(
        router.stats.hits.load(Ordering::Relaxed),
        hits_after + 1,
        "second negative lookup should be a cache hit"
    );
}

fn config_with_ttls(mapping_path: &str, positive: &str, negative: &str) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
positive_ttl = "{positive}"
negative_ttl = "{negative}"
[mapping.file]
path = "{mapping_path}"

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"

[destination.primary]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.primary.protocol.imap]
port = 143
tls = "plain"
"#
    )
}

#[tokio::test]
async fn positive_entry_expires_and_is_looked_up_again() {
    let mapping = mapping_file("user@example.com\tprimary\n");
    let toml = config_with_ttls(&mapping.path().display().to_string(), "60ms", "60ms");
    let router = build_router(&toml).await;

    assert_eq!(&*router.resolve(Some("user@example.com")).await, "primary");
    let misses_after_first = router.stats.misses.load(Ordering::Relaxed);
    assert_eq!(&*router.resolve(Some("user@example.com")).await, "primary");
    assert_eq!(
        router.stats.misses.load(Ordering::Relaxed),
        misses_after_first,
        "second lookup within TTL is a hit"
    );

    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    assert_eq!(&*router.resolve(Some("user@example.com")).await, "primary");
    assert!(
        router.stats.misses.load(Ordering::Relaxed) > misses_after_first,
        "lookup after TTL expiry must miss the cache and re-hit the store"
    );
}

#[tokio::test]
async fn invalidate_all_clears_every_entry() {
    let mapping = mapping_file("user@example.com\tprimary\n");
    let toml = config(&mapping.path().display().to_string());
    let router = build_router(&toml).await;

    assert_eq!(&*router.resolve(Some("user@example.com")).await, "primary");
    let misses = router.stats.misses.load(Ordering::Relaxed);
    router.invalidate_all();
    assert_eq!(&*router.resolve(Some("user@example.com")).await, "primary");
    assert!(
        router.stats.misses.load(Ordering::Relaxed) > misses,
        "after invalidate_all the entry must be re-fetched"
    );
}

#[tokio::test]
async fn reload_picks_up_edited_mapping() {
    let mapping = mapping_file("user@example.com\tprimary\n");
    let toml = config(&mapping.path().display().to_string());
    let router = build_router(&toml).await;

    assert_eq!(&*router.resolve(Some("user@example.com")).await, "primary");
    std::fs::write(mapping.path(), "user@example.com\tlegacy\n").unwrap();
    router.reload().await.unwrap();
    router.invalidate("user@example.com").await;
    assert_eq!(&*router.resolve(Some("user@example.com")).await, "legacy");
}

#[tokio::test]
async fn cache_respects_max_entries() {
    let mut lines = String::new();
    for i in 0..40 {
        lines.push_str(&format!("user{i}@example.com\tprimary\n"));
    }
    let mapping = mapping_file(&lines);
    let toml = config(&mapping.path().display().to_string()).replace(
        r#"normalize = "lowercase""#,
        "normalize = \"lowercase\"\ncache_max_entries = 10",
    );
    let router = build_router(&toml).await;

    for i in 0..40 {
        router.resolve(Some(&format!("user{i}@example.com"))).await;
    }

    let count = router.cache_entry_count().await;
    assert!(
        count <= 10,
        "cache must not exceed cache_max_entries, got {count}"
    );
}

#[tokio::test]
async fn normalize_none_preserves_case() {
    let mapping = mapping_file("User@Example.com\tprimary\n");
    let toml = config(&mapping.path().display().to_string())
        .replace(r#"normalize = "lowercase""#, r#"normalize = "none""#);
    let router = build_router(&toml).await;

    assert_eq!(&*router.resolve(Some("User@Example.com")).await, "primary");
    assert_eq!(&*router.resolve(Some("user@example.com")).await, "legacy");
}
