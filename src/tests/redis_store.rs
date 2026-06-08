/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use testcontainers::runners::AsyncRunner;
use testcontainers_modules::redis::{REDIS_PORT, Redis};

use crate::config::RedisMappingConfig;
use crate::route::store::redis::RedisStore;

#[tokio::test]
async fn redis_store_resolves_and_misses() {
    let node = Redis::default().start().await.unwrap();
    let port = node.get_host_port_ipv4(REDIS_PORT).await.unwrap();
    let url = format!("redis://127.0.0.1:{port}");

    let client = redis::Client::open(url.as_str()).unwrap();
    let mut conn = loop {
        match client.get_multiplexed_async_connection().await {
            Ok(c) => break c,
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
        }
    };
    let _: () = redis::cmd("SET")
        .arg("route:user@example.com")
        .arg("primary")
        .query_async(&mut conn)
        .await
        .unwrap();
    let _: () = redis::cmd("SET")
        .arg("route:empty@example.com")
        .arg("")
        .query_async(&mut conn)
        .await
        .unwrap();

    let cfg = RedisMappingConfig {
        url,
        key_prefix: "route:".to_string(),
        pool_size: 3,
    };
    let store = RedisStore::connect(&cfg).await.unwrap();

    assert_eq!(
        store.lookup("user@example.com").await.unwrap(),
        Some("primary".to_string())
    );
    assert_eq!(store.lookup("nobody@example.com").await.unwrap(), None);
    assert_eq!(store.lookup("empty@example.com").await.unwrap(), None);

    store
        .upsert("alice@example.com", "secondary")
        .await
        .unwrap();
    assert_eq!(
        store.lookup("alice@example.com").await.unwrap(),
        Some("secondary".to_string())
    );
    store.upsert("alice@example.com", "tertiary").await.unwrap();
    assert_eq!(
        store.lookup("alice@example.com").await.unwrap(),
        Some("tertiary".to_string())
    );
    assert!(store.remove("alice@example.com").await.unwrap());
    assert!(!store.remove("alice@example.com").await.unwrap());
    assert_eq!(store.lookup("alice@example.com").await.unwrap(), None);
}
