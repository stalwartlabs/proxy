/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use testcontainers::runners::AsyncRunner;
use testcontainers_modules::postgres::Postgres;

use crate::config::SqlMappingConfig;
use crate::route::store::sql::SqlStore;

#[tokio::test]
async fn sql_store_resolves_and_misses() {
    let node = Postgres::default().start().await.unwrap();
    let port = node.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    sqlx::any::install_default_drivers();
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    sqlx::query("CREATE TABLE routes (identifier TEXT PRIMARY KEY, destination TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO routes (identifier, destination) VALUES ($1, $2)")
        .bind("user@example.com")
        .bind("primary")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let cfg = SqlMappingConfig {
        url: url.clone(),
        query: "SELECT destination FROM routes WHERE identifier = $1".to_string(),
        pool_size: 3,
        upsert_query: None,
        delete_query: None,
    };
    let store = SqlStore::connect(&cfg).await.unwrap();

    assert_eq!(
        store.lookup("user@example.com").await.unwrap(),
        Some("primary".to_string())
    );
    assert_eq!(store.lookup("nobody@example.com").await.unwrap(), None);
    assert!(!store.writable());
}

#[tokio::test]
async fn sql_store_upsert_and_remove() {
    let node = Postgres::default().start().await.unwrap();
    let port = node.get_host_port_ipv4(5432).await.unwrap();
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    sqlx::any::install_default_drivers();
    let pool = sqlx::AnyPool::connect(&url).await.unwrap();
    sqlx::query("CREATE TABLE routes (identifier TEXT PRIMARY KEY, destination TEXT NOT NULL)")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;

    let cfg = SqlMappingConfig {
        url,
        query: "SELECT destination FROM routes WHERE identifier = $1".to_string(),
        pool_size: 3,
        upsert_query: Some(
            "INSERT INTO routes (identifier, destination) VALUES ($1, $2) ON CONFLICT (identifier) DO UPDATE SET destination = $2"
                .to_string(),
        ),
        delete_query: Some("DELETE FROM routes WHERE identifier = $1".to_string()),
    };
    let store = SqlStore::connect(&cfg).await.unwrap();
    assert!(store.writable());

    store.upsert("user@example.com", "primary").await.unwrap();
    assert_eq!(
        store.lookup("user@example.com").await.unwrap(),
        Some("primary".to_string())
    );

    store.upsert("user@example.com", "secondary").await.unwrap();
    assert_eq!(
        store.lookup("user@example.com").await.unwrap(),
        Some("secondary".to_string())
    );

    assert!(store.remove("user@example.com").await.unwrap());
    assert!(!store.remove("user@example.com").await.unwrap());
    assert_eq!(store.lookup("user@example.com").await.unwrap(), None);
}
