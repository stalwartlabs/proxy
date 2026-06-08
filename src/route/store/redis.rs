/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::{AtomicUsize, Ordering};

use redis::aio::ConnectionManager;

use crate::config::RedisMappingConfig;
use crate::error::{ProxyError, Result};

pub struct RedisStore {
    key_prefix: String,
    pool: Vec<ConnectionManager>,
    next: AtomicUsize,
}

impl RedisStore {
    pub async fn connect(cfg: &RedisMappingConfig) -> Result<Self> {
        let client = redis::Client::open(cfg.url.as_str())
            .map_err(|e| ProxyError::config(format!("invalid redis url: {e}")))?;
        let size = cfg.pool_size.max(1);
        let mut pool = Vec::with_capacity(size);
        for _ in 0..size {
            let conn = ConnectionManager::new(client.clone())
                .await
                .map_err(|e| ProxyError::backend(format!("redis connect: {e}")))?;
            pool.push(conn);
        }
        Ok(RedisStore {
            key_prefix: cfg.key_prefix.clone(),
            pool,
            next: AtomicUsize::new(0),
        })
    }

    fn conn(&self) -> ConnectionManager {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        self.pool[idx].clone()
    }

    pub async fn lookup(&self, key: &str) -> Result<Option<String>> {
        let mut conn = self.conn();
        let full_key = format!("{}{}", self.key_prefix, key);
        let value: Option<String> = redis::cmd("GET")
            .arg(full_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| ProxyError::backend(format!("redis GET: {e}")))?;
        Ok(value.filter(|v| !v.is_empty()))
    }

    pub async fn upsert(&self, key: &str, dest: &str) -> Result<()> {
        let mut conn = self.conn();
        let full_key = format!("{}{}", self.key_prefix, key);
        let _: () = redis::cmd("SET")
            .arg(full_key)
            .arg(dest)
            .query_async(&mut conn)
            .await
            .map_err(|e| ProxyError::backend(format!("redis SET: {e}")))?;
        Ok(())
    }

    pub async fn remove(&self, key: &str) -> Result<bool> {
        let mut conn = self.conn();
        let full_key = format!("{}{}", self.key_prefix, key);
        let removed: i64 = redis::cmd("DEL")
            .arg(full_key)
            .query_async(&mut conn)
            .await
            .map_err(|e| ProxyError::backend(format!("redis DEL: {e}")))?;
        Ok(removed > 0)
    }
}
