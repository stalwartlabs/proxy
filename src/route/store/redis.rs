/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use redis::aio::ConnectionManager;

use super::{MappingEntry, Page, Upsert};
use crate::config::RedisMappingConfig;
use crate::error::{ProxyError, Result};

const MAX_SCAN_ROUNDS: usize = 16;
const MIN_SCAN_COUNT: usize = 100;

pub struct RedisStore {
    key_prefix: Box<str>,
    pool: Box<[ConnectionManager]>,
    next: AtomicUsize,
}

impl RedisStore {
    pub async fn connect(cfg: &RedisMappingConfig) -> Result<Self> {
        let client = redis::Client::open(cfg.url.expose())
            .map_err(|e| ProxyError::config(format!("invalid redis url: {e}")))?;
        let size = cfg.pool_size.max(1);
        let mut pool = Vec::with_capacity(size);
        for _ in 0..size {
            let conn = ConnectionManager::new(client.clone())
                .await
                .map_err(|e| ProxyError::store(format!("redis connect: {e}")))?;
            pool.push(conn);
        }
        Ok(RedisStore {
            key_prefix: cfg.key_prefix.as_str().into(),
            pool: pool.into_boxed_slice(),
            next: AtomicUsize::new(0),
        })
    }

    fn conn(&self) -> Result<ConnectionManager> {
        let idx = self.next.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        self.pool
            .get(idx)
            .cloned()
            .ok_or_else(|| ProxyError::store("redis pool is empty"))
    }

    fn full_key(&self, key: &str) -> String {
        let mut full = String::with_capacity(self.key_prefix.len() + key.len());
        full.push_str(&self.key_prefix);
        full.push_str(key);
        full
    }

    pub async fn lookup(&self, key: &str) -> Result<Option<Box<str>>> {
        let mut conn = self.conn()?;
        let value: Option<String> = redis::cmd("GET")
            .arg(self.full_key(key))
            .query_async(&mut conn)
            .await
            .map_err(|e| ProxyError::store(format!("redis GET: {e}")))?;
        Ok(value.filter(|v| !v.is_empty()).map(String::into_boxed_str))
    }

    pub async fn upsert_many(&self, entries: &[Upsert<'_>]) -> Result<u64> {
        if entries.is_empty() {
            return Ok(0);
        }
        let mut pipe = redis::pipe();
        pipe.atomic();
        for entry in entries {
            let key = self.full_key(entry.key);
            pipe.cmd("EXISTS").arg(&key);
            pipe.cmd("SET").arg(key).arg(&*entry.name).ignore();
        }
        let mut conn = self.conn()?;
        let existed: Vec<i64> = pipe
            .query_async(&mut conn)
            .await
            .map_err(|e| ProxyError::store(format!("redis SET: {e}")))?;
        Ok(existed.iter().filter(|exists| **exists == 0).count() as u64)
    }

    pub async fn remove(&self, key: &str) -> Result<bool> {
        let mut conn = self.conn()?;
        let removed: i64 = redis::cmd("DEL")
            .arg(self.full_key(key))
            .query_async(&mut conn)
            .await
            .map_err(|e| ProxyError::store(format!("redis DEL: {e}")))?;
        Ok(removed > 0)
    }

    pub async fn list(&self, prefix: &str, cursor: Option<&str>, limit: usize) -> Result<Page> {
        let mut scan_cursor: u64 = match cursor {
            Some(cursor) => cursor
                .parse()
                .map_err(|_| ProxyError::config("invalid mapping list cursor"))?,
            None => 0,
        };
        let mut pattern = String::with_capacity((self.key_prefix.len() + prefix.len()) * 2 + 1);
        escape_glob(&mut pattern, &self.key_prefix);
        escape_glob(&mut pattern, prefix);
        pattern.push('*');
        let count = limit.max(MIN_SCAN_COUNT);
        let mut conn = self.conn()?;
        let mut items = Vec::with_capacity(limit);
        for _ in 0..MAX_SCAN_ROUNDS {
            let (next, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(scan_cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(count)
                .query_async(&mut conn)
                .await
                .map_err(|e| ProxyError::store(format!("redis SCAN: {e}")))?;
            scan_cursor = next;
            if !keys.is_empty() {
                let values: Vec<Option<String>> = redis::cmd("MGET")
                    .arg(&keys)
                    .query_async(&mut conn)
                    .await
                    .map_err(|e| ProxyError::store(format!("redis MGET: {e}")))?;
                items.extend(keys.iter().zip(values).filter_map(|(key, value)| {
                    let key = key.strip_prefix(&*self.key_prefix)?;
                    let value = value.filter(|v| !v.is_empty())?;
                    Some(MappingEntry {
                        key: Arc::from(key),
                        destination: Arc::from(value),
                    })
                }));
            }
            if scan_cursor == 0 || items.len() >= limit {
                break;
            }
        }
        Ok(Page {
            items,
            next_cursor: (scan_cursor != 0).then(|| scan_cursor.to_string().into_boxed_str()),
        })
    }
}

fn escape_glob(out: &mut String, literal: &str) {
    for ch in literal.chars() {
        if matches!(ch, '*' | '?' | '[' | ']' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
}
