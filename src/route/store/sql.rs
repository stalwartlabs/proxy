/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use futures_util::TryStreamExt;
use sqlx::any::{AnyPoolOptions, install_default_drivers};
use sqlx::{AnyPool, AssertSqlSafe};

use super::{DestCounts, MappingEntry, Page, Upsert};
use crate::config::SqlMappingConfig;
use crate::error::{ProxyError, Result};
use crate::runtime::IdTable;

const LIKE_ESCAPE: char = '\\';

pub struct SqlStore {
    pool: AnyPool,
    query: Arc<str>,
    upsert_query: Option<Arc<str>>,
    delete_query: Option<Arc<str>>,
    list_query: Option<Arc<str>>,
    count_query: Option<Arc<str>>,
}

impl SqlStore {
    fn failed(op: &'static str) -> impl FnOnce(sqlx::Error) -> ProxyError {
        move |e| ProxyError::store(format!("sql {op}: {e}"))
    }

    pub async fn connect(cfg: &SqlMappingConfig) -> Result<Self> {
        install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(u32::try_from(cfg.pool_size.max(1)).unwrap_or(u32::MAX))
            .test_before_acquire(false)
            .connect(cfg.url.expose())
            .await
            .map_err(SqlStore::failed("connect"))?;
        let shared = |query: &Option<String>| query.as_deref().map(Arc::from);
        Ok(SqlStore {
            pool,
            query: Arc::from(cfg.query.as_str()),
            upsert_query: shared(&cfg.upsert_query),
            delete_query: shared(&cfg.delete_query),
            list_query: shared(&cfg.list_query),
            count_query: shared(&cfg.count_query),
        })
    }

    pub async fn lookup(&self, key: &str) -> Result<Option<Box<str>>> {
        let dest: Option<Option<String>> = sqlx::query_scalar(AssertSqlSafe(self.query.clone()))
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(SqlStore::failed("query"))?;
        Ok(dest
            .flatten()
            .filter(|v| !v.is_empty())
            .map(String::into_boxed_str))
    }

    pub fn writable(&self) -> bool {
        self.upsert_query.is_some() && self.delete_query.is_some()
    }

    pub fn listable(&self) -> bool {
        self.list_query.is_some()
    }

    pub async fn upsert_many(&self, entries: &[Upsert<'_>]) -> Result<u64> {
        let upsert = self.upsert_query.as_ref().ok_or_else(|| {
            ProxyError::config("sql mapping store has no upsert_query configured")
        })?;
        let mut tx = self.pool.begin().await.map_err(SqlStore::failed("begin"))?;
        let mut created = 0;
        for entry in entries {
            let existing: Option<Option<String>> =
                sqlx::query_scalar(AssertSqlSafe(self.query.clone()))
                    .bind(entry.key)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(SqlStore::failed("query"))?;
            if existing.flatten().is_none_or(|v| v.is_empty()) {
                created += 1;
            }
            sqlx::query(AssertSqlSafe(upsert.clone()))
                .bind(entry.key)
                .bind(&*entry.name)
                .execute(&mut *tx)
                .await
                .map_err(SqlStore::failed("upsert"))?;
        }
        tx.commit().await.map_err(SqlStore::failed("commit"))?;
        Ok(created)
    }

    pub async fn remove(&self, key: &str) -> Result<bool> {
        let query = self.delete_query.as_ref().ok_or_else(|| {
            ProxyError::config("sql mapping store has no delete_query configured")
        })?;
        let result = sqlx::query(AssertSqlSafe(query.clone()))
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(SqlStore::failed("delete"))?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn list(&self, prefix: &str, cursor: Option<&str>, limit: usize) -> Result<Page> {
        let Some(query) = &self.list_query else {
            return Ok(Page::default());
        };
        let mut pattern = String::with_capacity(prefix.len() * 2 + 1);
        for ch in prefix.chars() {
            if matches!(ch, '%' | '_' | LIKE_ESCAPE) {
                pattern.push(LIKE_ESCAPE);
            }
            pattern.push(ch);
        }
        pattern.push('%');
        let fetch = i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX);
        let mut rows = sqlx::query_as::<_, (String, Option<String>)>(AssertSqlSafe(query.clone()))
            .bind(pattern)
            .bind(cursor.unwrap_or_default())
            .bind(fetch)
            .fetch(&self.pool);
        let mut items = Vec::with_capacity(limit);
        let mut more = false;
        while let Some((key, dest)) = rows.try_next().await.map_err(SqlStore::failed("list"))? {
            if items.len() == limit {
                more = true;
                break;
            }
            if let Some(dest) = dest.filter(|d| !d.is_empty()) {
                items.push(MappingEntry {
                    key: Arc::from(key),
                    destination: Arc::from(dest),
                });
            }
        }
        let next_cursor = if more {
            items.last().map(|entry| Box::from(&*entry.key))
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }

    async fn counts(&self) -> Result<Option<Vec<(String, i64)>>> {
        let Some(query) = &self.count_query else {
            return Ok(None);
        };
        sqlx::query_as::<_, (String, i64)>(AssertSqlSafe(query.clone()))
            .fetch_all(&self.pool)
            .await
            .map(Some)
            .map_err(SqlStore::failed("count"))
    }

    pub async fn count(&self) -> Result<Option<u64>> {
        Ok(self.counts().await?.map(|rows| {
            rows.iter()
                .map(|(_, count)| u64::try_from(*count).unwrap_or(0))
                .fold(0, u64::saturating_add)
        }))
    }

    pub async fn count_by_destination(&self, ids: &IdTable) -> Result<Option<DestCounts>> {
        Ok(self.counts().await?.map(|rows| {
            let mut counts = DestCounts::with_capacity(rows.len());
            for (name, count) in rows {
                if let Some(id) = ids.dest_id(&name) {
                    let total = counts.entry(id).or_default();
                    *total = total.saturating_add(u64::try_from(count).unwrap_or(0));
                }
            }
            counts
        }))
    }
}
