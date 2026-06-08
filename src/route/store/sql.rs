/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use sqlx::AnyPool;
use sqlx::any::{AnyPoolOptions, install_default_drivers};

use crate::config::SqlMappingConfig;
use crate::error::{ProxyError, Result};

pub struct SqlStore {
    pool: AnyPool,
    query: String,
    upsert_query: Option<String>,
    delete_query: Option<String>,
}

impl SqlStore {
    pub async fn connect(cfg: &SqlMappingConfig) -> Result<Self> {
        install_default_drivers();
        let pool = AnyPoolOptions::new()
            .max_connections(cfg.pool_size.max(1) as u32)
            .connect(&cfg.url)
            .await
            .map_err(|e| ProxyError::backend(format!("sql connect: {e}")))?;
        Ok(SqlStore {
            pool,
            query: cfg.query.clone(),
            upsert_query: cfg.upsert_query.clone(),
            delete_query: cfg.delete_query.clone(),
        })
    }

    pub async fn lookup(&self, key: &str) -> Result<Option<String>> {
        let dest: Option<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(self.query.clone()))
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ProxyError::backend(format!("sql query: {e}")))?;
        Ok(dest.filter(|v| !v.is_empty()))
    }

    pub fn writable(&self) -> bool {
        self.upsert_query.is_some() && self.delete_query.is_some()
    }

    pub async fn upsert(&self, key: &str, dest: &str) -> Result<()> {
        let query = self.upsert_query.as_ref().ok_or_else(|| {
            ProxyError::config("sql mapping store has no upsert_query configured")
        })?;
        sqlx::query(sqlx::AssertSqlSafe(query.clone()))
            .bind(key)
            .bind(dest)
            .execute(&self.pool)
            .await
            .map_err(|e| ProxyError::backend(format!("sql upsert: {e}")))?;
        Ok(())
    }

    pub async fn remove(&self, key: &str) -> Result<bool> {
        let query = self.delete_query.as_ref().ok_or_else(|| {
            ProxyError::config("sql mapping store has no delete_query configured")
        })?;
        let result = sqlx::query(sqlx::AssertSqlSafe(query.clone()))
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|e| ProxyError::backend(format!("sql delete: {e}")))?;
        Ok(result.rows_affected() > 0)
    }
}
