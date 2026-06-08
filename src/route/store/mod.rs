/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod file;
pub mod redis;
pub mod sql;

use crate::error::Result;

use file::FileStore;
use redis::RedisStore;
use sql::SqlStore;

pub enum MappingStore {
    File(FileStore),
    Redis(RedisStore),
    Sql(SqlStore),
}

impl MappingStore {
    pub async fn lookup(&self, key: &str) -> Result<Option<String>> {
        match self {
            MappingStore::File(s) => s.lookup(key),
            MappingStore::Redis(s) => s.lookup(key).await,
            MappingStore::Sql(s) => s.lookup(key).await,
        }
    }

    pub fn writable(&self) -> bool {
        match self {
            MappingStore::File(_) | MappingStore::Redis(_) => true,
            MappingStore::Sql(s) => s.writable(),
        }
    }

    pub async fn upsert(&self, key: &str, dest: &str) -> Result<()> {
        match self {
            MappingStore::File(s) => s.upsert(key, dest),
            MappingStore::Redis(s) => s.upsert(key, dest).await,
            MappingStore::Sql(s) => s.upsert(key, dest).await,
        }
    }

    pub async fn remove(&self, key: &str) -> Result<bool> {
        match self {
            MappingStore::File(s) => s.remove(key),
            MappingStore::Redis(s) => s.remove(key).await,
            MappingStore::Sql(s) => s.remove(key).await,
        }
    }

    pub async fn reload(&self) -> Result<()> {
        match self {
            MappingStore::File(s) => s.reload(),
            MappingStore::Redis(_) | MappingStore::Sql(_) => Ok(()),
        }
    }

    pub fn mapped_destinations(&self) -> Vec<String> {
        match self {
            MappingStore::File(s) => s.mapped_destinations(),
            MappingStore::Redis(_) | MappingStore::Sql(_) => Vec::new(),
        }
    }
}
