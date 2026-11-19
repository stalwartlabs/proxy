/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod file;
pub mod redis;
pub mod sql;

use std::sync::Arc;

use ahash::AHashMap;

use crate::config::{MappingConfig, MappingSource};
use crate::error::{ProxyError, Result};
use crate::runtime::{DestId, IdTable};

use file::{FileStore, PendingMappings};
use redis::RedisStore;
use sql::SqlStore;

pub enum MappingStore {
    Empty,
    File(FileStore),
    Redis(RedisStore),
    Sql(SqlStore),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stored {
    Dest(DestId),
    Name(Box<str>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingEntry {
    pub key: Arc<str>,
    pub destination: Arc<str>,
}

#[derive(Debug, Default)]
pub struct Page {
    pub items: Vec<MappingEntry>,
    pub next_cursor: Option<Box<str>>,
}

pub struct Upsert<'a> {
    pub key: &'a str,
    pub dest: DestId,
    pub name: Arc<str>,
}

pub type DestCounts = AHashMap<DestId, u64>;

impl MappingStore {
    pub async fn build(
        mapping: &MappingConfig,
        dest_names: &AHashMap<Box<str>, DestId>,
    ) -> Result<Self> {
        Ok(match mapping.source {
            MappingSource::File => {
                let cfg = mapping.file.as_ref().ok_or_else(|| {
                    ProxyError::config("mapping.source=file requires [mapping.file]")
                })?;
                MappingStore::File(
                    FileStore::open(cfg.path.clone(), mapping.normalize, dest_names.clone())
                        .await?,
                )
            }
            MappingSource::Redis => {
                let cfg = mapping.redis.as_ref().ok_or_else(|| {
                    ProxyError::config("mapping.source=redis requires [mapping.redis]")
                })?;
                MappingStore::Redis(RedisStore::connect(cfg).await?)
            }
            MappingSource::Sql => {
                let cfg = mapping.sql.as_ref().ok_or_else(|| {
                    ProxyError::config("mapping.source=sql requires [mapping.sql]")
                })?;
                MappingStore::Sql(SqlStore::connect(cfg).await?)
            }
        })
    }

    pub async fn lookup(&self, key: &str) -> Result<Option<Stored>> {
        match self {
            MappingStore::Empty => Ok(None),
            MappingStore::File(s) => Ok(s.lookup(key).map(Stored::Dest)),
            MappingStore::Redis(s) => Ok(s.lookup(key).await?.map(Stored::Name)),
            MappingStore::Sql(s) => Ok(s.lookup(key).await?.map(Stored::Name)),
        }
    }

    pub fn writable(&self) -> bool {
        match self {
            MappingStore::Empty => false,
            MappingStore::File(_) | MappingStore::Redis(_) => true,
            MappingStore::Sql(s) => s.writable(),
        }
    }

    pub fn listable(&self) -> bool {
        match self {
            MappingStore::Empty => false,
            MappingStore::File(_) | MappingStore::Redis(_) => true,
            MappingStore::Sql(s) => s.listable(),
        }
    }

    pub async fn list(&self, prefix: &str, cursor: Option<&str>, limit: usize) -> Result<Page> {
        match self {
            MappingStore::Empty => Ok(Page::default()),
            MappingStore::File(s) => s.list(prefix, cursor, limit).await,
            MappingStore::Redis(s) => s.list(prefix, cursor, limit).await,
            MappingStore::Sql(s) => s.list(prefix, cursor, limit).await,
        }
    }

    pub async fn count(&self) -> Result<Option<u64>> {
        match self {
            MappingStore::Empty => Ok(Some(0)),
            MappingStore::File(s) => Ok(Some(s.count())),
            MappingStore::Redis(_) => Ok(None),
            MappingStore::Sql(s) => s.count().await,
        }
    }

    pub async fn count_by_destination(&self, ids: &IdTable) -> Result<Option<DestCounts>> {
        match self {
            MappingStore::Empty => Ok(Some(DestCounts::default())),
            MappingStore::File(s) => Ok(Some(s.count_by_destination())),
            MappingStore::Redis(_) => Ok(None),
            MappingStore::Sql(s) => s.count_by_destination(ids).await,
        }
    }

    pub async fn upsert_many(&self, entries: &[Upsert<'_>]) -> Result<u64> {
        match self {
            MappingStore::Empty => Err(MappingStore::not_configured()),
            MappingStore::File(s) => s.upsert_many(entries).await,
            MappingStore::Redis(s) => s.upsert_many(entries).await,
            MappingStore::Sql(s) => s.upsert_many(entries).await,
        }
    }

    pub async fn remove(&self, key: &str) -> Result<bool> {
        match self {
            MappingStore::Empty => Err(MappingStore::not_configured()),
            MappingStore::File(s) => s.remove(key).await,
            MappingStore::Redis(s) => s.remove(key).await,
            MappingStore::Sql(s) => s.remove(key).await,
        }
    }

    pub async fn reload(&self) -> Result<()> {
        match self {
            MappingStore::File(s) => s.reload().await,
            MappingStore::Empty | MappingStore::Redis(_) | MappingStore::Sql(_) => Ok(()),
        }
    }

    pub async fn prepare_reload(&self) -> Result<Option<PendingMappings>> {
        match self {
            MappingStore::File(s) => s.prepare_reload().await.map(Some),
            MappingStore::Empty | MappingStore::Redis(_) | MappingStore::Sql(_) => Ok(None),
        }
    }

    pub fn install(&self, pending: PendingMappings) -> bool {
        match self {
            MappingStore::File(s) => s.install(pending),
            MappingStore::Empty | MappingStore::Redis(_) | MappingStore::Sql(_) => false,
        }
    }

    pub fn mapped_destinations(&self) -> Vec<Arc<str>> {
        match self {
            MappingStore::File(s) => s.mapped_destinations(),
            MappingStore::Empty | MappingStore::Redis(_) | MappingStore::Sql(_) => Vec::new(),
        }
    }

    #[cold]
    fn not_configured() -> ProxyError {
        ProxyError::config("no [mapping] store is configured")
    }
}
