/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use tokio::sync::Mutex;
use tokio::task::{JoinError, spawn_blocking};

use super::{DestCounts, MappingEntry, Page, Upsert};
use crate::config::Normalize;
use crate::error::{ProxyError, Result};
use crate::route::key::needs_lowercase;
use crate::runtime::DestId;
use crate::token::valid_routing_identifier;

type Mappings = AHashMap<Arc<str>, DestId>;
type SortedView = Box<[(Arc<str>, DestId)]>;

const PERSIST_BYTES_PER_ENTRY: usize = 32;

struct Snapshot {
    map: Mappings,
    sorted: OnceLock<SortedView>,
    counts: OnceLock<Box<[u64]>>,
}

impl Snapshot {
    fn new(map: Mappings) -> Self {
        Snapshot {
            map,
            sorted: OnceLock::new(),
            counts: OnceLock::new(),
        }
    }

    fn sorted(&self) -> &[(Arc<str>, DestId)] {
        self.sorted.get_or_init(|| {
            let mut entries: Vec<(Arc<str>, DestId)> = self
                .map
                .iter()
                .map(|(key, dest)| (key.clone(), *dest))
                .collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            entries.into_boxed_slice()
        })
    }

    fn counts(&self, destinations: usize) -> &[u64] {
        self.counts.get_or_init(|| {
            let mut counts = vec![0u64; destinations];
            for dest in self.map.values() {
                if let Some(count) = counts.get_mut(dest.index()) {
                    *count += 1;
                }
            }
            counts.into_boxed_slice()
        })
    }
}

pub struct PendingMappings {
    base: Arc<Snapshot>,
    next: Arc<Snapshot>,
    names: Arc<[Option<Arc<str>>]>,
}

impl PendingMappings {
    pub fn destinations(&self) -> impl Iterator<Item = &str> {
        self.next
            .counts(self.names.len())
            .iter()
            .zip(self.names.iter())
            .filter(|(count, _)| **count > 0)
            .filter_map(|(_, name)| name.as_deref())
    }
}

struct Source {
    path: Box<str>,
    normalize: Normalize,
    valid: AHashMap<Box<str>, DestId>,
    names: Arc<[Option<Arc<str>>]>,
}

impl Source {
    fn name(&self, dest: DestId) -> Option<&Arc<str>> {
        self.names.get(dest.index()).and_then(Option::as_ref)
    }

    fn load(&self) -> Result<Mappings> {
        let path = &self.path;
        let data = std::fs::read_to_string(&**path)
            .map_err(|e| ProxyError::config(format!("failed to read mapping file {path}: {e}")))?;
        let mut map = Mappings::new();
        for (lineno, line) in data.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let (Some(id), Some(dest)) = (fields.next(), fields.next()) else {
                return Err(ProxyError::config(format!(
                    "mapping file {path}:{} is not <identifier> <destination>",
                    lineno + 1
                )));
            };
            let Some(dest) = self.valid.get(dest) else {
                return Err(ProxyError::config(format!(
                    "mapping file {path}:{} references an undeclared destination",
                    lineno + 1
                )));
            };
            let key: Arc<str> = match self.normalize {
                Normalize::Lowercase if needs_lowercase(id) => Arc::from(id.to_lowercase()),
                Normalize::Lowercase | Normalize::None => Arc::from(id),
            };
            map.insert(key, *dest);
        }
        Ok(map)
    }

    fn persist(&self, snapshot: &Snapshot) -> Result<()> {
        let sorted = snapshot.sorted();
        let mut out = Vec::with_capacity(sorted.len().saturating_mul(PERSIST_BYTES_PER_ENTRY));
        for (key, dest) in sorted {
            let name = self.name(*dest).ok_or_else(|| {
                ProxyError::store(format!("mapping for {key:?} has an unknown destination"))
            })?;
            out.extend_from_slice(key.as_bytes());
            out.push(b'\t');
            out.extend_from_slice(name.as_bytes());
            out.push(b'\n');
        }
        let path = &self.path;
        let tmp = format!("{path}.tmp");
        let write_err = |e: std::io::Error| {
            ProxyError::store(format!("failed to write mapping file {tmp}: {e}"))
        };
        let mut file = File::create(&tmp).map_err(write_err)?;
        file.write_all(&out).map_err(write_err)?;
        file.sync_all().map_err(write_err)?;
        drop(file);
        std::fs::rename(&tmp, &**path).map_err(|e| {
            ProxyError::store(format!("failed to replace mapping file {path}: {e}"))
        })?;
        sync_parent(Path::new(&**path));
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent(path: &Path) {
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    if let Err(err) = File::open(dir).and_then(|dir| dir.sync_all()) {
        tracing::warn!(error = %err, "failed to sync mapping file directory");
    }
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) {}

fn tsv_safe(key: &str) -> bool {
    !key.is_empty()
        && !key.starts_with('#')
        && valid_routing_identifier(key)
        && !key.chars().any(char::is_whitespace)
}

pub struct FileStore {
    source: Arc<Source>,
    snapshot: ArcSwap<Snapshot>,
    writer: Mutex<()>,
}

impl FileStore {
    #[cold]
    fn task_failed(err: JoinError) -> ProxyError {
        ProxyError::store(format!("mapping file task failed: {err}"))
    }
    pub async fn open(
        path: String,
        normalize: Normalize,
        valid: AHashMap<Box<str>, DestId>,
    ) -> Result<Self> {
        let len = valid.values().map(|id| id.index() + 1).max().unwrap_or(0);
        let mut names: Vec<Option<Arc<str>>> = vec![None; len];
        for (name, id) in &valid {
            if let Some(slot) = names.get_mut(id.index()) {
                *slot = Some(Arc::from(&**name));
            }
        }
        let source = Arc::new(Source {
            path: path.into(),
            normalize,
            valid,
            names: names.into(),
        });
        let map = Self::load(&source).await?;
        Ok(FileStore {
            source,
            snapshot: ArcSwap::from_pointee(Snapshot::new(map)),
            writer: Mutex::new(()),
        })
    }

    async fn load(source: &Arc<Source>) -> Result<Mappings> {
        let source = source.clone();
        spawn_blocking(move || source.load())
            .await
            .map_err(FileStore::task_failed)?
    }

    pub fn lookup(&self, key: &str) -> Option<DestId> {
        self.snapshot.load().map.get(key).copied()
    }

    pub fn count(&self) -> u64 {
        u64::try_from(self.snapshot.load().map.len()).unwrap_or(u64::MAX)
    }

    pub fn count_by_destination(&self) -> DestCounts {
        let snapshot = self.snapshot.load();
        snapshot
            .counts(self.source.names.len())
            .iter()
            .enumerate()
            .filter(|(_, count)| **count > 0)
            .filter_map(|(index, count)| DestId::new(index).map(|id| (id, *count)))
            .collect()
    }

    pub fn mapped_destinations(&self) -> Vec<Arc<str>> {
        let snapshot = self.snapshot.load();
        snapshot
            .counts(self.source.names.len())
            .iter()
            .zip(self.source.names.iter())
            .filter(|(count, _)| **count > 0)
            .filter_map(|(_, name)| name.clone())
            .collect()
    }

    pub async fn list(&self, prefix: &str, cursor: Option<&str>, limit: usize) -> Result<Page> {
        let snapshot = self.snapshot.load_full();
        if snapshot.sorted.get().is_none() {
            let building = snapshot.clone();
            spawn_blocking(move || {
                building.sorted();
            })
            .await
            .map_err(FileStore::task_failed)?;
        }
        let sorted = snapshot.sorted();
        let start = match cursor {
            Some(cursor) if cursor >= prefix => sorted.partition_point(|(key, _)| &**key <= cursor),
            _ => sorted.partition_point(|(key, _)| &**key < prefix),
        };
        let mut matching = sorted
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take_while(|(key, _)| key.starts_with(prefix));
        let mut items = Vec::with_capacity(limit.min(sorted.len()));
        for (key, dest) in matching.by_ref().take(limit) {
            let Some(name) = self.source.name(*dest) else {
                continue;
            };
            items.push(MappingEntry {
                key: key.clone(),
                destination: name.clone(),
            });
        }
        let next_cursor = match matching.next() {
            Some(_) => items.last().map(|entry| Box::from(&*entry.key)),
            None => None,
        };
        Ok(Page { items, next_cursor })
    }

    pub async fn upsert_many(&self, entries: &[Upsert<'_>]) -> Result<u64> {
        for entry in entries {
            if !tsv_safe(entry.key) {
                return Err(ProxyError::config(format!(
                    "identifier {:?} cannot be stored in a mapping file",
                    entry.key
                )));
            }
            if self.source.name(entry.dest).is_none() {
                return Err(ProxyError::config(format!(
                    "unknown destination {:?}",
                    entry.name
                )));
            }
        }
        let _writer = self.writer.lock().await;
        let current = self.snapshot.load_full();
        let mut map = current.map.clone();
        map.reserve(entries.len());
        let mut created = 0;
        let mut changed = false;
        for entry in entries {
            match map.get_mut(entry.key) {
                Some(dest) => {
                    changed |= *dest != entry.dest;
                    *dest = entry.dest;
                }
                None => {
                    map.insert(Arc::from(entry.key), entry.dest);
                    created += 1;
                    changed = true;
                }
            }
        }
        if changed {
            self.commit(Snapshot::new(map)).await?;
        }
        Ok(created)
    }

    pub async fn remove(&self, key: &str) -> Result<bool> {
        let _writer = self.writer.lock().await;
        let current = self.snapshot.load_full();
        if !current.map.contains_key(key) {
            return Ok(false);
        }
        let mut map = current.map.clone();
        map.remove(key);
        self.commit(Snapshot::new(map)).await?;
        Ok(true)
    }

    async fn commit(&self, snapshot: Snapshot) -> Result<()> {
        let snapshot = Arc::new(snapshot);
        let source = self.source.clone();
        let persisted = snapshot.clone();
        spawn_blocking(move || source.persist(&persisted))
            .await
            .map_err(FileStore::task_failed)??;
        self.snapshot.store(snapshot);
        Ok(())
    }

    pub async fn reload(&self) -> Result<()> {
        let _writer = self.writer.lock().await;
        let map = Self::load(&self.source).await?;
        self.snapshot.store(Arc::new(Snapshot::new(map)));
        Ok(())
    }

    pub async fn prepare_reload(&self) -> Result<PendingMappings> {
        let base = self.snapshot.load_full();
        let source = self.source.clone();
        let current = base.clone();
        let next = spawn_blocking(move || {
            let map = source.load()?;
            let next = match current.map == map {
                true => current,
                false => Arc::new(Snapshot::new(map)),
            };
            next.counts(source.names.len());
            Ok::<_, ProxyError>(next)
        })
        .await
        .map_err(FileStore::task_failed)??;
        Ok(PendingMappings {
            base,
            next,
            names: self.source.names.clone(),
        })
    }

    pub fn install(&self, pending: PendingMappings) -> bool {
        let PendingMappings { base, next, .. } = pending;
        if Arc::ptr_eq(&base, &next) {
            return false;
        }
        let previous = self.snapshot.compare_and_swap(&base, next);
        if Arc::ptr_eq(&previous, &base) {
            return true;
        }
        tracing::warn!("mappings were written during reload; keeping the live mappings");
        false
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../../proxy-tests/unit/src/route/store/file/tests.rs"]
mod tests;
