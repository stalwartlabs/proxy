/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use parking_lot::RwLock;

use crate::config::Normalize;
use crate::error::{ProxyError, Result};
use crate::route::normalize_key;

pub struct FileStore {
    path: String,
    normalize: Normalize,
    valid_destinations: AHashSet<String>,
    map: RwLock<Arc<AHashMap<Box<str>, Box<str>>>>,
}

impl FileStore {
    pub fn open(
        path: String,
        normalize: Normalize,
        valid_destinations: AHashSet<String>,
    ) -> Result<Self> {
        let map = Self::load(&path, normalize, &valid_destinations)?;
        Ok(FileStore {
            path,
            normalize,
            valid_destinations,
            map: RwLock::new(Arc::new(map)),
        })
    }

    fn load(
        path: &str,
        normalize: Normalize,
        valid: &AHashSet<String>,
    ) -> Result<AHashMap<Box<str>, Box<str>>> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| ProxyError::config(format!("failed to read mapping file {path}: {e}")))?;
        let mut map = AHashMap::new();
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
            if !valid.contains(dest) {
                return Err(ProxyError::config(format!(
                    "mapping file {path}:{} references undeclared destination {dest:?}",
                    lineno + 1
                )));
            }
            map.insert(normalize_key(id, normalize).into(), dest.into());
        }
        Ok(map)
    }

    fn snapshot(&self) -> Arc<AHashMap<Box<str>, Box<str>>> {
        self.map.read().clone()
    }

    pub fn lookup(&self, key: &str) -> Result<Option<String>> {
        Ok(self.snapshot().get(key).map(|v| v.to_string()))
    }

    pub fn mapped_destinations(&self) -> Vec<String> {
        self.snapshot()
            .values()
            .map(|v| v.to_string())
            .collect::<AHashSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn reload(&self) -> Result<()> {
        let map = Self::load(&self.path, self.normalize, &self.valid_destinations)?;
        *self.map.write() = Arc::new(map);
        Ok(())
    }

    pub fn upsert(&self, key: &str, dest: &str) -> Result<()> {
        let mut guard = self.map.write();
        let mut next = (**guard).clone();
        next.insert(key.into(), dest.into());
        let next = Arc::new(next);
        Self::persist(&self.path, &next)?;
        *guard = next;
        Ok(())
    }

    pub fn remove(&self, key: &str) -> Result<bool> {
        let mut guard = self.map.write();
        if !guard.contains_key(key) {
            return Ok(false);
        }
        let mut next = (**guard).clone();
        next.remove(key);
        let next = Arc::new(next);
        Self::persist(&self.path, &next)?;
        *guard = next;
        Ok(true)
    }

    fn persist(path: &str, map: &AHashMap<Box<str>, Box<str>>) -> Result<()> {
        let mut entries: Vec<(&str, &str)> =
            map.iter().map(|(k, v)| (k.as_ref(), v.as_ref())).collect();
        entries.sort_unstable();
        let mut out = String::new();
        for (id, dest) in entries {
            out.push_str(id);
            out.push('\t');
            out.push_str(dest);
            out.push('\n');
        }
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, out.as_bytes())
            .map_err(|e| ProxyError::config(format!("failed to write mapping file {tmp}: {e}")))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            ProxyError::config(format!("failed to replace mapping file {path}: {e}"))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> AHashSet<String> {
        ["legacy", "secondary"]
            .into_iter()
            .map(String::from)
            .collect()
    }

    fn store_with(contents: &str) -> (FileStore, tempfile::NamedTempFile) {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        let path = file.path().display().to_string();
        let store = FileStore::open(path, Normalize::Lowercase, valid()).unwrap();
        (store, file)
    }

    #[test]
    fn upsert_persists_and_reloads() {
        let (store, file) = store_with("user@example.com\tlegacy\n");
        store.upsert("alice@example.com", "secondary").unwrap();
        assert_eq!(
            store.lookup("alice@example.com").unwrap(),
            Some("secondary".to_string())
        );

        let on_disk = std::fs::read_to_string(file.path()).unwrap();
        assert!(on_disk.contains("alice@example.com\tsecondary"));
        assert!(on_disk.contains("user@example.com\tlegacy"));

        let reloaded = FileStore::open(
            file.path().display().to_string(),
            Normalize::Lowercase,
            valid(),
        )
        .unwrap();
        assert_eq!(
            reloaded.lookup("alice@example.com").unwrap(),
            Some("secondary".to_string())
        );
    }

    #[test]
    fn upsert_replaces_existing() {
        let (store, _file) = store_with("user@example.com\tlegacy\n");
        store.upsert("user@example.com", "secondary").unwrap();
        assert_eq!(
            store.lookup("user@example.com").unwrap(),
            Some("secondary".to_string())
        );
    }

    #[test]
    fn remove_reports_existence_and_persists() {
        let (store, file) = store_with("user@example.com\tlegacy\n");
        assert!(store.remove("user@example.com").unwrap());
        assert!(!store.remove("user@example.com").unwrap());
        assert_eq!(store.lookup("user@example.com").unwrap(), None);
        let on_disk = std::fs::read_to_string(file.path()).unwrap();
        assert!(!on_disk.contains("user@example.com"));
    }
}
