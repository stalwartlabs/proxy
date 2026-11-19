/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ahash::AHashMap;

use super::Config;
use crate::error::{ConfigError, ConfigErrors};

pub const CERTS_DIR: &str = "certs";
pub const MAPPINGS_DIR: &str = "mappings";
const SQLITE_SCHEME: &str = "sqlite:";
const SQLITE_MEMORY: &str = ":memory:";
const PERCENT: char = '%';

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ConfinedDir {
    Certs,
    Mappings,
}

#[derive(Clone, Debug)]
pub struct ConfigDir(PathBuf);

struct ConfinedPath<'a> {
    key: String,
    value: &'a str,
    dir: ConfinedDir,
}

impl ConfinedDir {
    pub fn name(self) -> &'static str {
        match self {
            ConfinedDir::Certs => CERTS_DIR,
            ConfinedDir::Mappings => MAPPINGS_DIR,
        }
    }
}

impl ConfigDir {
    pub fn of(config: &Path) -> io::Result<Self> {
        let config = fs::canonicalize(config)?;
        config
            .parent()
            .map(|dir| ConfigDir(dir.to_path_buf()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "config path has no parent"))
    }

    pub fn path(&self, dir: ConfinedDir) -> PathBuf {
        self.0.join(dir.name())
    }

    fn check(&self, value: &str, dir: ConfinedDir) -> Result<(), String> {
        let allowed = self.path(dir);
        let path = Path::new(value);
        if value.contains(PERCENT) {
            return Err(format!(
                "{value} contains '%'; percent-encoded paths are not accepted from the API"
            ));
        }
        if !path.is_absolute()
            || path.file_name().is_none()
            || path.parent() != Some(allowed.as_path())
        {
            return Err(format!(
                "API edits may only reference a file directly inside {}",
                allowed.display()
            ));
        }
        match fs::symlink_metadata(&allowed) {
            Ok(meta) if meta.is_dir() => {}
            _ => {
                return Err(format!(
                    "{} must be an existing directory, not a symlink",
                    allowed.display()
                ));
            }
        }
        match fs::symlink_metadata(path) {
            Ok(meta) if !meta.is_file() => Err(format!("{value} is not a regular file")),
            Ok(meta) if ConfigDir::is_linked(&meta) => {
                Err(format!("{value} has more than one hard link"))
            }
            Ok(_) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("{value}: {err}")),
        }
    }

    #[cfg(unix)]
    fn is_linked(meta: &fs::Metadata) -> bool {
        use std::os::unix::fs::MetadataExt;
        meta.nlink() > 1
    }

    #[cfg(not(unix))]
    fn is_linked(_meta: &fs::Metadata) -> bool {
        false
    }
}

impl Config {
    pub fn check_confined(
        &self,
        previous: Option<&Config>,
        root: Option<&ConfigDir>,
    ) -> Result<(), ConfigErrors> {
        let unchanged: AHashMap<String, &str> = previous
            .map(|previous| {
                previous
                    .confined_paths()
                    .into_iter()
                    .map(|path| (path.key, path.value))
                    .collect()
            })
            .unwrap_or_default();
        let mut errors = ConfigErrors::default();
        for path in self.confined_paths() {
            if unchanged.get(&path.key) == Some(&path.value) {
                continue;
            }
            let verdict = match root {
                Some(root) => root.check(path.value, path.dir),
                None => Err("the config file location is unknown; paths cannot be changed".into()),
            };
            if let Err(message) = verdict {
                errors.0.push(ConfigError::new(path.key, message));
            }
        }
        errors.into_result()
    }

    fn confined_paths(&self) -> Vec<ConfinedPath<'_>> {
        let mut paths = Vec::new();
        for (id, cert) in &self.tls.certificate {
            paths.push(ConfinedPath {
                key: format!("tls.certificate.{id}.cert"),
                value: &cert.cert,
                dir: ConfinedDir::Certs,
            });
            paths.push(ConfinedPath {
                key: format!("tls.certificate.{id}.key"),
                value: &cert.key,
                dir: ConfinedDir::Certs,
            });
        }
        for (name, dest) in &self.destination {
            for (field, value) in [
                ("tls_client_cert", &dest.tls_client_cert),
                ("tls_client_key", &dest.tls_client_key),
            ] {
                if let Some(value) = value {
                    paths.push(ConfinedPath {
                        key: format!("destination.{name}.{field}"),
                        value,
                        dir: ConfinedDir::Certs,
                    });
                }
            }
        }
        if let Some(mapping) = &self.mapping {
            if let Some(file) = &mapping.file {
                paths.push(ConfinedPath {
                    key: "mapping.file.path".to_string(),
                    value: &file.path,
                    dir: ConfinedDir::Mappings,
                });
            }
            if let Some(value) = mapping
                .sql
                .as_ref()
                .and_then(|sql| sqlite_path(sql.url.expose()))
            {
                paths.push(ConfinedPath {
                    key: "mapping.sql.url".to_string(),
                    value,
                    dir: ConfinedDir::Mappings,
                });
            }
        }
        paths
    }
}

fn sqlite_path(url: &str) -> Option<&str> {
    let rest = url
        .get(..SQLITE_SCHEME.len())
        .filter(|scheme| scheme.eq_ignore_ascii_case(SQLITE_SCHEME))
        .and_then(|_| url.get(SQLITE_SCHEME.len()..))?;
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    let path = rest.split_once('?').map_or(rest, |(path, _)| path);
    match path {
        SQLITE_MEMORY => None,
        path => Some(path),
    }
}
