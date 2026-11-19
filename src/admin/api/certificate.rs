/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use encodify::pem::{self, Block};
use memchr::memmem;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use serde_json::Value as Json;
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::config::Revision;
use crate::config::edit::{EditError, EditOp, History};
use crate::config::tls::DEFAULT_SUBJECT;
use crate::error::{ConfigError, ConfigErrors};
use crate::runtime::time::UtcTime;

pub const MAX_UPLOAD: usize = 256 * 1024;
const MAX_ID_LEN: usize = 64;
const MAX_CHAIN: usize = 16;
const CERT_DIR: &str = "certs";
const CERT_LABEL: &str = "CERTIFICATE";
const CERT_EXT: &str = "crt";
const KEY_EXT: &str = "key";

pub struct CertificateId(Box<str>);

impl CertificateId {
    pub fn parse(id: &str) -> Option<Self> {
        let valid = (1..=MAX_ID_LEN).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        valid.then(|| CertificateId(id.into()))
    }
}

pub struct Upload {
    pub id: CertificateId,
    pub pair: CertificatePair,
    pub body: UploadBody,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadBody {
    pub revision: String,
    pub cert: String,
    pub key: String,
    #[serde(default)]
    pub subjects: Option<Vec<String>>,
    #[serde(default)]
    pub default: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PemError {
    #[error("the certificate field must hold PEM CERTIFICATE blocks only")]
    CertificateSection,
    #[error("no certificate found")]
    NoCertificate,
    #[error("the certificate chain is too long")]
    ChainTooLong,
    #[error("a certificate is not valid X.509 DER")]
    InvalidCertificate,
    #[error("the key field must hold exactly one unencrypted PEM private key")]
    KeySection,
    #[error("encrypted private keys are not supported")]
    EncryptedKey,
    #[error("the private key is invalid or uses an unsupported algorithm")]
    InvalidKey,
    #[error("the private key does not match the certificate")]
    KeyMismatch,
}

impl PemError {
    pub fn code(self) -> &'static str {
        match self {
            PemError::CertificateSection
            | PemError::NoCertificate
            | PemError::ChainTooLong
            | PemError::InvalidCertificate => "invalid_certificate",
            PemError::KeySection | PemError::EncryptedKey | PemError::InvalidKey => "invalid_key",
            PemError::KeyMismatch => "key_mismatch",
        }
    }
}

#[derive(Clone, Copy)]
enum KeyFormat {
    Pkcs8,
    Pkcs1,
    Sec1,
    Encrypted,
}

impl KeyFormat {
    fn of(label: &str) -> Option<KeyFormat> {
        hashify::map!(
            label.as_bytes(),
            KeyFormat,
            "PRIVATE KEY" => KeyFormat::Pkcs8,
            "RSA PRIVATE KEY" => KeyFormat::Pkcs1,
            "EC PRIVATE KEY" => KeyFormat::Sec1,
            "ENCRYPTED PRIVATE KEY" => KeyFormat::Encrypted,
        )
        .copied()
    }

    fn der(self, contents: Vec<u8>) -> Result<PrivateKeyDer<'static>, PemError> {
        match self {
            KeyFormat::Pkcs8 => Ok(PrivatePkcs8KeyDer::from(contents).into()),
            KeyFormat::Pkcs1 => Ok(PrivatePkcs1KeyDer::from(contents).into()),
            KeyFormat::Sec1 => Ok(PrivateSec1KeyDer::from(contents).into()),
            KeyFormat::Encrypted => Err(PemError::EncryptedKey),
        }
    }

    fn label(self) -> &'static str {
        match self {
            KeyFormat::Pkcs8 | KeyFormat::Encrypted => "PRIVATE KEY",
            KeyFormat::Pkcs1 => "RSA PRIVATE KEY",
            KeyFormat::Sec1 => "EC PRIVATE KEY",
        }
    }
}

fn is_plain(block: &Block<'_>) -> bool {
    block.label == block.end_label && block.headers.is_empty()
}

pub struct CertificatePair {
    cert_pem: String,
    key_pem: String,
    not_after: UtcTime,
}

impl CertificatePair {
    pub fn parse(cert: &str, key: &str, provider: &CryptoProvider) -> Result<Self, PemError> {
        let mut chain = Vec::new();
        let mut cert_pem = String::with_capacity(cert.len());
        let mut not_after = None;
        for block in pem::STANDARD.blocks(cert) {
            let block = block.map_err(|_| PemError::CertificateSection)?;
            if block.label != CERT_LABEL || !is_plain(&block) {
                return Err(PemError::CertificateSection);
            }
            if chain.len() == MAX_CHAIN {
                return Err(PemError::ChainTooLong);
            }
            let ([], parsed) = X509Certificate::from_der(&block.contents)
                .map_err(|_| PemError::InvalidCertificate)?
            else {
                return Err(PemError::InvalidCertificate);
            };
            not_after.get_or_insert(parsed.validity().not_after.timestamp());
            pem::STANDARD.encode_append(CERT_LABEL, &block.contents, &mut cert_pem);
            chain.push(CertificateDer::from(block.contents));
        }
        let not_after = not_after.ok_or(PemError::NoCertificate)?;
        let not_after = UtcTime(
            u64::try_from(not_after)
                .ok()
                .and_then(|secs| SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs)))
                .unwrap_or(SystemTime::UNIX_EPOCH),
        );

        let mut blocks = pem::STANDARD.blocks(key);
        let (Some(Ok(block)), None) = (blocks.next(), blocks.next()) else {
            return Err(PemError::KeySection);
        };
        let format = KeyFormat::of(block.label)
            .filter(|_| is_plain(&block))
            .ok_or(PemError::KeySection)?;
        let mut key_pem = String::new();
        pem::STANDARD.encode_append(format.label(), &block.contents, &mut key_pem);
        let signing = provider
            .key_provider
            .load_private_key(format.der(block.contents)?)
            .map_err(|_| PemError::InvalidKey)?;
        CertifiedKey::new(chain, signing)
            .keys_match()
            .map_err(|_| PemError::KeyMismatch)?;
        Ok(CertificatePair {
            cert_pem,
            key_pem,
            not_after,
        })
    }
}

#[derive(Serialize)]
pub struct StoredView {
    id: Box<str>,
    not_after: UtcTime,
}

pub struct CertStore {
    dir: PathBuf,
}

impl CertStore {
    pub fn for_config(config: &Path) -> io::Result<Self> {
        let parent = config.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "config path has no parent")
        })?;
        Ok(CertStore {
            dir: parent.join(CERT_DIR),
        })
    }

    pub fn stage(&self, upload: Upload, current: &toml::Table) -> Result<Staged, EditError> {
        let Upload { id, pair, body } = upload;
        self.ensure_dir()?;
        let stem = format!("{}.{}", id.0, Revision::of(pair.cert_pem.as_bytes()));
        let mut staged = Staged {
            dir: self.dir.clone(),
            id: id.0,
            files: Vec::with_capacity(2),
            kept: false,
            not_after: pair.not_after,
            ops: Vec::new(),
        };
        for (ext, text) in [(CERT_EXT, &pair.cert_pem), (KEY_EXT, &pair.key_pem)] {
            let path = self.dir.join(format!("{stem}.{ext}"));
            let fresh = fs::symlink_metadata(&path).is_err();
            write_private(&path, text.as_bytes())?;
            staged.files.push(StagedFile { path, fresh });
        }
        staged.ops = staged.edit_ops(&body, current)?;
        Ok(staged)
    }

    fn ensure_dir(&self) -> io::Result<()> {
        if self.dir.to_str().is_none() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "certificate directory path is not UTF-8",
            ));
        }
        match fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.is_dir() => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "certificate directory is not a plain directory",
            )),
            Err(err) if err.kind() == io::ErrorKind::NotFound => create_private_dir(&self.dir),
            Err(err) => Err(err),
        }
    }
}

struct StagedFile {
    path: PathBuf,
    fresh: bool,
}

pub struct Staged {
    dir: PathBuf,
    id: Box<str>,
    files: Vec<StagedFile>,
    kept: bool,
    not_after: UtcTime,
    pub ops: Vec<EditOp>,
}

impl Staged {
    fn edit_ops(&self, body: &UploadBody, current: &toml::Table) -> Result<Vec<EditOp>, EditError> {
        let entry_path = |id: &str, key: &str| -> Vec<String> {
            ["tls", "certificate", id, key]
                .into_iter()
                .map(str::to_string)
                .collect()
        };
        let path = |key: &str| entry_path(&self.id, key);
        let text = |file: &StagedFile| Json::String(file.path.to_string_lossy().into_owned());
        let mut ops: Vec<EditOp> = ["cert", "key"]
            .into_iter()
            .zip(&self.files)
            .map(|(key, file)| EditOp::Set {
                path: path(key),
                value: text(file),
            })
            .collect();
        match body.subjects.as_deref() {
            Some([]) => ops.push(EditOp::Remove {
                path: path("subjects"),
            }),
            Some(subjects) => ops.push(EditOp::Set {
                path: path("subjects"),
                value: Json::Array(subjects.iter().cloned().map(Json::String).collect()),
            }),
            None => {}
        }
        if let Some(default) = body.default {
            ops.push(EditOp::Set {
                path: path("default"),
                value: Json::Bool(default),
            });
        }
        if body.default == Some(true) {
            let others = current
                .get("tls")
                .and_then(|tls| tls.get("certificate"))
                .and_then(toml::Value::as_table)
                .into_iter()
                .flatten()
                .filter(|(id, _)| **id != *self.id);
            for (id, entry) in others {
                if entry.get("default").and_then(toml::Value::as_bool) == Some(true) {
                    ops.push(EditOp::Set {
                        path: entry_path(id, "default"),
                        value: Json::Bool(false),
                    });
                }
                let Some(subjects) = entry.get("subjects").and_then(toml::Value::as_array) else {
                    continue;
                };
                let is_wildcard = |subject: &toml::Value| subject.as_str() == Some(DEFAULT_SUBJECT);
                if !subjects.iter().any(is_wildcard) {
                    continue;
                }
                let kept: Vec<Json> = subjects
                    .iter()
                    .filter(|subject| !is_wildcard(subject))
                    .filter_map(toml::Value::as_str)
                    .map(|subject| Json::String(subject.to_string()))
                    .collect();
                if kept.is_empty() {
                    return Err(EditError::Invalid(ConfigErrors(vec![ConfigError::new(
                        format!("tls.certificate.{id}.subjects"),
                        format!(
                            "certificate {id} is the default through subjects = [\"*\"] and names no host; give it explicit subjects or remove it before making {} the default",
                            self.id
                        ),
                    )])));
                }
                ops.push(EditOp::Set {
                    path: entry_path(id, "subjects"),
                    value: Json::Array(kept),
                });
            }
        }
        Ok(ops)
    }

    pub fn view(&self) -> StoredView {
        StoredView {
            id: self.id.clone(),
            not_after: self.not_after,
        }
    }

    pub fn keep(mut self, config: &str, history: &History) {
        self.kept = true;
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return;
        };
        let mut archived: Option<Vec<String>> = None;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str().filter(|name| is_uploaded(name)) else {
                continue;
            };
            let mentions = |text: &str| memmem::find(text.as_bytes(), name.as_bytes()).is_some();
            if mentions(config) {
                continue;
            }
            if archived.is_none() {
                let Some(texts) = history.texts() else {
                    tracing::warn!(dir = ?self.dir, "configuration history unreadable; keeping unreferenced certificate files");
                    return;
                };
                archived = Some(texts);
            }
            if archived.iter().flatten().any(|text| mentions(text)) {
                continue;
            }
            if let Err(err) = fs::remove_file(entry.path()) {
                tracing::warn!(error = %err, file = ?entry.path(), "could not remove an unreferenced certificate file");
            }
        }
    }
}

impl History {
    fn texts(&self) -> Option<Vec<String>> {
        self.list()
            .ok()?
            .iter()
            .map(|past| self.read(&past.id).ok().map(|past| past.text))
            .collect()
    }
}

fn is_uploaded(name: &str) -> bool {
    name.rsplit_once('.')
        .filter(|(_, ext)| *ext == CERT_EXT || *ext == KEY_EXT)
        .and_then(|(stem, _)| stem.rsplit_once('.'))
        .is_some_and(|(id, revision)| {
            CertificateId::parse(id).is_some() && revision.parse::<Revision>().is_ok()
        })
}

impl Drop for Staged {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        for file in self.files.iter().filter(|file| file.fresh) {
            let _ = fs::remove_file(&file.path);
        }
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let result = create_private(&tmp).and_then(|mut file| {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[cfg(unix)]
fn create_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new().create(path)
}
