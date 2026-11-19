/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

use super::Call;
use super::certificate::{
    CertStore, CertificateId, CertificatePair, MAX_UPLOAD, Staged, StoredView, Upload, UploadBody,
};
use super::view::Invalid;
use crate::admin::http::{Out, Reply};
use crate::config::edit::{EditError, EditOp, History, Source};
use crate::config::schema::SCHEMA;
use crate::config::{Config, Revision};
use crate::error::{ConfigError, ConfigErrors};
use crate::net::tls;
use crate::runtime::metrics::EventKind;
use crate::runtime::time::UtcTime;

const DRY_RUN: &str = "dry_run";
const IF_MATCH: &[u8] = b"if-match";

#[derive(Serialize)]
struct ConfigView<'a> {
    path: &'a str,
    revision: Revision,
    running_revision: Revision,
    loaded_at: UtcTime,
    writable: bool,
    restart_required: &'a [Box<str>],
    source: &'a str,
    values: &'a Config,
}

#[derive(Serialize)]
struct Valid {
    valid: bool,
}

#[derive(Deserialize)]
struct PatchBody {
    revision: String,
    ops: Vec<EditOp>,
}

#[derive(Deserialize)]
struct RestoreBody {
    revision: String,
}

#[derive(Serialize)]
struct WriteResult<'a> {
    revision: Revision,
    source: &'a str,
    applied: bool,
    restart_required: &'a [Box<str>],
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<StoredView>,
}

#[derive(Serialize)]
struct Reloaded<'a> {
    revision: Revision,
    restart_required: &'a [Box<str>],
}

#[derive(Serialize)]
struct HistoryView<'a> {
    id: &'a str,
    revision: Revision,
    size: u64,
    at: UtcTime,
}

#[derive(Serialize)]
struct SourceView<'a> {
    source: &'a str,
}

#[derive(Serialize)]
struct ConflictBody<'a> {
    error: ConflictDetail<'a>,
    revision: Revision,
}

#[derive(Serialize)]
struct ConflictDetail<'a> {
    code: &'a str,
    message: &'a str,
}

enum Edit {
    Ops(Vec<EditOp>),
    Replace(String),
    Restore(Box<str>),
    Certificate(Upload),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    DryRun,
    Apply,
}

async fn blocking<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    tokio::task::spawn_blocking(work).await.ok()
}

impl Call<'_> {
    fn mode(&self) -> Mode {
        match self.request.query_param(DRY_RUN).as_deref() {
            Some("true" | "1") => Mode::DryRun,
            _ => Mode::Apply,
        }
    }

    fn utf8_body(&self) -> Option<&str> {
        std::str::from_utf8(self.request.body()).ok()
    }

    pub async fn get_config(&self, out: &mut Out) -> Reply {
        let Some(path) = self.admin.config_path.clone() else {
            return Reply::unavailable(out);
        };
        let read = blocking(move || {
            let source = Source::read(Path::new(&*path)).map_err(EditError::Io)?;
            source.masked().map(|masked| (source.revision, masked))
        })
        .await;
        let (revision, masked) = match read {
            Some(Ok(read)) => read,
            Some(Err(err)) => return Reply::edit_failed(out, &err),
            None => return Reply::internal(out),
        };
        let rt = self.rt;
        Reply::json(
            &mut out.body,
            200,
            &ConfigView {
                path: self.admin.config_path.as_deref().unwrap_or_default(),
                revision,
                running_revision: rt.revision,
                loaded_at: rt.loaded_at,
                writable: self.admin.config_writable(rt),
                restart_required: &rt.restart_required,
                source: &masked,
                values: &rt.raw,
            },
        )
    }

    pub async fn validate_config(&self, out: &mut Out) -> Reply {
        let Some(text) = self.utf8_body() else {
            return Reply::bad_body(&mut out.body);
        };
        let checked = match self.admin.config_path.clone() {
            Some(path) => {
                let text = text.to_string();
                match blocking(move || Source::read(Path::new(&*path))?.validate(&text)).await {
                    Some(checked) => checked.map(drop),
                    None => return Reply::internal(out),
                }
            }
            None => Config::parse(text).map(drop).map_err(EditError::Invalid),
        };
        match checked {
            Ok(()) => Reply::json(&mut out.body, 200, &Valid { valid: true }),
            Err(err) => Reply::edit_failed(out, &err),
        }
    }

    pub async fn patch_config(&self, out: &mut Out) -> Reply {
        let Some(body) = self.request.json_body::<PatchBody>() else {
            return Reply::bad_body(&mut out.body);
        };
        let Ok(revision) = body.revision.parse::<Revision>() else {
            return Reply::error(&mut out.body, 400, "bad_request", "invalid revision");
        };
        self.write_config(out, revision, Edit::Ops(body.ops)).await
    }

    pub async fn put_source(&self, out: &mut Out) -> Reply {
        let Some(revision) = self.request.header(IF_MATCH).and_then(|tag| {
            let tag = tag.trim();
            tag.strip_prefix("W/")
                .unwrap_or(tag)
                .trim_matches('"')
                .parse::<Revision>()
                .ok()
        }) else {
            return Reply::error(
                &mut out.body,
                428,
                "precondition_required",
                "If-Match revision required",
            );
        };
        let Some(text) = self.utf8_body() else {
            return Reply::bad_body(&mut out.body);
        };
        self.write_config(out, revision, Edit::Replace(text.to_string()))
            .await
    }

    pub async fn restore(&self, id: &str, out: &mut Out) -> Reply {
        let Some(body) = self.request.json_body::<RestoreBody>() else {
            return Reply::bad_body(&mut out.body);
        };
        let Ok(revision) = body.revision.parse::<Revision>() else {
            return Reply::error(&mut out.body, 400, "bad_request", "invalid revision");
        };
        self.write_config(out, revision, Edit::Restore(id.into()))
            .await
    }

    pub async fn put_certificate(&self, id: &str, out: &mut Out) -> Reply {
        let Some(id) = CertificateId::parse(id) else {
            return Reply::error(
                &mut out.body,
                400,
                "bad_request",
                "certificate id must be 1-64 letters, digits, '-' or '_'",
            );
        };
        if !self.admin.config_writable(self.rt) {
            return Reply::write_disabled(out);
        }
        if self.request.body().len() > MAX_UPLOAD {
            return Reply::error(
                &mut out.body,
                413,
                "payload_too_large",
                "certificate upload too large",
            );
        }
        let Some(body) = self.request.json_body::<UploadBody>() else {
            return Reply::bad_body(&mut out.body);
        };
        let Ok(revision) = body.revision.parse::<Revision>() else {
            return Reply::error(&mut out.body, 400, "bad_request", "invalid revision");
        };
        let pair = match CertificatePair::parse(&body.cert, &body.key, &tls::provider()) {
            Ok(pair) => pair,
            Err(err) => return Reply::error(&mut out.body, 422, err.code(), &err.to_string()),
        };
        self.write_config(out, revision, Edit::Certificate(Upload { id, pair, body }))
            .await
    }

    async fn write_config(&self, out: &mut Out, revision: Revision, edit: Edit) -> Reply {
        let admin = self.admin;
        if !admin.config_writable(self.rt) {
            return Reply::write_disabled(out);
        }
        let Some(path) = admin.config_path.clone() else {
            return Reply::unavailable(out);
        };
        let mode = self.mode();
        let _writes = admin.writes.lock().await;
        let before = admin.shared.load_full();
        let edit_path = path.clone();
        let edited = blocking(move || {
            let path = fs::canonicalize(&*edit_path)?;
            let current = Source::read(&path)?;
            current.check(revision)?;
            let mut staged = None;
            let edited = match edit {
                Edit::Ops(ops) => current.apply(&ops)?,
                Edit::Replace(text) => current.replace(&text)?,
                Edit::Restore(id) => {
                    current.replace(&History::for_config(&path).read(&id)?.text)?
                }
                Edit::Certificate(upload) => {
                    let table = toml::from_str::<toml::Table>(&current.text).map_err(|err| {
                        EditError::Invalid(ConfigErrors(vec![ConfigError::new(
                            "",
                            err.message().to_string(),
                        )]))
                    })?;
                    let stored =
                        staged.insert(CertStore::for_config(&path)?.stage(upload, &table)?);
                    current.apply(&stored.ops)?
                }
            };
            let masked = edited.source.masked()?;
            Ok::<_, EditError>((path, current, edited, masked, staged))
        })
        .await;
        let (resolved, current, edited, masked, staged) = match edited {
            Some(Ok(edited)) => edited,
            Some(Err(err)) => return Reply::edit_failed(out, &err),
            None => return Reply::internal(out),
        };
        let new_source = edited.source;
        let new_revision = new_source.revision;
        let prepared = match admin.prepare(edited.config, new_revision).await {
            Ok(prepared) => prepared,
            Err(err) => return Reply::build_failed(out, err),
        };
        if mode == Mode::DryRun {
            return Reply::json(
                &mut out.body,
                200,
                &WriteResult {
                    revision: new_revision,
                    source: &masked,
                    applied: false,
                    restart_required: &prepared.rt.restart_required,
                    certificate: staged.as_ref().map(Staged::view),
                },
            );
        }
        if let Err(err) = prepared.rt.bind_listeners() {
            return Reply::build_failed(out, err);
        }
        let certificate = staged.as_ref().map(Staged::view);
        let committed = blocking(move || {
            new_source.commit_resolved(Path::new(&*path), &resolved, &current)?;
            if let Some(staged) = staged {
                staged.keep(&new_source.text, &History::for_config(&resolved));
            }
            Ok::<_, EditError>(())
        })
        .await;
        match committed {
            Some(Ok(())) => {}
            Some(Err(err)) => return Reply::edit_failed(out, &err),
            None => return Reply::internal(out),
        }
        tracing::info!(revision = %new_revision, "admin saved configuration");
        let exposure = prepared.rt.raw.exposure_changes(&before.raw);
        if !exposure.is_empty() {
            tracing::warn!(
                actor = %self.caller.actor(),
                ip = %self.ip,
                revision = %new_revision,
                changes = %exposure,
                "admin changed listeners or destinations"
            );
        }
        let rt = match admin.install(prepared) {
            Ok(rt) => rt,
            Err(err) => {
                if !exposure.is_empty() {
                    self.record(&before, EventKind::Config, exposure, None);
                }
                return Reply::not_applied(out, err);
            }
        };
        if !exposure.is_empty() {
            self.record(&rt, EventKind::Config, exposure, None);
        }
        self.record(
            &rt,
            EventKind::Config,
            format!("saved configuration revision {new_revision}"),
            None,
        );
        Reply::json(
            &mut out.body,
            200,
            &WriteResult {
                revision: new_revision,
                source: &masked,
                applied: true,
                restart_required: &rt.restart_required,
                certificate,
            },
        )
    }

    pub async fn reload_config(&self, out: &mut Out) -> Reply {
        let Some(path) = self.admin.config_path.as_deref() else {
            return Reply::unavailable(out);
        };
        let result = self.admin.reload_config(path).await;
        let current = self.admin.shared.load_full();
        match result {
            Ok(rt) => {
                tracing::info!("admin reloaded configuration");
                self.record(&current, EventKind::Config, "reloaded configuration", None);
                Reply::json(
                    &mut out.body,
                    200,
                    &Reloaded {
                        revision: rt.revision,
                        restart_required: &rt.restart_required,
                    },
                )
            }
            Err(err) => {
                tracing::warn!(error = %err, "admin config reload failed");
                self.record(
                    &current,
                    EventKind::Config,
                    format!("configuration reload failed: {err}"),
                    None,
                );
                Reply::build_failed(out, err)
            }
        }
    }

    pub async fn config_history(&self, out: &mut Out) -> Reply {
        let Some(path) = self.admin.config_path.clone() else {
            return Reply::unavailable(out);
        };
        let entries =
            match blocking(move || History::for_config(&fs::canonicalize(&*path)?).list()).await {
                Some(Ok(entries)) => entries,
                Some(Err(err)) => return Reply::edit_failed(out, &EditError::Io(err)),
                None => return Reply::internal(out),
            };
        let views: Vec<_> = entries
            .iter()
            .map(|entry| HistoryView {
                id: &entry.id,
                revision: entry.revision,
                size: entry.size,
                at: UtcTime(entry.at),
            })
            .collect();
        Reply::json(&mut out.body, 200, &views)
    }

    pub async fn history_entry(&self, id: &str, out: &mut Out) -> Reply {
        let Some(path) = self.admin.config_path.clone() else {
            return Reply::unavailable(out);
        };
        let id: Box<str> = id.into();
        let read = blocking(move || {
            History::for_config(&fs::canonicalize(&*path)?)
                .read(&id)?
                .masked()
        })
        .await;
        match read {
            Some(Ok(masked)) => Reply::json(&mut out.body, 200, &SourceView { source: &masked }),
            Some(Err(err)) => Reply::edit_failed(out, &err),
            None => Reply::internal(out),
        }
    }
}

impl Reply {
    fn unavailable(out: &mut Out) -> Reply {
        Reply::error(
            &mut out.body,
            503,
            "config_unavailable",
            "configuration file path unknown",
        )
    }

    fn write_disabled(out: &mut Out) -> Reply {
        Reply::error(
            &mut out.body,
            403,
            "config_write_disabled",
            "configuration writes are disabled (admin.config_write)",
        )
    }

    fn internal(out: &mut Out) -> Reply {
        Reply::error(&mut out.body, 500, "internal", "internal error")
    }

    fn edit_failed(out: &mut Out, err: &EditError) -> Reply {
        match err {
            EditError::Conflict { current } => Reply::json(
                &mut out.body,
                409,
                &ConflictBody {
                    error: ConflictDetail {
                        code: "revision_mismatch",
                        message: "the configuration changed on disk; reload and retry",
                    },
                    revision: *current,
                },
            ),
            EditError::Invalid(errors) => Reply::json(&mut out.body, 422, &Invalid::of(errors)),
            EditError::NotFound => {
                Reply::error(&mut out.body, 404, "not_found", "history entry not found")
            }
            EditError::Io(io) => {
                tracing::warn!(error = %io, "admin config file I/O failed");
                Reply::error(
                    &mut out.body,
                    500,
                    "io_error",
                    "configuration file I/O failed",
                )
            }
        }
    }

    fn build_failed(out: &mut Out, err: impl std::fmt::Display) -> Reply {
        let errors = ConfigErrors(vec![ConfigError::new("", err.to_string())]);
        Reply::json(&mut out.body, 422, &Invalid::of(&errors))
    }

    fn not_applied(out: &mut Out, err: impl std::fmt::Display) -> Reply {
        tracing::warn!(error = %err, "admin saved configuration but could not apply it");
        Reply::error(
            &mut out.body,
            503,
            "not_applied",
            "configuration saved but not applied; reload to apply it",
        )
    }

    pub fn schema(out: &mut Out) -> Reply {
        out.body.extend_from_slice(SCHEMA.as_bytes());
        Reply::json_empty(200)
    }
}

impl Source {
    pub(super) fn commit_resolved(
        &self,
        configured: &Path,
        resolved: &Path,
        current: &Source,
    ) -> Result<(), EditError> {
        let now = fs::canonicalize(configured)?;
        if now != resolved {
            return Err(EditError::Conflict {
                current: Source::read(&now)?.revision,
            });
        }
        self.commit(resolved, current)
    }
}

impl Config {
    pub(super) fn exposure_changes(&self, previous: &Config) -> String {
        let mut exposure = Exposure(String::new());
        exposure.compare(
            "listener",
            &previous.listener,
            &self.listener,
            |listener, out| {
                let _ = write!(
                    out,
                    " ({} tls={:?} bind={:?})",
                    listener.protocol.as_str(),
                    listener.tls,
                    listener.bind
                );
            },
        );
        exposure.compare(
            "destination",
            &previous.destination,
            &self.destination,
            |destination, out| {
                let _ = write!(out, " (host {})", destination.host);
            },
        );
        exposure.0
    }
}

struct Exposure(String);

impl Exposure {
    fn compare<T: Serialize>(
        &mut self,
        kind: &str,
        previous: &AHashMap<String, T>,
        current: &AHashMap<String, T>,
        detail: impl Fn(&T, &mut String),
    ) {
        let mut names: Vec<&str> = current
            .keys()
            .chain(previous.keys())
            .map(String::as_str)
            .collect();
        names.sort_unstable();
        names.dedup();
        for name in names {
            let entry = current.get(name);
            let change = match (previous.get(name), entry) {
                (None, Some(_)) => "added",
                (Some(_), None) => "removed",
                (Some(old), Some(new))
                    if serde_json::to_value(old).ok() != serde_json::to_value(new).ok() =>
                {
                    "changed"
                }
                _ => continue,
            };
            if !self.0.is_empty() {
                self.0.push_str("; ");
            }
            let _ = write!(self.0, "{kind} {name} {change}");
            if let Some(entry) = entry {
                detail(entry, &mut self.0);
            }
        }
    }
}
