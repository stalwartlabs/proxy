/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::Call;
use super::read::DelayView;
use crate::admin::http::{Out, Reply};
use crate::route::key::RoutingKey;
use crate::runtime::DestId;
use crate::runtime::metrics::EventKind;

const MAX_IMPORT: usize = 5000;
const MAX_KICK_IDS: usize = 1000;

#[derive(Deserialize)]
struct MappingBody {
    destination: String,
}

#[derive(Deserialize)]
struct ImportBody {
    entries: Vec<(String, String)>,
}

#[derive(Deserialize, Default)]
struct IdentifierBody {
    identifier: Option<String>,
}

#[derive(Deserialize)]
struct KickBody {
    identifier: Option<String>,
    ids: Option<Vec<u64>>,
}

#[derive(Deserialize)]
struct DelayBody {
    seconds: u64,
}

#[derive(Serialize)]
struct Upserted<'a> {
    identifier: &'a str,
    normalized: &'a str,
    destination: &'a str,
    created: bool,
}

#[derive(Serialize)]
struct Existed {
    existed: bool,
}

#[derive(Serialize)]
struct ImportError {
    index: usize,
    code: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct Imported {
    upserted: usize,
    errors: Vec<ImportError>,
}

#[derive(Serialize)]
struct Reloaded {
    reloaded: bool,
}

#[derive(Serialize)]
struct Invalidated {
    invalidated: &'static str,
}

#[derive(Serialize)]
struct Kicked {
    kicked: usize,
}

#[derive(Serialize)]
struct Released {
    released: bool,
}

impl Call<'_> {
    pub async fn reset_destination(&self, name: &str, out: &mut Out) -> Reply {
        let rt = self.rt;
        let Some(dest) = rt.dest_id(name).and_then(|id| rt.destination(id)) else {
            return Reply::error(
                &mut out.body,
                404,
                "unknown_destination",
                "unknown destination",
            );
        };
        dest.health.reset();
        tracing::info!(destination = %name, "admin reset destination health");
        self.record(rt, EventKind::Admin, "reset destination health", Some(name));
        rt.destination_reply(name, out).await
    }

    pub async fn put_mapping(&self, identifier: &str, out: &mut Out) -> Reply {
        let Some(body) = self.request.json_body::<MappingBody>() else {
            return Reply::bad_body(&mut out.body);
        };
        let _writes = self.admin.writes.lock().await;
        let rt = self.admin.shared.load_full();
        let Some(key) = RoutingKey::parse(identifier, &rt.key_rules).ok().flatten() else {
            return Reply::invalid_identifier(out);
        };
        if !rt.router.store_writable() {
            return Reply::read_only(out);
        }
        let Some(dest) = rt.dest_id(&body.destination) else {
            return Reply::error(
                &mut out.body,
                400,
                "unknown_destination",
                "unknown destination",
            );
        };
        match rt.router.upsert(&key, dest).await {
            Ok(upserted) => {
                rt.shared.registry.release_delay(key.as_str());
                tracing::info!(identifier = %rt.shared.redact.redact(key.as_str()), destination = %body.destination, "admin upserted mapping");
                self.record(
                    &rt,
                    EventKind::Mapping,
                    format!("mapped to {}", body.destination),
                    Some(key.as_str()),
                );
                Reply::json(
                    &mut out.body,
                    200,
                    &Upserted {
                        identifier,
                        normalized: key.as_str(),
                        destination: &body.destination,
                        created: upserted.created,
                    },
                )
            }
            Err(err) => Reply::store_failed(out, "upsert", err),
        }
    }

    pub async fn delete_mapping(&self, identifier: &str, out: &mut Out) -> Reply {
        let _writes = self.admin.writes.lock().await;
        let rt = self.admin.shared.load_full();
        let Some(key) = RoutingKey::parse(identifier, &rt.key_rules).ok().flatten() else {
            return Reply::invalid_identifier(out);
        };
        if !rt.router.store_writable() {
            return Reply::read_only(out);
        }
        match rt.router.remove(&key).await {
            Ok(existed) => {
                rt.shared.registry.release_delay(key.as_str());
                tracing::info!(identifier = %rt.shared.redact.redact(key.as_str()), existed, "admin removed mapping");
                self.record(
                    &rt,
                    EventKind::Mapping,
                    "removed mapping",
                    Some(key.as_str()),
                );
                Reply::json(&mut out.body, 200, &Existed { existed })
            }
            Err(err) => Reply::store_failed(out, "remove", err),
        }
    }

    pub async fn import(&self, out: &mut Out) -> Reply {
        let Some(body) = self.request.json_body::<ImportBody>() else {
            return Reply::bad_body(&mut out.body);
        };
        if body.entries.len() > MAX_IMPORT {
            return Reply::error(
                &mut out.body,
                413,
                "too_many_entries",
                "at most 5000 entries per call",
            );
        }
        let _writes = self.admin.writes.lock().await;
        let rt = self.admin.shared.load_full();
        if !rt.router.store_writable() {
            return Reply::read_only(out);
        }
        let mut errors = Vec::new();
        let mut valid: Vec<(RoutingKey, DestId)> = Vec::with_capacity(body.entries.len());
        for (index, (identifier, destination)) in body.entries.iter().enumerate() {
            let Some(key) = RoutingKey::parse(identifier, &rt.key_rules).ok().flatten() else {
                errors.push(ImportError {
                    index,
                    code: "invalid_identifier",
                    message: "invalid identifier",
                });
                continue;
            };
            let Some(dest) = rt.dest_id(destination) else {
                errors.push(ImportError {
                    index,
                    code: "unknown_destination",
                    message: "unknown destination",
                });
                continue;
            };
            valid.push((key, dest));
        }
        let upserted = match valid.is_empty() {
            true => 0,
            false => match rt.router.upsert_many(&valid).await {
                Ok(result) => result.upserted,
                Err(err) => return Reply::store_failed(out, "import", err),
            },
        };
        for (key, _) in &valid {
            rt.shared.registry.release_delay(key.as_str());
        }
        tracing::info!(upserted, rejected = errors.len(), "admin imported mappings");
        self.record(
            &rt,
            EventKind::Mapping,
            format!("imported {upserted} mappings ({} rejected)", errors.len()),
            None,
        );
        Reply::json(&mut out.body, 200, &Imported { upserted, errors })
    }

    pub async fn reload_mappings(&self, out: &mut Out) -> Reply {
        let _writes = self.admin.writes.lock().await;
        let rt = self.admin.shared.load_full();
        match rt.router.reload().await {
            Ok(()) => {
                rt.shared.registry.release_all_delays();
                tracing::info!("admin reloaded mappings");
                self.record(&rt, EventKind::Mapping, "reloaded mappings", None);
                Reply::json(&mut out.body, 200, &Reloaded { reloaded: true })
            }
            Err(err) => {
                tracing::warn!(error = %err, "admin mapping reload failed");
                self.record(&rt, EventKind::Mapping, "mapping reload failed", None);
                Reply::error(&mut out.body, 502, "reload_failed", "mapping reload failed")
            }
        }
    }

    pub async fn invalidate(&self, out: &mut Out) -> Reply {
        let body = match self.request.body() {
            [] => IdentifierBody::default(),
            _ => match self.request.json_body::<IdentifierBody>() {
                Some(body) => body,
                None => return Reply::bad_body(&mut out.body),
            },
        };
        let rt = self.rt;
        let invalidated = match body.identifier.as_deref() {
            Some(identifier) => {
                let Some(key) = self.key(identifier) else {
                    return Reply::invalid_identifier(out);
                };
                rt.router.invalidate(&key);
                rt.shared.registry.release_delay(key.as_str());
                tracing::info!(identifier = %rt.shared.redact.redact(key.as_str()), "admin invalidated entry");
                self.record(
                    rt,
                    EventKind::Admin,
                    "invalidated cache entry",
                    Some(key.as_str()),
                );
                "one"
            }
            None => {
                rt.router.invalidate_all();
                rt.shared.registry.release_all_delays();
                tracing::info!("admin invalidated entire cache");
                self.record(rt, EventKind::Admin, "invalidated entire cache", None);
                "all"
            }
        };
        Reply::json(&mut out.body, 200, &Invalidated { invalidated })
    }

    pub fn kick(&self, out: &mut Out) -> Reply {
        let Some(body) = self.request.json_body::<KickBody>() else {
            return Reply::bad_body(&mut out.body);
        };
        let rt = self.rt;
        let registry = &rt.shared.registry;
        let (kicked, target) = match (body.identifier.as_deref(), body.ids.as_deref()) {
            (Some(identifier), None) => {
                let Some(key) = self.key(identifier) else {
                    return Reply::invalid_identifier(out);
                };
                let kicked = registry.kick(key.as_str());
                tracing::info!(identifier = %rt.shared.redact.redact(key.as_str()), kicked, "admin kicked connections");
                (kicked, Some(key))
            }
            (None, Some(ids)) if ids.len() <= MAX_KICK_IDS => {
                let kicked = registry.kick_ids(ids);
                tracing::info!(
                    requested = ids.len(),
                    kicked,
                    "admin kicked connections by id"
                );
                (kicked, None)
            }
            _ => {
                return Reply::error(
                    &mut out.body,
                    400,
                    "bad_request",
                    "expected identifier or ids (at most 1000)",
                );
            }
        };
        self.record(
            rt,
            EventKind::Admin,
            format!("kicked {kicked} sessions"),
            target.as_ref().map(RoutingKey::as_str),
        );
        Reply::json(&mut out.body, 200, &Kicked { kicked })
    }

    pub fn put_delay(&self, identifier: &str, out: &mut Out) -> Reply {
        let Some(body) = self.request.json_body::<DelayBody>() else {
            return Reply::bad_body(&mut out.body);
        };
        let Some(key) = self.key(identifier) else {
            return Reply::invalid_identifier(out);
        };
        let Some(until) = Instant::now().checked_add(Duration::from_secs(body.seconds)) else {
            return Reply::error(&mut out.body, 400, "bad_request", "invalid seconds");
        };
        let rt = self.rt;
        let registry = &rt.shared.registry;
        registry.set_delay(key.as_str(), until);
        tracing::info!(identifier = %rt.shared.redact.redact(key.as_str()), seconds = body.seconds, "admin set login delay");
        self.record(
            rt,
            EventKind::Admin,
            format!("delayed logins for {}s", body.seconds),
            Some(key.as_str()),
        );
        match registry.delay_info(key.as_str()) {
            Some(info) => Reply::json(&mut out.body, 200, &DelayView::from(&info)),
            None => Reply::json(&mut out.body, 200, &Released { released: true }),
        }
    }

    pub fn delete_delay(&self, identifier: &str, out: &mut Out) -> Reply {
        let Some(key) = self.key(identifier) else {
            return Reply::invalid_identifier(out);
        };
        let rt = self.rt;
        let released = rt.shared.registry.release_delay(key.as_str());
        if released {
            tracing::info!(identifier = %rt.shared.redact.redact(key.as_str()), "admin released login delay");
            self.record(
                rt,
                EventKind::Admin,
                "released login delay",
                Some(key.as_str()),
            );
        }
        Reply::json(&mut out.body, 200, &Released { released })
    }
}

impl Reply {
    fn invalid_identifier(out: &mut Out) -> Reply {
        Reply::error(
            &mut out.body,
            400,
            "invalid_identifier",
            "invalid identifier",
        )
    }

    fn read_only(out: &mut Out) -> Reply {
        Reply::error(
            &mut out.body,
            501,
            "read_only",
            "mapping store is read-only",
        )
    }

    fn store_failed(out: &mut Out, action: &str, err: impl std::fmt::Display) -> Reply {
        tracing::warn!(error = %err, action, "admin mapping store write failed");
        Reply::error(&mut out.body, 502, "store_error", "mapping store error")
    }
}
