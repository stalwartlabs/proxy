/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod actions;
mod certificate;
mod config;
mod read;
mod view;

use std::borrow::Cow;
use std::fmt;
use std::io::Write as _;
use std::net::IpAddr;
use std::sync::Arc;

use percent_encoding::percent_decode_str;
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::http::{Out, Reply, Request};
use super::session::{COOKIE_NAME, CreateError, SessionView};
use super::{API_PREFIX, Access, Admin, Caller, LOCKED_OUT, TokenCheck};
use crate::http::head::Method;
use crate::observe::RedactKey;
use crate::route::key::RoutingKey;
use crate::runtime::Runtime;
use crate::runtime::metrics::EventKind;
use view::SessionBody;

const CSRF_HEADER: &[u8] = b"x-csrf-token";
const FETCH_SITE_HEADER: &[u8] = b"sec-fetch-site";
const SAME_ORIGIN: &str = "same-origin";
const COOKIE_ATTRIBUTES: &str = "; Secure; HttpOnly; SameSite=Strict; Path=/";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Fixed {
    Session,
    Overview,
    Series,
    Destinations,
    Listeners,
    Connections,
    Kick,
    Delays,
    Mappings,
    Lookup,
    Import,
    MappingsReload,
    Cache,
    Invalidate,
    Events,
    Config,
    Schema,
    Validate,
    Source,
    ConfigReload,
    History,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Collection {
    Destinations,
    Mappings,
    Delays,
    Config,
    Certificates,
}

#[derive(Debug)]
enum Route<'a> {
    Fixed(Fixed),
    Destination(Cow<'a, str>),
    DestinationReset(Cow<'a, str>),
    Mapping(Cow<'a, str>),
    Delay(Cow<'a, str>),
    Certificate(Cow<'a, str>),
    HistoryEntry(&'a str),
    HistoryRestore(&'a str),
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}

impl<'a> Route<'a> {
    fn parse(rest: &'a str) -> Option<Route<'a>> {
        if let Some(fixed) = hashify::map!(
            rest.as_bytes(),
            Fixed,
            "session" => Fixed::Session,
            "overview" => Fixed::Overview,
            "metrics/series" => Fixed::Series,
            "destinations" => Fixed::Destinations,
            "listeners" => Fixed::Listeners,
            "connections" => Fixed::Connections,
            "connections/kick" => Fixed::Kick,
            "delays" => Fixed::Delays,
            "mappings" => Fixed::Mappings,
            "mappings/lookup" => Fixed::Lookup,
            "mappings/import" => Fixed::Import,
            "mappings/reload" => Fixed::MappingsReload,
            "cache" => Fixed::Cache,
            "cache/invalidate" => Fixed::Invalidate,
            "events" => Fixed::Events,
            "config" => Fixed::Config,
            "config/schema" => Fixed::Schema,
            "config/validate" => Fixed::Validate,
            "config/source" => Fixed::Source,
            "config/reload" => Fixed::ConfigReload,
            "config/history" => Fixed::History,
        ) {
            return Some(Route::Fixed(*fixed));
        }
        let (collection, item) = rest.split_once('/')?;
        let collection = hashify::map!(
            collection.as_bytes(),
            Collection,
            "destinations" => Collection::Destinations,
            "mappings" => Collection::Mappings,
            "delays" => Collection::Delays,
            "config" => Collection::Config,
            "certificates" => Collection::Certificates,
        )?;
        match collection {
            Collection::Destinations => match item.strip_suffix("/reset") {
                Some(id) => decode(id).map(Route::DestinationReset),
                None => decode(item).map(Route::Destination),
            },
            Collection::Mappings => decode(item).map(Route::Mapping),
            Collection::Delays => decode(item).map(Route::Delay),
            Collection::Certificates => decode(item).map(Route::Certificate),
            Collection::Config => {
                let id = item.strip_prefix("history/")?;
                match id.strip_suffix("/restore") {
                    Some(id) => Some(Route::HistoryRestore(id)),
                    None => Some(Route::HistoryEntry(id)),
                }
            }
        }
    }
}

pub(super) struct LoggedPath<'a> {
    path: &'a str,
    redact: &'a RedactKey,
}

impl<'a> LoggedPath<'a> {
    pub(super) fn new(path: &'a str, redact: &'a RedactKey) -> Self {
        LoggedPath { path, redact }
    }
}

impl fmt::Display for LoggedPath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.path.strip_prefix(API_PREFIX).and_then(Route::parse) {
            Some(Route::Mapping(id)) => {
                write!(f, "{API_PREFIX}mappings/{}", self.redact.redact(&id))
            }
            Some(Route::Delay(id)) => write!(f, "{API_PREFIX}delays/{}", self.redact.redact(&id)),
            _ => f.write_str(self.path),
        }
    }
}

fn decode(segment: &str) -> Option<Cow<'_, str>> {
    if segment.is_empty() || segment.contains('/') {
        return None;
    }
    percent_decode_str(segment).decode_utf8().ok()
}

pub(super) struct Call<'a> {
    admin: &'a Admin,
    rt: &'a Arc<Runtime>,
    request: &'a Request,
    ip: IpAddr,
    caller: Caller,
}

impl Call<'_> {
    fn record(
        &self,
        rt: &Runtime,
        kind: EventKind,
        message: impl Into<Box<str>>,
        target: Option<&str>,
    ) {
        self.admin
            .record_as(rt, self.caller, kind, message.into(), target, self.ip);
    }

    fn key(&self, raw: &str) -> Option<RoutingKey> {
        RoutingKey::parse(raw, &self.rt.key_rules).ok().flatten()
    }
}

enum Denied {
    Unauthorized,
    Csrf,
}

impl Denied {
    fn reply(self, body: &mut Vec<u8>) -> Reply {
        match self {
            Denied::Unauthorized => Reply::unauthorized(body),
            Denied::Csrf => Reply::error(body, 403, "csrf", "missing or invalid CSRF token"),
        }
    }
}

impl Reply {
    fn unauthorized(body: &mut Vec<u8>) -> Reply {
        Reply::error(body, 401, "unauthorized", "unauthorized")
    }

    fn not_found(body: &mut Vec<u8>) -> Reply {
        Reply::error(body, 404, "not_found", "not found")
    }

    fn method_not_allowed(body: &mut Vec<u8>) -> Reply {
        Reply::error(body, 405, "method_not_allowed", "method not allowed")
    }

    fn bad_body(body: &mut Vec<u8>) -> Reply {
        Reply::error(body, 400, "bad_request", "malformed request body")
    }
}

impl Request {
    fn json_body<T: DeserializeOwned>(&self) -> Option<T> {
        serde_json::from_slice(self.body()).ok()
    }
}

impl Admin {
    pub async fn handle_api(
        &self,
        rt: &Arc<Runtime>,
        request: &Request,
        rest: &str,
        ip: IpAddr,
        access: &mut Access,
        out: &mut Out,
    ) -> Reply {
        let Some(route) = Route::parse(rest) else {
            return Reply::not_found(&mut out.body);
        };
        if let Route::Fixed(Fixed::Session) = route {
            return self.session(rt, request, ip, access, out);
        }
        let caller = match self.authenticate(rt, request, ip) {
            Ok(caller) => caller,
            Err(denied) => return denied.reply(&mut out.body),
        };
        *access = Access::Authenticated;
        let method = request.method();
        let ctx = Call {
            admin: self,
            rt,
            request,
            ip,
            caller,
        };
        match route {
            Route::Fixed(fixed) => match (fixed, method) {
                (Fixed::Overview, Method::Get) => ctx.overview(out).await,
                (Fixed::Series, Method::Get) => ctx.series(out),
                (Fixed::Destinations, Method::Get) => ctx.destinations(out).await,
                (Fixed::Listeners, Method::Get) => ctx.listeners(out),
                (Fixed::Connections, Method::Get) => ctx.connections(out),
                (Fixed::Kick, Method::Post) => ctx.kick(out),
                (Fixed::Delays, Method::Get) => ctx.delays(out),
                (Fixed::Mappings, Method::Get) => ctx.mappings(out).await,
                (Fixed::Lookup, Method::Get) => ctx.lookup(out).await,
                (Fixed::Import, Method::Post) => ctx.import(out).await,
                (Fixed::MappingsReload, Method::Post) => ctx.reload_mappings(out).await,
                (Fixed::Cache, Method::Get) => ctx.cache(out),
                (Fixed::Invalidate, Method::Post) => ctx.invalidate(out).await,
                (Fixed::Events, Method::Get) => ctx.events(out),
                (Fixed::Config, Method::Get) => ctx.get_config(out).await,
                (Fixed::Config, Method::Patch) => ctx.patch_config(out).await,
                (Fixed::Schema, Method::Get) => Reply::schema(out),
                (Fixed::Validate, Method::Post) => ctx.validate_config(out).await,
                (Fixed::Source, Method::Put) => ctx.put_source(out).await,
                (Fixed::ConfigReload, Method::Post) => ctx.reload_config(out).await,
                (Fixed::History, Method::Get) => ctx.config_history(out).await,
                _ => Reply::method_not_allowed(&mut out.body),
            },
            Route::Destination(id) => match method {
                Method::Get => ctx.destination(&id, out).await,
                _ => Reply::method_not_allowed(&mut out.body),
            },
            Route::DestinationReset(id) => match method {
                Method::Post => ctx.reset_destination(&id, out).await,
                _ => Reply::method_not_allowed(&mut out.body),
            },
            Route::Mapping(identifier) => match method {
                Method::Put => ctx.put_mapping(&identifier, out).await,
                Method::Delete => ctx.delete_mapping(&identifier, out).await,
                _ => Reply::method_not_allowed(&mut out.body),
            },
            Route::Delay(identifier) => match method {
                Method::Put => ctx.put_delay(&identifier, out),
                Method::Delete => ctx.delete_delay(&identifier, out),
                _ => Reply::method_not_allowed(&mut out.body),
            },
            Route::Certificate(id) => match method {
                Method::Put => ctx.put_certificate(&id, out).await,
                _ => Reply::method_not_allowed(&mut out.body),
            },
            Route::HistoryEntry(id) => match method {
                Method::Get => ctx.history_entry(id, out).await,
                _ => Reply::method_not_allowed(&mut out.body),
            },
            Route::HistoryRestore(id) => match method {
                Method::Post => ctx.restore(id, out).await,
                _ => Reply::method_not_allowed(&mut out.body),
            },
        }
    }

    fn authenticate(&self, rt: &Runtime, request: &Request, ip: IpAddr) -> Result<Caller, Denied> {
        if request.bearer().is_some() {
            return match self.check_bearer(rt, request, ip) {
                true => Ok(Caller::Bearer),
                false => Err(Denied::Unauthorized),
            };
        }
        let view = request
            .cookie(COOKIE_NAME)
            .and_then(|cookie| self.sessions.touch(cookie, self.session_limits(rt), ip))
            .ok_or(Denied::Unauthorized)?;
        if !matches!(request.method(), Method::Get | Method::Head) {
            let csrf = request
                .header(CSRF_HEADER)
                .is_some_and(|presented| view.csrf.matches(presented));
            let site = request
                .header(FETCH_SITE_HEADER)
                .is_none_or(|site| site.eq_ignore_ascii_case(SAME_ORIGIN));
            if !(csrf && site) {
                return Err(Denied::Csrf);
            }
        }
        Ok(Caller::Session(view.tag))
    }

    fn session(
        &self,
        rt: &Runtime,
        request: &Request,
        ip: IpAddr,
        access: &mut Access,
        out: &mut Out,
    ) -> Reply {
        let limits = self.session_limits(rt);
        match request.method() {
            Method::Post => {
                let Some(body) = request.json_body::<TokenBody>() else {
                    return Reply::error(
                        &mut out.body,
                        400,
                        "bad_request",
                        "expected {\"token\":\"...\"}",
                    );
                };
                let generation = self.sessions.generation();
                match self.check_token(rt, body.token.as_bytes(), ip) {
                    TokenCheck::Valid => {}
                    TokenCheck::Invalid => {
                        tracing::warn!(%ip, "admin session login failed");
                        return Reply::unauthorized(&mut out.body);
                    }
                    TokenCheck::Locked => {
                        return Reply::error(&mut out.body, 429, "locked_out", LOCKED_OUT)
                            .closing();
                    }
                }
                let issued = match self.sessions.create(limits, generation, ip) {
                    Ok(issued) => issued,
                    Err(CreateError::Stale) => return Reply::unauthorized(&mut out.body),
                    Err(CreateError::RandomUnavailable) => {
                        return Reply::error(
                            &mut out.body,
                            500,
                            "internal",
                            "random source unavailable",
                        );
                    }
                };
                let _ = write!(
                    out.headers,
                    "Set-Cookie: {COOKIE_NAME}={}{COOKIE_ATTRIBUTES}\r\n",
                    issued.cookie
                );
                let caller = Caller::Session(issued.view.tag);
                tracing::info!(%ip, actor = %issued.view.tag, "admin session login");
                self.record_as(rt, caller, EventKind::Admin, "signed in".into(), None, ip);
                *access = Access::Authenticated;
                issued.view.reply(&mut out.body)
            }
            Method::Get => match request
                .cookie(COOKIE_NAME)
                .and_then(|cookie| self.sessions.touch(cookie, limits, ip))
            {
                Some(view) => {
                    *access = Access::Authenticated;
                    view.reply(&mut out.body)
                }
                None => Reply::unauthorized(&mut out.body),
            },
            Method::Delete => {
                if let Some(view) = request
                    .cookie(COOKIE_NAME)
                    .and_then(|cookie| self.sessions.remove(cookie, limits, ip))
                {
                    let caller = Caller::Session(view.tag);
                    tracing::info!(%ip, actor = %view.tag, "admin session logout");
                    self.record_as(rt, caller, EventKind::Admin, "signed out".into(), None, ip);
                }
                let _ = write!(
                    out.headers,
                    "Set-Cookie: {COOKIE_NAME}={COOKIE_ATTRIBUTES}; Max-Age=0\r\n"
                );
                Reply::plain(super::http::NO_CONTENT)
            }
            _ => Reply::method_not_allowed(&mut out.body),
        }
    }
}

impl SessionView {
    fn reply(&self, body: &mut Vec<u8>) -> Reply {
        Reply::json(body, 200, &SessionBody::from(self))
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../../proxy-tests/unit/src/admin/api/tests.rs"]
mod tests;
