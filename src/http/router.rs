/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::time::Duration;

use ahash::AHashMap;
use encodify::base64::STANDARD as BASE64;
use globset::{Glob, GlobSet, GlobSetBuilder};
use memchr::{memchr, memchr2};
use percent_encoding::percent_decode_str;
use regex::Regex;

use crate::config::{ExtractFrom, HttpConfig, HttpExtract, HttpRoute};
use crate::error::ProxyError;
use crate::http::head::{Head, HeaderKind};
use crate::route::key::{KeyRules, RoutingKey};
use crate::runtime::DestId;
use crate::token::bearer_identifier;

const BASIC: &[u8] = b"basic";
const BEARER: &[u8] = b"bearer";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Extracted {
    Missing,
    Key(RoutingKey),
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteOutcome {
    Pin(DestId),
    Identifier {
        key: Extracted,
        fallback: Option<DestId>,
    },
}

struct Ambiguous;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchError {
    DotSegment,
}

enum Extract {
    Authorization,
    Query { param: Box<str> },
    Body { regex: Regex },
    Header { name: Box<[u8]>, kind: HeaderKind },
}

enum CompiledRoute {
    Pin(DestId),
    Extract {
        extract: Option<Extract>,
        fallback: Option<DestId>,
    },
}

pub struct HttpRouter {
    set: GlobSet,
    routes: Box<[CompiledRoute]>,
    jwt_username_claim: Box<str>,
    pub body_extract_cap: usize,
    pub max_head_size: usize,
    pub relay_idle: Duration,
    pub keepalive_timeout: Duration,
    pub max_keepalive_requests: u32,
}

impl HttpRouter {
    pub fn build(
        http: &HttpConfig,
        jwt_username_claim: &str,
        dest_names: &AHashMap<Box<str>, DestId>,
    ) -> Result<Self, ProxyError> {
        let mut builder = GlobSetBuilder::new();
        let mut routes = Vec::with_capacity(http.route.len());
        for route in &http.route {
            builder.add(
                Glob::new(&route.match_glob)
                    .map_err(|e| ProxyError::config(format!("invalid http route glob: {e}")))?,
            );
            routes.push(CompiledRoute::build(route, dest_names)?);
        }
        let set = builder
            .build()
            .map_err(|e| ProxyError::config(format!("invalid http route set: {e}")))?;
        Ok(HttpRouter {
            set,
            routes: routes.into_boxed_slice(),
            jwt_username_claim: jwt_username_claim.into(),
            body_extract_cap: http.body_extract_cap,
            max_head_size: http.max_head_size,
            relay_idle: http.relay_idle,
            keepalive_timeout: http.keepalive_timeout,
            max_keepalive_requests: http.max_keepalive_requests,
        })
    }

    pub fn match_index(
        &self,
        head: &Head,
        scratch: &mut Vec<usize>,
    ) -> Result<Option<usize>, MatchError> {
        let path = normalize_path(head.path())?;
        self.set.matches_into(path.as_ref(), scratch);
        let mut best = scratch.iter().copied().min();
        let trimmed = path.trim_end_matches('/');
        if trimmed.len() != path.len() && !trimmed.is_empty() {
            self.set.matches_into(trimmed, scratch);
            best = best.into_iter().chain(scratch.iter().copied()).min();
        }
        Ok(best)
    }

    pub fn needs_body_at(&self, idx: usize) -> bool {
        matches!(
            self.routes.get(idx),
            Some(CompiledRoute::Extract {
                extract: Some(Extract::Body { .. }),
                ..
            })
        )
    }

    pub fn route_at(
        &self,
        idx: usize,
        head: &Head,
        body: Option<&[u8]>,
        rules: &KeyRules,
    ) -> RouteOutcome {
        match self.routes.get(idx) {
            Some(CompiledRoute::Pin(dest)) => RouteOutcome::Pin(*dest),
            Some(CompiledRoute::Extract { extract, fallback }) => RouteOutcome::Identifier {
                key: match extract
                    .as_ref()
                    .map(|extract| self.extract(extract, head, body))
                {
                    None | Some(Ok(None)) => Extracted::Missing,
                    Some(Err(Ambiguous)) => Extracted::Invalid,
                    Some(Ok(Some(raw))) => match RoutingKey::parse(&raw, rules) {
                        Ok(Some(key)) => Extracted::Key(key),
                        Ok(None) => Extracted::Missing,
                        Err(_) => Extracted::Invalid,
                    },
                },
                fallback: *fallback,
            },
            None => RouteOutcome::Identifier {
                key: Extracted::Missing,
                fallback: None,
            },
        }
    }

    fn extract<'a>(
        &self,
        extract: &Extract,
        head: &'a Head,
        body: Option<&'a [u8]>,
    ) -> Result<Option<Cow<'a, str>>, Ambiguous> {
        Ok(match extract {
            Extract::Authorization => self.extract_authorization(head),
            Extract::Query { param } => match head.query() {
                Some(query) => query_param(query, param)?,
                None => None,
            },
            Extract::Body { regex } => body
                .and_then(|body| std::str::from_utf8(body).ok())
                .and_then(|text| regex.captures(text)?.get(1))
                .map(|captured| form_decode(captured.as_str())),
            Extract::Header { name, kind } => {
                let mut values = head.values_named(*kind, name);
                let first = values.next();
                if values.next().is_some() {
                    return Err(Ambiguous);
                }
                first
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .map(Cow::Borrowed)
            }
        })
    }

    fn extract_authorization<'a>(&self, head: &'a Head) -> Option<Cow<'a, str>> {
        let value = head.header(HeaderKind::Authorization)?.trim_ascii();
        if let Some(credentials) = strip_scheme(value, BASIC) {
            let mut decoded = BASE64.decode(credentials.trim_ascii()).ok()?;
            if let Some(colon) = memchr(b':', &decoded) {
                decoded.truncate(colon);
            }
            let mut login = String::from_utf8(decoded).ok()?;
            let leading = login.len() - login.trim_start().len();
            login.truncate(login.trim_end().len());
            login.drain(..leading);
            return Some(Cow::Owned(login));
        }
        let token = std::str::from_utf8(strip_scheme(value, BEARER)?.trim_ascii()).ok()?;
        bearer_identifier(token, &self.jwt_username_claim).map(Cow::Owned)
    }
}

impl CompiledRoute {
    fn build(
        route: &HttpRoute,
        dest_names: &AHashMap<Box<str>, DestId>,
    ) -> Result<Self, ProxyError> {
        let lookup = |name: &str| {
            dest_names.get(name).copied().ok_or_else(|| {
                ProxyError::config(format!(
                    "http route {:?} references undeclared destination {name:?}",
                    route.match_glob
                ))
            })
        };
        if let Some(destination) = &route.destination {
            return lookup(destination).map(CompiledRoute::Pin);
        }
        Ok(CompiledRoute::Extract {
            extract: route.extract.as_ref().map(Extract::build).transpose()?,
            fallback: route.fallback.as_deref().map(lookup).transpose()?,
        })
    }
}

impl Extract {
    fn build(extract: &HttpExtract) -> Result<Self, ProxyError> {
        let missing = |field: &str| {
            ProxyError::config(format!(
                "http extract from {:?} requires {field}",
                extract.from
            ))
        };
        Ok(match extract.from {
            ExtractFrom::Authorization => Extract::Authorization,
            ExtractFrom::Query => Extract::Query {
                param: extract
                    .param
                    .as_deref()
                    .ok_or_else(|| missing("param"))?
                    .into(),
            },
            ExtractFrom::Body => Extract::Body {
                regex: Regex::new(extract.regex.as_deref().ok_or_else(|| missing("regex"))?)
                    .map_err(|e| ProxyError::config(format!("invalid http extract regex: {e}")))?,
            },
            ExtractFrom::Header => {
                let name = extract
                    .header
                    .as_deref()
                    .ok_or_else(|| missing("header"))?
                    .as_bytes();
                Extract::Header {
                    name: name.into(),
                    kind: HeaderKind::classify(name),
                }
            }
        })
    }
}

fn strip_scheme<'a>(value: &'a [u8], scheme: &[u8]) -> Option<&'a [u8]> {
    let name = value.get(..scheme.len())?;
    let rest = value.get(scheme.len()..)?;
    if name.eq_ignore_ascii_case(scheme) {
        rest.strip_prefix(b" ")
    } else {
        None
    }
}

fn is_dot_segment(segment: &[u8]) -> bool {
    hashify::set_ignore_case!(segment, ".", "..", "%2e", ".%2e", "%2e.", "%2e%2e")
}

fn strip_authority(target: &str) -> &str {
    if target.starts_with('/') {
        return target;
    }
    let Some((scheme, rest)) = target.split_once("://") else {
        return target;
    };
    if !hashify::set_ignore_case!(scheme.as_bytes(), "http", "https") {
        return target;
    }
    match memchr(b'/', rest.as_bytes()) {
        Some(slash) => rest.get(slash..).unwrap_or("/"),
        None => "/",
    }
}

fn normalize_path(target: &str) -> Result<Cow<'_, str>, MatchError> {
    let path = strip_authority(target);
    if memchr2(b'.', b'%', path.as_bytes()).is_some()
        && path.as_bytes().split(|&b| b == b'/').any(is_dot_segment)
    {
        return Err(MatchError::DotSegment);
    }
    if !path.contains("//") {
        return Ok(Cow::Borrowed(path));
    }
    let mut collapsed = String::with_capacity(path.len());
    let mut segments = path.split('/');
    collapsed.extend(segments.next());
    for segment in segments.filter(|segment| !segment.is_empty()) {
        collapsed.push('/');
        collapsed.push_str(segment);
    }
    if path.ends_with('/') {
        collapsed.push('/');
    }
    Ok(Cow::Owned(collapsed))
}

fn query_param<'a>(query: &'a str, param: &str) -> Result<Option<Cow<'a, str>>, Ambiguous> {
    let mut values = query.split('&').filter_map(|pair| {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        (form_decode(key) == param).then_some(value)
    });
    let first = values.next();
    if values.next().is_some() {
        return Err(Ambiguous);
    }
    Ok(first.map(form_decode))
}

fn form_decode(input: &str) -> Cow<'_, str> {
    if memchr2(b'+', b'%', input.as_bytes()).is_none() {
        return Cow::Borrowed(input);
    }
    let spaced: Cow<'_, str> = if memchr(b'+', input.as_bytes()).is_some() {
        Cow::Owned(input.replace('+', " "))
    } else {
        Cow::Borrowed(input)
    };
    if memchr(b'%', spaced.as_bytes()).is_none() {
        return spaced;
    }
    Cow::Owned(percent_decode_str(&spaced).decode_utf8_lossy().into_owned())
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/http/router/tests.rs"]
mod tests;
