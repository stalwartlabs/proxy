/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering::Relaxed;
use std::time::SystemTime;

use serde::Serialize;

use super::Call;
use super::view::{
    CacheView, Counters, DestinationStats, DestinationView, ListenerView, Name, Points,
    ProtocolCounts, SERIES_FIELDS, WithTtl, remaining,
};
use crate::admin::http::{Out, Reply};
use crate::config::{MappingSource, Protocol, Revision};
use crate::route::key::RoutingKey;
use crate::route::store::DestCounts;
use crate::route::{CacheState, MAX_PAGE_SIZE, Route};
use crate::runtime::health::HealthState;
use crate::runtime::metrics::{EventKind, SAMPLE_INTERVAL, SERIES_LEN};
use crate::runtime::registry::{ConnFilter, ConnInfo, DelayInfo, SessionSummary};
use crate::runtime::time::UtcTime;
use crate::runtime::{DestId, IdTable, Runtime};

const TOP_IDENTIFIERS: usize = 10;
const DEFAULT_CONNECTIONS_PAGE: usize = 100;
const DEFAULT_MAPPINGS_PAGE: usize = 50;
const DEFAULT_WINDOW_SECS: u64 = 3600;
const CURSOR_PREFIX: &str = "c:";

#[derive(Serialize)]
pub(super) struct ConfigInfo<'a> {
    path: Option<&'a str>,
    revision: Revision,
    loaded_at: UtcTime,
    writable: bool,
    restart_required: &'a [Box<str>],
}

#[derive(Serialize)]
struct SessionsInfo<'a> {
    active: usize,
    by_protocol: ProtocolCounts<'a>,
}

#[derive(Serialize, Default)]
struct HealthCounts {
    total: usize,
    up: usize,
    degraded: usize,
    down: usize,
}

#[derive(Serialize)]
struct TopView<'a> {
    identifier: &'a str,
    sessions: usize,
}

#[derive(Serialize)]
struct Overview<'a> {
    version: &'static str,
    started_at: UtcTime,
    uptime_s: u64,
    open_connections: i64,
    config: ConfigInfo<'a>,
    sessions: SessionsInfo<'a>,
    counters: Counters,
    cache: CacheView,
    destinations: HealthCounts,
    top_identifiers: Vec<TopView<'a>>,
}

#[derive(Serialize)]
struct Series<'a> {
    interval_s: u64,
    start: Option<UtcTime>,
    fields: [&'static str; SERIES_FIELDS.len()],
    points: Points<'a>,
}

#[derive(Serialize)]
struct ConnView<'a> {
    id: u64,
    identifier: Option<&'a str>,
    protocol: Protocol,
    listener: Name,
    client: SocketAddr,
    destination: Name,
    backend: SocketAddr,
    client_tls: bool,
    backend_tls: bool,
    started_at: UtcTime,
    bytes_up: u64,
    bytes_down: u64,
}

#[derive(Serialize)]
struct ConnList<'a> {
    total: usize,
    next_cursor: Option<String>,
    items: Vec<ConnView<'a>>,
}

#[derive(Serialize)]
pub(super) struct DelayView<'a> {
    identifier: &'a str,
    until: UtcTime,
    remaining_s: u64,
    waiting: usize,
}

#[derive(Serialize)]
struct MappingItem<'a> {
    identifier: &'a str,
    destination: &'a str,
}

#[derive(Serialize)]
struct MappingList<'a> {
    source: Option<MappingSource>,
    writable: bool,
    listable: bool,
    total: Option<u64>,
    next_cursor: Option<&'a str>,
    items: Vec<MappingItem<'a>>,
}

#[derive(Serialize)]
struct CacheEntryView {
    state: &'static str,
    ttl_remaining_s: Option<u64>,
}

#[derive(Serialize)]
struct LookupView<'a> {
    identifier: &'a str,
    account: &'a str,
    key: &'a str,
    store_value: Option<&'a str>,
    store_error: bool,
    destination: Option<&'a str>,
    routed_to_default: bool,
    cache: CacheEntryView,
}

#[derive(Serialize)]
struct EventView<'a> {
    seq: u64,
    at: UtcTime,
    kind: &'static str,
    actor: Option<&'a str>,
    ip: Option<IpAddr>,
    message: &'a str,
    target: Option<&'a str>,
}

#[derive(Serialize)]
struct EventList<'a> {
    last_seq: u64,
    items: Vec<EventView<'a>>,
}

impl<'a> From<&'a DelayInfo> for DelayView<'a> {
    fn from(delay: &'a DelayInfo) -> Self {
        let left = remaining(delay.until);
        DelayView {
            identifier: &delay.identifier,
            until: UtcTime::after(left),
            remaining_s: left.as_secs(),
            waiting: delay.waiting,
        }
    }
}

impl Call<'_> {
    pub(super) fn config_info<'a>(&'a self, rt: &'a Runtime) -> ConfigInfo<'a> {
        ConfigInfo {
            path: self.admin.config_path.as_deref(),
            revision: rt.revision,
            loaded_at: rt.loaded_at,
            writable: self.admin.config_writable(rt),
            restart_required: &rt.restart_required,
        }
    }

    pub async fn overview(&self, out: &mut Out) -> Reply {
        let rt = self.rt;
        let clock = &rt.shared.clock;
        let started_at = clock.started_at();
        let summary = rt
            .shared
            .registry
            .summary(&ConnFilter::default(), TOP_IDENTIFIERS);
        let now = clock.now();
        let mut destinations = HealthCounts::default();
        for dest in rt.destinations.iter().flatten() {
            destinations.total += 1;
            match dest.health.snapshot(now).state {
                HealthState::Up => destinations.up += 1,
                HealthState::Degraded => destinations.degraded += 1,
                HealthState::Down => destinations.down += 1,
            }
        }
        Reply::json(
            &mut out.body,
            200,
            &Overview {
                version: env!("CARGO_PKG_VERSION"),
                started_at: UtcTime(started_at),
                uptime_s: SystemTime::now()
                    .duration_since(started_at)
                    .map_or(0, |up| up.as_secs()),
                open_connections: rt.shared.metrics.active_connections.load(Relaxed),
                config: self.config_info(rt),
                sessions: SessionsInfo {
                    active: summary.total,
                    by_protocol: ProtocolCounts(&summary.by_protocol),
                },
                counters: Counters::from(rt.shared.metrics.totals()),
                cache: CacheView::of(rt, WithTtl::No),
                destinations,
                top_identifiers: summary
                    .top_identifiers
                    .iter()
                    .map(|top| TopView {
                        identifier: &top.identifier,
                        sessions: top.sessions,
                    })
                    .collect(),
            },
        )
    }

    pub fn series(&self, out: &mut Out) -> Reply {
        let window = match self.request.query_param("window") {
            Some(window) => match window.parse::<u64>() {
                Ok(window) => window,
                Err(_) => return Reply::error(&mut out.body, 400, "bad_request", "invalid window"),
            },
            None => DEFAULT_WINDOW_SECS,
        };
        let interval = SAMPLE_INTERVAL.as_secs().max(1);
        let max = usize::try_from(window.div_ceil(interval))
            .unwrap_or(SERIES_LEN)
            .min(SERIES_LEN);
        let samples = self.rt.shared.metrics.series(max);
        let clock = &self.rt.shared.clock;
        Reply::json(
            &mut out.body,
            200,
            &Series {
                interval_s: interval,
                start: samples.first().map(|sample| UtcTime(clock.wall(sample.at))),
                fields: SERIES_FIELDS,
                points: Points(&samples),
            },
        )
    }

    pub async fn destinations(&self, out: &mut Out) -> Reply {
        let rt = self.rt;
        let counts = rt.mapped_counts().await;
        let summary = rt.shared.registry.summary(&ConnFilter::default(), 0);
        let now = rt.shared.clock.now();
        let snapshots: Vec<_> = rt
            .destinations
            .iter()
            .flatten()
            .filter_map(|dest| {
                let config = rt.raw.destination.get(&*dest.name)?;
                Some((dest, config, dest.health.snapshot(now)))
            })
            .collect();
        let views: Vec<_> = snapshots
            .iter()
            .map(|(dest, config, health)| {
                DestinationView::new(
                    rt,
                    dest.id,
                    &dest.name,
                    config,
                    health,
                    DestinationStats::new(&summary, counts.as_ref(), dest.id),
                )
            })
            .collect();
        Reply::json(&mut out.body, 200, &views)
    }

    pub async fn destination(&self, name: &str, out: &mut Out) -> Reply {
        self.rt.destination_reply(name, out).await
    }

    pub fn listeners(&self, out: &mut Out) -> Reply {
        let rt = self.rt;
        let summary = rt.shared.registry.summary(&ConnFilter::default(), 0);
        let views: Vec<_> = rt
            .listeners
            .iter()
            .flatten()
            .map(|listener| {
                let totals = rt.shared.metrics.listener(listener.id).totals();
                ListenerView {
                    id: &listener.name,
                    protocol: listener.protocol,
                    bind: &listener.bind,
                    tls: listener.tls,
                    proxy_protocol: listener.proxy_protocol,
                    proxy_trusted: &listener.proxy_trusted,
                    max_connections: listener.max_connections,
                    sessions: summary.listener(listener.id),
                    preauth_timeout_s: listener.preauth_timeout.as_secs(),
                    max_auth_attempts: listener.max_auth_attempts,
                    forwarded: listener.forwarded,
                    accepted: totals.accepted,
                    rejected_limit: totals.rejected_limit,
                }
            })
            .collect();
        Reply::json(&mut out.body, 200, &views)
    }

    fn limit_param(&self, default: usize, max: usize) -> Option<usize> {
        match self.request.query_param("limit") {
            Some(limit) => limit
                .parse::<usize>()
                .ok()
                .filter(|limit| (1..=max).contains(limit)),
            None => Some(default),
        }
    }

    fn nonempty_param<'a>(&'a self, name: &str) -> Option<Cow<'a, str>> {
        self.request
            .query_param(name)
            .filter(|value| !value.is_empty())
    }

    fn parsed_param<T>(
        &self,
        name: &str,
        parse: impl FnOnce(&str) -> Option<T>,
    ) -> Result<Option<T>, ()> {
        self.nonempty_param(name)
            .map(|value| parse(&value).ok_or(()))
            .transpose()
    }

    pub fn connections(&self, out: &mut Out) -> Reply {
        let rt = self.rt;
        let ids = &rt.shared.ids;
        let Some(limit) = self.limit_param(DEFAULT_CONNECTIONS_PAGE, MAX_PAGE_SIZE) else {
            return Reply::error(&mut out.body, 400, "bad_request", "invalid limit");
        };
        let Ok(cursor) = self.parsed_param("cursor", |cursor| {
            cursor
                .strip_prefix(CURSOR_PREFIX)
                .unwrap_or(cursor)
                .parse::<u64>()
                .ok()
        }) else {
            return Reply::error(&mut out.body, 400, "bad_request", "invalid cursor");
        };
        let Ok(protocol) = self.parsed_param("protocol", |name| Protocol::parse(name.as_bytes()))
        else {
            return Reply::error(&mut out.body, 400, "bad_request", "unknown protocol");
        };
        let Ok(dest) = self.parsed_param("destination", |name| ids.dest_id(name)) else {
            return Reply::error(
                &mut out.body,
                400,
                "unknown_destination",
                "unknown destination",
            );
        };
        let Ok(listener) = self.parsed_param("listener", |name| ids.listener_id(name)) else {
            return Reply::error(&mut out.body, 400, "unknown_listener", "unknown listener");
        };
        let identifier = self.nonempty_param("identifier");
        let page = rt.shared.registry.list(
            &ConnFilter {
                identifier_prefix: identifier.as_deref(),
                protocol,
                dest,
                listener,
            },
            cursor,
            limit,
        );
        let items = page
            .items
            .iter()
            .map(|info| ConnView::new(info, ids))
            .collect();
        Reply::json(
            &mut out.body,
            200,
            &ConnList {
                total: page.total,
                next_cursor: page
                    .next_cursor
                    .map(|cursor| format!("{CURSOR_PREFIX}{cursor}")),
                items,
            },
        )
    }

    pub fn delays(&self, out: &mut Out) -> Reply {
        let delays = self.rt.shared.registry.delays();
        let views: Vec<_> = delays.iter().map(DelayView::from).collect();
        Reply::json(&mut out.body, 200, &views)
    }

    pub async fn mappings(&self, out: &mut Out) -> Reply {
        let rt = self.rt;
        let router = &rt.router;
        let Some(limit) = self.limit_param(DEFAULT_MAPPINGS_PAGE, MAX_PAGE_SIZE) else {
            return Reply::error(&mut out.body, 400, "bad_request", "invalid limit");
        };
        let prefix = self.request.query_param("prefix").unwrap_or_default();
        let cursor = self.nonempty_param("cursor");
        let listable = router.store_listable();
        let total = match router.count().await {
            Ok(total) => total,
            Err(err) => {
                tracing::warn!(error = %err, "admin mapping count failed");
                None
            }
        };
        let page = match listable {
            true => match router.list(&prefix, cursor.as_deref(), limit).await {
                Ok(page) => Some(page),
                Err(err) => {
                    tracing::warn!(error = %err, "admin mapping list failed");
                    return Reply::error(&mut out.body, 502, "store_error", "mapping store error");
                }
            },
            false => None,
        };
        Reply::json(
            &mut out.body,
            200,
            &MappingList {
                source: rt.raw.mapping.as_ref().map(|mapping| mapping.source),
                writable: router.store_writable(),
                listable,
                total,
                next_cursor: page.as_ref().and_then(|page| page.next_cursor.as_deref()),
                items: page
                    .as_ref()
                    .map(|page| {
                        page.items
                            .iter()
                            .map(|entry| MappingItem {
                                identifier: &entry.key,
                                destination: &entry.destination,
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            },
        )
    }

    pub async fn lookup(&self, out: &mut Out) -> Reply {
        let rt = self.rt;
        let Some(identifier) = self.request.query_param("identifier") else {
            return Reply::error(&mut out.body, 400, "bad_request", "identifier required");
        };
        let Ok(Some(explained)) = RoutingKey::parse_explained(&identifier, &rt.key_rules) else {
            return Reply::error(
                &mut out.body,
                400,
                "invalid_identifier",
                "invalid identifier",
            );
        };
        let inspection = rt.router.inspect(&explained.key).await;
        let (store_value, store_error) = match &inspection.store {
            Ok(value) => (value.as_deref(), false),
            Err(_) => (None, true),
        };
        let ids = &rt.shared.ids;
        let (destination, routed_to_default) = match inspection.route {
            Route::Mapped(id) => (ids.dest_name(id), false),
            Route::Default | Route::Transient => {
                (rt.default_dest.and_then(|id| ids.dest_name(id)), true)
            }
        };
        Reply::json(
            &mut out.body,
            200,
            &LookupView {
                identifier: &identifier,
                account: explained.account,
                key: explained.key.as_str(),
                store_value,
                store_error,
                destination: destination.as_deref(),
                routed_to_default,
                cache: CacheEntryView {
                    state: inspection.cache.label(),
                    ttl_remaining_s: inspection.ttl_remaining.map(|ttl| ttl.as_secs()),
                },
            },
        )
    }

    pub fn cache(&self, out: &mut Out) -> Reply {
        Reply::json(&mut out.body, 200, &CacheView::of(self.rt, WithTtl::Yes))
    }

    pub fn events(&self, out: &mut Out) -> Reply {
        let rt = self.rt;
        let Ok(after) = self.parsed_param("after", |after| after.parse::<u64>().ok()) else {
            return Reply::error(&mut out.body, 400, "bad_request", "invalid after");
        };
        let Ok(kind) = self.parsed_param("kind", |kind| EventKind::parse(kind.as_bytes())) else {
            return Reply::error(&mut out.body, 400, "bad_request", "unknown event kind");
        };
        let page = rt.shared.events.since(after.unwrap_or(0), kind);
        let clock = &rt.shared.clock;
        Reply::json(
            &mut out.body,
            200,
            &EventList {
                last_seq: page.last_seq,
                items: page
                    .items
                    .iter()
                    .map(|event| EventView {
                        seq: event.seq,
                        at: UtcTime(clock.wall(event.at)),
                        kind: event.body.kind.as_str(),
                        actor: event.body.actor.as_deref(),
                        ip: event.body.ip,
                        message: &event.body.message,
                        target: event.body.target.as_deref(),
                    })
                    .collect(),
            },
        )
    }
}

impl CacheState {
    const fn label(self) -> &'static str {
        match self {
            CacheState::Miss => "miss",
            CacheState::Positive => "positive",
            CacheState::Negative => "negative",
            CacheState::Transient => "transient",
        }
    }
}

impl Runtime {
    async fn mapped_counts(&self) -> Option<DestCounts> {
        match self.router.count_by_destination().await {
            Ok(counts) => counts,
            Err(err) => {
                tracing::warn!(error = %err, "admin mapping count failed");
                None
            }
        }
    }

    pub(super) async fn destination_reply(&self, name: &str, out: &mut Out) -> Reply {
        let rt = self;
        let Some((dest, config)) = rt
            .dest_id(name)
            .and_then(|id| rt.destination(id))
            .and_then(|dest| Some((dest, rt.raw.destination.get(name)?)))
        else {
            return Reply::error(
                &mut out.body,
                404,
                "unknown_destination",
                "unknown destination",
            );
        };
        let counts = rt.mapped_counts().await;
        let summary = rt.shared.registry.summary(
            &ConnFilter {
                dest: Some(dest.id),
                ..ConnFilter::default()
            },
            0,
        );
        let health = dest.health.snapshot(rt.shared.clock.now());
        Reply::json(
            &mut out.body,
            200,
            &DestinationView::new(
                rt,
                dest.id,
                &dest.name,
                config,
                &health,
                DestinationStats::new(&summary, counts.as_ref(), dest.id),
            ),
        )
    }
}

impl DestinationStats {
    fn new(summary: &SessionSummary, counts: Option<&DestCounts>, id: DestId) -> DestinationStats {
        DestinationStats {
            sessions: summary.dest(id),
            mapped: counts.map(|counts| counts.get(&id).copied().unwrap_or(0)),
        }
    }
}

impl<'a> ConnView<'a> {
    fn new(info: &'a ConnInfo, ids: &IdTable) -> ConnView<'a> {
        ConnView {
            id: info.id,
            identifier: info.key.as_ref().map(RoutingKey::as_str),
            protocol: info.protocol,
            listener: Name(ids.listener_name(info.listener)),
            client: info.client,
            destination: Name(ids.dest_name(info.dest)),
            backend: info.backend,
            client_tls: info.client_tls.is_some(),
            backend_tls: info.backend_tls.is_some(),
            started_at: UtcTime(info.started_at),
            bytes_up: info.bytes_up.load(Relaxed),
            bytes_down: info.bytes_down.load(Relaxed),
        }
    }
}
