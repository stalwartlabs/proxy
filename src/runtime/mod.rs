/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod capabilities;
pub mod compile;
pub mod destination;
pub mod diff;
pub mod health;
pub mod metrics;
pub mod registry;
pub mod time;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use ahash::AHashMap;
use arc_swap::ArcSwap;
use parking_lot::{Mutex, RwLock};
use rustls::crypto::CryptoProvider;
use tokio_rustls::TlsAcceptor;

use crate::config::allow::{HostPattern, HostVerdict};
use crate::config::{
    AdminConfig, Config, ForwardedMode, ListenerConfig, MappingSource, Protocol, ProxyProtocolMode,
    Revision, ServerConfig, TlsMode,
};
use crate::error::{ProxyError, Result};
use crate::http::router::HttpRouter;
use crate::net::acceptor::{ListenerSet, StagedListeners};
use crate::net::cidr::Cidr;
use crate::observe::RedactKey;
use crate::proto::forward::LoopGuard;
use crate::route::Router;
use crate::route::key::KeyRules;
use crate::route::store::file::PendingMappings;
use capabilities::Capabilities;
use destination::Destination;
use health::{Clock, HealthChange, HealthLimits, HealthTable};
use metrics::{EventBody, EventKind, Events, Metrics, Reading};
use registry::ConnRegistry;
use time::UtcTime;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DestId(u16);

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ListenerId(u16);

impl DestId {
    pub fn new(index: usize) -> Option<Self> {
        u16::try_from(index).ok().map(DestId)
    }

    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

impl ListenerId {
    pub const fn index(self) -> usize {
        self.0 as usize
    }
}

#[derive(Clone, Default)]
struct Names {
    names: Vec<Arc<str>>,
    index: AHashMap<Arc<str>, u16>,
}

impl Names {
    fn intern(&mut self, name: &str) -> Option<u16> {
        if let Some(id) = self.index.get(name) {
            return Some(*id);
        }
        let id = u16::try_from(self.names.len()).ok()?;
        let name: Arc<str> = Arc::from(name);
        self.names.push(name.clone());
        self.index.insert(name, id);
        Some(id)
    }

    fn get(&self, name: &str) -> Option<u16> {
        self.index.get(name).copied()
    }

    fn name(&self, id: u16) -> Option<Arc<str>> {
        self.names.get(usize::from(id)).cloned()
    }

    fn len(&self) -> usize {
        self.names.len()
    }

    fn absorb(&mut self, forked: &Names, base: usize) -> Option<()> {
        for name in forked.names.get(base..).unwrap_or_default() {
            self.intern(name)?;
        }
        Some(())
    }
}

#[derive(Default)]
pub struct IdTable {
    dests: RwLock<Names>,
    listeners: RwLock<Names>,
}

impl IdTable {
    pub fn intern_dest(&self, name: &str) -> Result<DestId> {
        self.dests
            .write()
            .intern(name)
            .map(DestId)
            .ok_or_else(|| ProxyError::config("too many destination names: restart required"))
    }

    pub fn intern_listener(&self, name: &str) -> Result<ListenerId> {
        self.listeners
            .write()
            .intern(name)
            .map(ListenerId)
            .ok_or_else(|| ProxyError::config("too many listener names: restart required"))
    }

    fn fork(&self) -> IdFork {
        let dests = self.dests.read().clone();
        let listeners = self.listeners.read().clone();
        IdFork {
            dest_base: dests.len(),
            listener_base: listeners.len(),
            table: IdTable {
                dests: RwLock::new(dests),
                listeners: RwLock::new(listeners),
            },
        }
    }

    fn merge(&self, fork: &IdFork) -> Result<()> {
        let forked_dests = fork.table.dests.read();
        let forked_listeners = fork.table.listeners.read();
        let mut dests = self.dests.write();
        let mut listeners = self.listeners.write();
        if dests.len() != fork.dest_base || listeners.len() != fork.listener_base {
            return Err(ProxyError::config(
                "destination or listener names changed while the configuration was compiled: retry",
            ));
        }
        dests
            .absorb(&forked_dests, fork.dest_base)
            .ok_or_else(|| ProxyError::config("too many destination names: restart required"))?;
        listeners
            .absorb(&forked_listeners, fork.listener_base)
            .ok_or_else(|| ProxyError::config("too many listener names: restart required"))
    }

    pub fn dest_id(&self, name: &str) -> Option<DestId> {
        self.dests.read().get(name).map(DestId)
    }

    pub fn listener_id(&self, name: &str) -> Option<ListenerId> {
        self.listeners.read().get(name).map(ListenerId)
    }

    pub fn dest_name(&self, id: DestId) -> Option<Arc<str>> {
        self.dests.read().name(id.0)
    }

    pub fn listener_name(&self, id: ListenerId) -> Option<Arc<str>> {
        self.listeners.read().name(id.0)
    }

    pub fn dest_count(&self) -> usize {
        self.dests.read().len()
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.read().len()
    }
}

struct IdFork {
    dest_base: usize,
    listener_base: usize,
    table: IdTable,
}

pub struct Shared {
    pub ids: Arc<IdTable>,
    pub registry: ConnRegistry,
    pub metrics: Arc<Metrics>,
    pub events: Events,
    pub health: HealthTable,
    pub clock: Clock,
    pub redact: RedactKey,
    pub listeners: ListenerSet,
    session_seq: AtomicU64,
}

impl Shared {
    pub fn new(config: &Config) -> Result<Arc<Self>> {
        let ids = IdTable::default();
        let mut listeners: Vec<&str> = config.listener.keys().map(String::as_str).collect();
        listeners.sort_unstable();
        for name in &listeners {
            ids.intern_listener(name)?;
        }
        Ok(Arc::new(Shared {
            ids: Arc::new(ids),
            registry: ConnRegistry::default(),
            metrics: Arc::new(Metrics::new(listeners.len())),
            events: Events::default(),
            health: HealthTable::default(),
            clock: Clock::default(),
            redact: RedactKey::default(),
            listeners: ListenerSet::default(),
            session_seq: AtomicU64::new(0),
        }))
    }
}

impl Shared {
    pub fn next_session_id(&self) -> u64 {
        self.session_seq.fetch_add(1, Ordering::Relaxed)
    }

    pub fn record_event(&self, body: EventBody) -> u64 {
        self.events.push(self.clock.now(), body)
    }

    pub fn note_health(&self, dest: &str, change: HealthChange) {
        if let Some(message) = change.message() {
            tracing::info!(destination = %dest, message);
            self.record_event(EventBody::new(EventKind::Health, message).target(dest));
        }
    }
}

pub struct ServerSettings {
    pub bridge_idle: Duration,
    pub backend_timeout: Duration,
    pub backend_connect_retries: u32,
    pub health: HealthLimits,
    pub proxy_ttl: u32,
    pub hostname: Option<Box<str>>,
}

impl ServerSettings {
    fn build(server: &ServerConfig) -> Self {
        ServerSettings {
            bridge_idle: server.bridge_idle,
            backend_timeout: server.backend_timeout,
            backend_connect_retries: server.backend_connect_retries,
            health: HealthLimits::for_server(server),
            proxy_ttl: server.proxy_ttl,
            hostname: server.hostname.as_deref().map(Box::from),
        }
    }
}

pub struct ListenerSettings {
    pub id: ListenerId,
    pub name: Box<str>,
    pub protocol: Protocol,
    pub tls: TlsMode,
    pub bind: Box<[SocketAddr]>,
    pub max_connections: usize,
    pub proxy_protocol: ProxyProtocolMode,
    pub proxy_trusted: Box<[Cidr]>,
    pub preauth_timeout: Duration,
    pub max_auth_attempts: u32,
    pub forwarded: ForwardedMode,
}

impl ListenerSettings {
    fn build(id: ListenerId, name: &str, cfg: &ListenerConfig) -> Self {
        ListenerSettings {
            id,
            name: name.into(),
            protocol: cfg.protocol,
            tls: cfg.tls,
            bind: cfg.bind.as_slice().into(),
            max_connections: cfg.max_connections,
            proxy_protocol: cfg.proxy_protocol,
            proxy_trusted: cfg.proxy_trusted.as_slice().into(),
            preauth_timeout: cfg.preauth_timeout,
            max_auth_attempts: cfg.max_auth_attempts,
            forwarded: cfg.forwarded,
        }
    }
}

pub struct HttpRuntime {
    pub router: Arc<HttpRouter>,
}

pub struct Runtime {
    pub raw: Arc<Config>,
    pub boot: Arc<Config>,
    pub restart_required: Box<[Box<str>]>,
    pub revision: Revision,
    pub loaded_at: UtcTime,
    pub server: ServerSettings,
    pub destinations: Box<[Option<Destination>]>,
    pub dest_names: AHashMap<Box<str>, DestId>,
    pub default_dest: Option<DestId>,
    pub passthrough_dest: Option<DestId>,
    pub listeners: Box<[Option<ListenerSettings>]>,
    pub router: Arc<Router>,
    pub http: HttpRuntime,
    pub inbound_tls: Option<TlsAcceptor>,
    pub admin_tls: Option<TlsAcceptor>,
    pub capabilities: Capabilities,
    pub loop_guard: LoopGuard,
    pub key_rules: KeyRules,
    pub shared: Arc<Shared>,
    ids: IdFork,
    pending_mappings: Mutex<Option<PendingMappings>>,
    staged_listeners: Mutex<Option<StagedListeners>>,
}

impl Runtime {
    pub async fn build(
        raw: Arc<Config>,
        revision: Revision,
        shared: Arc<Shared>,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Self> {
        Self::compile(raw, revision, shared, provider, None).await
    }

    pub async fn rebuild(
        raw: Arc<Config>,
        revision: Revision,
        previous: &Runtime,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Self> {
        Self::compile(
            raw,
            revision,
            previous.shared.clone(),
            provider,
            Some(previous),
        )
        .await
    }

    async fn compile(
        raw: Arc<Config>,
        revision: Revision,
        shared: Arc<Shared>,
        provider: &Arc<CryptoProvider>,
        previous: Option<&Runtime>,
    ) -> Result<Self> {
        let fork = shared.ids.fork();
        let ids = &fork.table;
        let server_configs = raw.tls.server_configs(provider.clone())?;
        let inbound_tls = Some(TlsAcceptor::from(server_configs.inbound));
        let admin_tls = Some(TlsAcceptor::from(server_configs.admin));
        let allow = raw.admin.as_ref().map(|admin| &admin.allow);
        let allowed_networks: Option<Arc<[Cidr]>> = allow
            .map(|allow| {
                allow
                    .destination_hosts
                    .iter()
                    .filter_map(|pattern| match pattern {
                        HostPattern::Network(net) => Some(*net),
                        HostPattern::Name(_) | HostPattern::Subdomain(_) => None,
                    })
                    .collect::<Arc<[Cidr]>>()
            })
            .filter(|networks| !networks.is_empty());

        let mut sorted: Vec<_> = raw.destination.iter().collect();
        sorted.sort_unstable_by_key(|(name, _)| name.as_str());
        let mut dest_names = AHashMap::with_capacity(sorted.len());
        let mut built = Vec::with_capacity(sorted.len());
        for (name, cfg) in sorted {
            let name = name.as_str();
            let id = ids.intern_dest(name)?;
            let interned = ids.dest_name(id).unwrap_or_else(|| Arc::from(name));
            let mut dest = Destination::build(id, interned, cfg, provider, &shared.health)?;
            if let (Some(allow), Some(networks)) = (allow, &allowed_networks)
                && allow.destination_host(&cfg.host) == HostVerdict::ByAddress
            {
                dest.restrict_peers(networks);
            }
            built.push(dest);
            dest_names.insert(Box::from(name), id);
        }
        let mut destinations: Vec<Option<Destination>> = Vec::new();
        destinations.resize_with(ids.dest_count(), || None);
        for dest in built {
            if let Some(slot) = destinations.get_mut(dest.id.index()) {
                *slot = Some(dest);
            }
        }

        let dest_id = |name: &str| {
            dest_names.get(name).copied().ok_or_else(|| {
                ProxyError::config(format!(
                    "routing references undeclared destination {name:?}"
                ))
            })
        };
        let default_dest = raw
            .routing
            .as_ref()
            .map(|routing| dest_id(&routing.default_destination))
            .transpose()?;
        let passthrough_dest = raw
            .routing
            .as_ref()
            .and_then(|routing| routing.smtp_passthrough_destination.as_deref())
            .map(dest_id)
            .transpose()?;

        let boot = previous.map_or_else(|| raw.clone(), |previous| previous.boot.clone());
        let mut built_listeners = Vec::with_capacity(raw.listener.len());
        for (name, cfg) in &raw.listener {
            built_listeners.push(ListenerSettings::build(
                ids.intern_listener(name)?,
                name,
                cfg,
            ));
        }
        let mut listeners: Vec<Option<ListenerSettings>> = Vec::new();
        listeners.resize_with(ids.listener_count(), || None);
        for settings in built_listeners {
            if let Some(slot) = listeners.get_mut(settings.id.index()) {
                *slot = Some(settings);
            }
        }
        let restart_required = boot.restart_required(&raw).into_boxed_slice();

        let reused = previous
            .filter(|previous| previous.router_reusable(&raw, &dest_names))
            .map(|previous| previous.router.clone());
        let router = match &reused {
            Some(router) => router.clone(),
            None => {
                Arc::new(Router::build(&raw, &dest_names, shared.ids.clone(), shared.clock).await?)
            }
        };
        let http_router = Arc::new(HttpRouter::build(
            &raw.http,
            &raw.oauth.jwt_username_claim,
            &dest_names,
        )?);

        let pending_mappings = match reused {
            Some(router) => router.prepare_reload().await?,
            None => None,
        };
        let mut routed = Vec::new();
        for protocol in raw.listener.values().map(|l| l.protocol) {
            if !protocol.is_passthrough()
                && protocol != Protocol::Http
                && !routed.contains(&protocol)
            {
                routed.push(protocol);
            }
        }
        match &pending_mappings {
            Some(pending) => raw.check_mapped_destinations(&routed, pending.destinations())?,
            None => raw.check_mapped_destinations(
                &routed,
                router.mapped_destinations().iter().map(AsRef::as_ref),
            )?,
        }

        Ok(Runtime {
            server: ServerSettings::build(&raw.server),
            capabilities: Capabilities::build(&raw.capabilities),
            loop_guard: LoopGuard::new(
                raw.listener
                    .values()
                    .flat_map(|l| l.bind.iter().copied())
                    .chain(
                        boot.admin
                            .iter()
                            .chain(&raw.admin)
                            .flat_map(AdminConfig::binds),
                    ),
                raw.server.proxy_ttl,
            ),
            key_rules: KeyRules::from_config(&raw),
            destinations: destinations.into_boxed_slice(),
            dest_names,
            default_dest,
            passthrough_dest,
            listeners: listeners.into_boxed_slice(),
            router,
            http: HttpRuntime {
                router: http_router,
            },
            inbound_tls,
            admin_tls,
            revision,
            loaded_at: UtcTime(SystemTime::now()),
            raw,
            boot,
            restart_required,
            shared,
            ids: fork,
            pending_mappings: Mutex::new(pending_mappings),
            staged_listeners: Mutex::new(None),
        })
    }

    pub fn bind_listeners(&self) -> Result<()> {
        let staged = self.shared.listeners.stage(&self.raw)?;
        *self.staged_listeners.lock() = Some(staged);
        Ok(())
    }

    fn take_staged_listeners(&self) -> Result<StagedListeners> {
        match self.staged_listeners.lock().take() {
            Some(staged) => Ok(staged),
            None => self.shared.listeners.stage(&self.raw),
        }
    }

    pub fn activate(self) -> Result<Arc<Runtime>> {
        self.commit()?;
        if let Some(admin) = &self.raw.admin
            && !admin.bind.ip().to_canonical().is_loopback()
        {
            tracing::warn!(
                bind = %admin.bind,
                "admin.bind is not a loopback address: the management API is reachable from the network; bind it to loopback or a trusted management network"
            );
        }
        for dest in self.raw.destination.values() {
            if dest.tls_allow_invalid_certs {
                tracing::warn!(
                    host = %dest.host,
                    "tls_allow_invalid_certs is enabled: the proxy->backend leg is UNAUTHENTICATED and forwards real credentials"
                );
            }
        }
        Ok(Arc::new(self))
    }

    pub fn install(self, swap: &Arc<ArcSwap<Runtime>>) -> Result<Arc<Runtime>> {
        let staged = self.take_staged_listeners()?;
        let rt = self.activate()?;
        swap.store(rt.clone());
        rt.shared.listeners.start(staged, swap, &rt);
        Ok(rt)
    }

    pub fn launch(self) -> Result<Arc<ArcSwap<Runtime>>> {
        let staged = self.take_staged_listeners()?;
        let rt = self.activate()?;
        let swap = Arc::new(ArcSwap::new(rt.clone()));
        rt.shared.listeners.start(staged, &swap, &rt);
        Ok(swap)
    }

    pub fn commit(&self) -> Result<()> {
        self.shared.ids.merge(&self.ids)?;
        if let Some(pending) = self.pending_mappings.lock().take() {
            self.router.install(pending);
        }
        self.shared.health.commit(
            self.destinations
                .iter()
                .flatten()
                .map(|dest| (&*dest.name, dest.target, &dest.health)),
        );
        Ok(())
    }

    fn router_reusable(&self, raw: &Config, dest_names: &AHashMap<Box<str>, DestId>) -> bool {
        self.raw.mapping == raw.mapping
            && self.raw.default_destination() == raw.default_destination()
            && self.dest_names.len() == dest_names.len()
            && dest_names
                .keys()
                .all(|name| self.dest_names.contains_key(name))
    }

    pub fn destination(&self, id: DestId) -> Option<&Destination> {
        self.destinations.get(id.index()).and_then(Option::as_ref)
    }

    pub fn dest_id(&self, name: &str) -> Option<DestId> {
        self.dest_names.get(name).copied()
    }

    pub fn reading(&self) -> Reading {
        let shared = &self.shared;
        Reading {
            at: shared.clock.now(),
            active_connections: shared.metrics.active_connections.load(Ordering::Relaxed),
            sessions: u64::try_from(shared.registry.session_count()).unwrap_or(u64::MAX),
            totals: shared.metrics.totals(),
            cache: self.router.stats.snapshot(),
        }
    }

    pub fn listener(&self, id: ListenerId) -> Option<&ListenerSettings> {
        self.listeners.get(id.index()).and_then(Option::as_ref)
    }
}

impl Config {
    fn check_mapped_destinations<'a>(
        &self,
        routed: &[Protocol],
        mapped: impl Iterator<Item = &'a str>,
    ) -> Result<()> {
        if self.mapping.as_ref().is_some_and(|mapping| {
            matches!(mapping.source, MappingSource::Redis | MappingSource::Sql)
        }) {
            tracing::info!(
                "dynamic mapping store: per-destination protocol support is validated at connection time, not at boot"
            );
            return Ok(());
        }
        for name in mapped {
            let Some(dest) = self.destination.get(name) else {
                continue;
            };
            if let Some(missing) = routed.iter().find(|p| !dest.protocol.contains_key(p)) {
                return Err(ProxyError::config(format!(
                    "mapped destination {name:?} does not declare protocol {} required by a listener",
                    missing.as_str()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/runtime/tests.rs"]
mod tests;

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/runtime/test_support.rs"]
mod test_support;
