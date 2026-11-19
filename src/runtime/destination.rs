/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use rustls::ClientConfig;
use rustls::crypto::CryptoProvider;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;

use crate::config::{DestinationConfig, Protocol, TlsMode};
use crate::error::{ProxyError, Result};
use crate::net::cidr::Cidr;
use crate::net::dial::DnsCache;
use crate::net::tls::{Alpn, ClientIdentity, TlsVerify};
use crate::runtime::DestId;
use crate::runtime::health::{DestHealth, HealthTable};

pub use crate::config::Forwarding;

pub enum Host {
    Ip(IpAddr),
    Name(Box<str>),
}

pub enum LegTls {
    Plain,
    Starttls(Arc<ClientConfig>),
    Implicit(Arc<ClientConfig>),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CredentialEgress {
    RequireTls,
    PlaintextAllowed,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ForwardedHeader {
    Off,
    Append,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthErrors {
    Relay,
    Hide,
}

pub struct Endpoint {
    pub port: u16,
    pub leg: LegTls,
    pub forwarding: Forwarding,
    pub egress: CredentialEgress,
    pub forwarded_header: ForwardedHeader,
    pub addrs: Option<Box<[SocketAddr]>>,
    pub peers: PeerPolicy,
}

#[derive(Clone, Default)]
pub enum PeerPolicy {
    #[default]
    Any,
    Within(Arc<[Cidr]>),
}

impl Endpoint {
    pub fn check_peer(&self, tcp: &TcpStream) -> Result<()> {
        let PeerPolicy::Within(networks) = &self.peers else {
            return Ok(());
        };
        match tcp.peer_addr() {
            Ok(peer) if Cidr::any_contains(networks, peer.ip().to_canonical()) => Ok(()),
            Ok(peer) => Err(ProxyError::peer_not_allowed(peer)),
            Err(e) => Err(ProxyError::config(format!(
                "backend peer address unavailable: {e}"
            ))),
        }
    }
}

#[derive(Default)]
pub struct SourceIps {
    pub v4: Box<[Ipv4Addr]>,
    pub v6: Box<[Ipv6Addr]>,
    rr: AtomicU32,
}

impl SourceIps {
    pub fn new(ips: &[IpAddr]) -> Self {
        SourceIps {
            v4: ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V4(v4) => Some(*v4),
                    IpAddr::V6(_) => None,
                })
                .collect(),
            v6: ips
                .iter()
                .filter_map(|ip| match ip {
                    IpAddr::V6(v6) => Some(*v6),
                    IpAddr::V4(_) => None,
                })
                .collect(),
            rr: AtomicU32::new(0),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn serves(&self, backend: &SocketAddr) -> bool {
        match backend {
            SocketAddr::V4(_) => !self.v4.is_empty(),
            SocketAddr::V6(_) => !self.v6.is_empty(),
        }
    }

    pub fn pick(&self, backend: &SocketAddr) -> Option<IpAddr> {
        let next = self.rr.fetch_add(1, Ordering::Relaxed) as usize;
        match backend {
            SocketAddr::V4(_) => pick(&self.v4, next).map(IpAddr::V4),
            SocketAddr::V6(_) => pick(&self.v6, next).map(IpAddr::V6),
        }
    }
}

fn pick<T: Copy>(ips: &[T], next: usize) -> Option<T> {
    match ips.len() {
        0 => None,
        len => ips.get(next % len).copied(),
    }
}

pub struct Destination {
    pub id: DestId,
    pub name: Arc<str>,
    pub host: Host,
    pub server_name: Option<ServerName<'static>>,
    pub endpoints: [Option<Endpoint>; Protocol::COUNT],
    pub source_ips: SourceIps,
    pub dns_cache: Option<DnsCache>,
    pub auth_errors: AuthErrors,
    pub target: u64,
    pub health: Arc<DestHealth>,
    xclient_warned: AtomicBool,
}

struct LegConfigs<'a> {
    cfg: &'a DestinationConfig,
    provider: &'a Arc<CryptoProvider>,
    verify: Option<(TlsVerify, Option<ClientIdentity>)>,
    mail: Option<Arc<ClientConfig>>,
    http: Option<Arc<ClientConfig>>,
}

impl<'a> LegConfigs<'a> {
    fn new(cfg: &'a DestinationConfig, provider: &'a Arc<CryptoProvider>) -> Self {
        LegConfigs {
            cfg,
            provider,
            verify: None,
            mail: None,
            http: None,
        }
    }

    fn get(&mut self, protocol: Protocol) -> Result<Arc<ClientConfig>> {
        let (slot, alpn) = match protocol {
            Protocol::Http => (&mut self.http, Alpn::Http11),
            _ => (&mut self.mail, Alpn::None),
        };
        if let Some(config) = slot {
            return Ok(config.clone());
        }
        let (verify, identity) = match &mut self.verify {
            Some(verify) => verify,
            verify @ None => verify.insert((
                TlsVerify::from_destination(self.cfg)?,
                ClientIdentity::from_destination(self.cfg)?,
            )),
        };
        let config = verify.client_config(identity.as_ref(), alpn, self.provider)?;
        Ok(slot.insert(config).clone())
    }
}

impl Destination {
    pub fn build(
        id: DestId,
        name: Arc<str>,
        cfg: &DestinationConfig,
        provider: &Arc<CryptoProvider>,
        health: &HealthTable,
    ) -> Result<Self> {
        let target = cfg.target_fingerprint();
        let health = health.carry_over(&name, target);
        let host = match cfg.host.parse::<IpAddr>() {
            Ok(ip) => Host::Ip(ip),
            Err(_) => Host::Name(cfg.host.as_str().into()),
        };
        let server_name = match cfg.protocol.values().any(|ep| ep.tls != TlsMode::Plain) {
            true => Some(
                ServerName::try_from(cfg.tls_name())
                    .map_err(|_| {
                        ProxyError::config(format!(
                            "destination {name:?} has no valid TLS server name"
                        ))
                    })?
                    .to_owned(),
            ),
            false => None,
        };
        let mut legs = LegConfigs::new(cfg, provider);
        let mut endpoints = Protocol::ALL.map(|_| None);
        for (slot, protocol) in endpoints.iter_mut().zip(Protocol::ALL) {
            let Some(ep) = cfg.protocol.get(&protocol) else {
                continue;
            };
            let leg = match ep.tls {
                TlsMode::Plain => LegTls::Plain,
                TlsMode::Starttls => LegTls::Starttls(legs.get(protocol)?),
                TlsMode::Implicit => LegTls::Implicit(legs.get(protocol)?),
            };
            let egress = match (ep.tls, cfg.allow_plaintext_auth) {
                (TlsMode::Plain, true) => CredentialEgress::PlaintextAllowed,
                _ => CredentialEgress::RequireTls,
            };
            let forwarded_header = match (protocol, cfg.forwarded) {
                (Protocol::Http, true) => ForwardedHeader::Append,
                _ => ForwardedHeader::Off,
            };
            let addrs = match &host {
                Host::Ip(ip) => Some(Box::from([SocketAddr::new(*ip, ep.port)])),
                Host::Name(_) => None,
            };
            *slot = Some(Endpoint {
                port: ep.port,
                leg,
                forwarding: cfg.forwarding_for(protocol),
                egress,
                forwarded_header,
                addrs,
                peers: PeerPolicy::Any,
            });
        }
        let dns_cache = match host {
            Host::Name(_) => cfg.dns_cache_ttl.map(DnsCache::new),
            Host::Ip(_) => None,
        };
        Ok(Destination {
            id,
            name,
            host,
            server_name,
            endpoints,
            source_ips: SourceIps::new(&cfg.source_ips),
            dns_cache,
            auth_errors: if cfg.hide_auth_errors {
                AuthErrors::Hide
            } else {
                AuthErrors::Relay
            },
            target,
            health,
            xclient_warned: AtomicBool::new(false),
        })
    }

    pub fn endpoint(&self, protocol: Protocol) -> Result<&Endpoint> {
        self.endpoints
            .get(protocol.index())
            .and_then(Option::as_ref)
            .ok_or_else(|| {
                ProxyError::config(format!(
                    "destination {:?} does not support protocol {}",
                    self.name,
                    protocol.as_str()
                ))
            })
    }

    pub fn restrict_peers(&mut self, networks: &Arc<[Cidr]>) {
        for endpoint in self.endpoints.iter_mut().flatten() {
            endpoint.peers = PeerPolicy::Within(networks.clone());
        }
    }

    pub fn warn_once_unadvertised(&self) -> bool {
        !self.xclient_warned.swap(true, Ordering::Relaxed)
    }
}

impl ProxyError {
    #[cold]
    #[inline(never)]
    fn peer_not_allowed(peer: SocketAddr) -> ProxyError {
        ProxyError::config(format!(
            "backend address {peer} is not allowed by admin.allow.destination_hosts"
        ))
    }
}

impl DestinationConfig {
    fn target_fingerprint(&self) -> u64 {
        let mut h = DefaultHasher::new();
        self.host.hash(&mut h);
        self.tls_server_name.hash(&mut h);
        self.tls_allow_invalid_certs.hash(&mut h);
        self.tls_pinned_cert_sha256.hash(&mut h);
        self.tls_client_cert.hash(&mut h);
        self.tls_client_key.hash(&mut h);
        self.forwarded.hash(&mut h);
        self.source_ips.hash(&mut h);
        for protocol in Protocol::ALL {
            if let Some(ep) = self.protocol.get(&protocol) {
                protocol.index().hash(&mut h);
                ep.port.hash(&mut h);
                ep.tls.as_str().hash(&mut h);
                self.forwarding_for(protocol).hash(&mut h);
            }
        }
        h.finish()
    }
}
