/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::sync::Arc;

use ahash::AHashMap;
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

use super::{load_certs, load_key};
use crate::config::tls::{ADMIN_CERTIFICATE_ID, DEFAULT_SUBJECT, TlsConfig};
use crate::error::{ProxyError, Result};

const WILDCARD_PREFIX: &str = "*.";
const SELF_SIGNED_NAME: &str = "localhost";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SelfSigned {
    Allowed,
    Denied,
}

#[derive(Debug, Default)]
pub struct CertResolver {
    exact: AHashMap<Box<str>, Arc<CertifiedKey>>,
    wildcard: AHashMap<Box<str>, Arc<CertifiedKey>>,
    fallback: Option<Arc<CertifiedKey>>,
    admin: Option<Arc<CertifiedKey>>,
}

#[derive(Debug)]
struct FixedCert(Arc<CertifiedKey>);

pub struct ServerConfigs {
    pub inbound: Arc<ServerConfig>,
    pub admin: Arc<ServerConfig>,
}

impl CertResolver {
    pub fn resolve_name(&self, name: Option<&str>) -> Option<Arc<CertifiedKey>> {
        name.and_then(|name| self.matching(name))
            .or(self.fallback.as_ref())
            .cloned()
    }

    fn matching(&self, name: &str) -> Option<&Arc<CertifiedKey>> {
        let name: Cow<'_, str> = if name.bytes().any(|b| b.is_ascii_uppercase()) {
            Cow::Owned(name.to_ascii_lowercase())
        } else {
            Cow::Borrowed(name)
        };
        self.exact.get(&*name).or_else(|| {
            name.split_once('.')
                .and_then(|(_, parent)| self.wildcard.get(parent))
        })
    }

    fn insert(&mut self, id: &str, subject: &str, key: &Arc<CertifiedKey>) {
        let subject = subject.to_ascii_lowercase();
        let (table, name) = match subject.strip_prefix(WILDCARD_PREFIX) {
            Some(parent) => (&mut self.wildcard, parent),
            None => (&mut self.exact, subject.as_str()),
        };
        if table.contains_key(name) {
            tracing::warn!(
                certificate = id,
                subject = %subject,
                "subject is already served by another certificate; keeping the first by id"
            );
            return;
        }
        table.insert(name.into(), key.clone());
    }

    pub fn build(
        config: &TlsConfig,
        provider: &CryptoProvider,
        self_signed: SelfSigned,
    ) -> Result<Self> {
        let mut entries: Vec<_> = config.certificate.iter().collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
        let mut resolver = CertResolver::default();
        let mut default = None;
        let mut sole = None;
        for (index, (id, cert_cfg)) in entries.iter().enumerate() {
            let chain = load_certs(&cert_cfg.cert)?;
            let key = load_key(&cert_cfg.key)?;
            let sans;
            let subjects = if cert_cfg.subjects.is_empty() {
                sans = chain.first().map(san_dns_names).unwrap_or_default();
                &sans
            } else {
                &cert_cfg.subjects
            };
            let certified = certified_key(provider, chain, key)?;
            if id.as_str() == ADMIN_CERTIFICATE_ID {
                resolver.admin = Some(certified.clone());
            }
            let mut is_default = cert_cfg.default;
            for subject in subjects {
                if subject == DEFAULT_SUBJECT {
                    is_default = true;
                } else {
                    resolver.insert(id, subject, &certified);
                }
            }
            if is_default {
                match default {
                    None => default = Some(certified.clone()),
                    Some(_) => tracing::warn!(
                        certificate = id.as_str(),
                        "more than one default certificate; keeping the first by id"
                    ),
                }
            }
            if index == 0 {
                sole = Some(certified);
            }
        }
        resolver.fallback = match (default, entries.len()) {
            (Some(default), _) => Some(default),
            (None, 1) => sole,
            _ if self_signed == SelfSigned::Allowed => Some(self_signed_key(provider)?),
            (None, 0) => None,
            _ => {
                tracing::warn!(
                    "several certificates and none is the default: a client sending no or an unmatched SNI name fails the handshake"
                );
                None
            }
        };
        Ok(resolver)
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.resolve_name(hello.server_name())
    }
}

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

fn san_dns_names(cert: &CertificateDer<'_>) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok((_, parsed)) = X509Certificate::from_der(cert.as_ref()) {
        if let Ok(Some(san)) = parsed.subject_alternative_name() {
            names.extend(
                san.value
                    .general_names
                    .iter()
                    .filter_map(|name| match name {
                        GeneralName::DNSName(name) => Some(name.to_string()),
                        _ => None,
                    }),
            );
        }
        if names.is_empty() {
            names.extend(
                parsed
                    .subject()
                    .iter_common_name()
                    .filter_map(|cn| cn.as_str().ok().map(str::to_string)),
            );
        }
    }
    names
}

fn certified_key(
    provider: &CryptoProvider,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<CertifiedKey>> {
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| ProxyError::tls(format!("invalid signing key: {e}")))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
}

pub fn self_signed_key(provider: &CryptoProvider) -> Result<Arc<CertifiedKey>> {
    let cert = rcgen::generate_simple_self_signed(vec![SELF_SIGNED_NAME.to_string()])
        .map_err(|e| ProxyError::tls(format!("self-signed cert generation failed: {e}")))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .map_err(|e| ProxyError::tls(format!("self-signed key error: {e}")))?;
    certified_key(provider, vec![cert_der], key_der)
}

fn provider_without_disabled(
    base: &CryptoProvider,
    disabled: &[String],
) -> Result<Arc<CryptoProvider>> {
    let mut provider = base.clone();
    if !disabled.is_empty() {
        provider.cipher_suites.retain(|cs| {
            cs.suite()
                .as_str()
                .is_none_or(|name| !disabled.iter().any(|d| d.eq_ignore_ascii_case(name)))
        });
        if provider.cipher_suites.is_empty() {
            return Err(ProxyError::config(
                "disable_cipher_suites removed every available cipher suite",
            ));
        }
    }
    Ok(Arc::new(provider))
}

impl TlsConfig {
    pub fn server_configs(&self, provider: Arc<CryptoProvider>) -> Result<ServerConfigs> {
        let provider = provider_without_disabled(&provider, &self.protocols.disable_cipher_suites)?;
        let self_signed = if self.allow_self_signed {
            SelfSigned::Allowed
        } else {
            SelfSigned::Denied
        };
        let mut resolver = CertResolver::build(self, &provider, self_signed)?;
        let admin = resolver.admin.take();
        let fallback = resolver.fallback.clone();
        let inbound = self.server_config_with(&provider, Arc::new(resolver))?;
        let admin = match admin.or(fallback) {
            Some(cert) => cert,
            None => self_signed_key(&provider)?,
        };
        let admin = self.server_config_with(&provider, Arc::new(FixedCert(admin)))?;
        Ok(ServerConfigs { inbound, admin })
    }

    fn server_config_with(
        &self,
        provider: &Arc<CryptoProvider>,
        resolver: Arc<dyn ResolvesServerCert>,
    ) -> Result<Arc<ServerConfig>> {
        let versions = self.protocols.min_version.protocol_versions();
        let mut server_config = ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(versions)
            .map_err(|e| ProxyError::tls(format!("tls server config: {e}")))?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.ignore_client_order = self.protocols.ignore_client_order;
        Ok(Arc::new(server_config))
    }
}
