/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use ahash::AHashMap;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::{TLS12, TLS13};
use rustls::{
    ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme, SupportedProtocolVersion,
};
use rustls_platform_verifier::BuilderVerifierExt;

use crate::config::{Config, DestinationConfig};
use crate::error::{ProxyError, Result};

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

static TLS13_ONLY: &[&SupportedProtocolVersion] = &[&TLS13];
static TLS12_PLUS: &[&SupportedProtocolVersion] = &[&TLS12, &TLS13];

fn protocol_versions(min_version: &str) -> Result<&'static [&'static SupportedProtocolVersion]> {
    match min_version {
        "1.3" => Ok(TLS13_ONLY),
        "1.2" => Ok(TLS12_PLUS),
        other => Err(ProxyError::config(format!(
            "unsupported tls min_version {other:?} (use \"1.2\" or \"1.3\")"
        ))),
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path)
        .map_err(|e| ProxyError::config(format!("failed to read cert {path}: {e}")))?;
    let certs: std::result::Result<Vec<_>, _> =
        rustls_pemfile::certs(&mut data.as_slice()).collect();
    let certs = certs.map_err(|e| ProxyError::config(format!("invalid cert {path}: {e}")))?;
    if certs.is_empty() {
        return Err(ProxyError::config(format!(
            "no certificates found in {path}"
        )));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path)
        .map_err(|e| ProxyError::config(format!("failed to read key {path}: {e}")))?;
    rustls_pemfile::private_key(&mut data.as_slice())
        .map_err(|e| ProxyError::config(format!("invalid key {path}: {e}")))?
        .ok_or_else(|| ProxyError::config(format!("no private key found in {path}")))
}

fn san_dns_names(cert: &CertificateDer<'_>) -> Vec<String> {
    use x509_parser::prelude::*;
    let mut names = Vec::new();
    if let Ok((_, parsed)) = X509Certificate::from_der(cert.as_ref()) {
        if let Ok(Some(san)) = parsed.subject_alternative_name() {
            for gn in &san.value.general_names {
                if let GeneralName::DNSName(name) = gn {
                    names.push(name.to_string());
                }
            }
        }
        if names.is_empty() {
            for cn in parsed.subject().iter_common_name() {
                if let Ok(s) = cn.as_str() {
                    names.push(s.to_string());
                }
            }
        }
    }
    names
}

#[derive(Debug)]
pub struct CertificateResolver {
    certs: AHashMap<String, Arc<CertifiedKey>>,
    self_signed: Arc<CertifiedKey>,
}

impl CertificateResolver {
    pub fn resolve_certificate(&self, name: Option<&str>) -> Arc<CertifiedKey> {
        let pick = name
            .and_then(|name| {
                self.certs.get(name).or_else(|| {
                    name.split_once('.')
                        .and_then(|(_, parent)| self.certs.get(parent))
                })
            })
            .or_else(|| self.certs.get("*"))
            .or_else(|| {
                if self.certs.len() == 1 {
                    self.certs.values().next()
                } else {
                    None
                }
            });
        pick.cloned().unwrap_or_else(|| self.self_signed.clone())
    }
}

impl ResolvesServerCert for CertificateResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.resolve_certificate(hello.server_name()))
    }
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

fn self_signed_default(provider: &CryptoProvider) -> Result<Arc<CertifiedKey>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .map_err(|e| ProxyError::tls(format!("self-signed cert generation failed: {e}")))?;
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(cert.signing_key.serialize_der())
        .map_err(|e| ProxyError::tls(format!("self-signed key error: {e}")))?;
    certified_key(provider, vec![cert_der], key_der)
}

pub fn build_resolver(config: &Config, provider: &CryptoProvider) -> Result<CertificateResolver> {
    let mut certs: AHashMap<String, Arc<CertifiedKey>> = AHashMap::new();
    for cert_cfg in config.tls.certificate.values() {
        let chain = load_certs(&cert_cfg.cert)?;
        let key = load_key(&cert_cfg.key)?;
        let names = if cert_cfg.subjects.is_empty() {
            san_dns_names(&chain[0])
        } else {
            cert_cfg.subjects.clone()
        };
        let ck = certified_key(provider, chain, key)?;
        for name in names {
            let key = name
                .strip_prefix("*.")
                .unwrap_or(&name)
                .to_ascii_lowercase();
            certs.insert(key, ck.clone());
        }
        if cert_cfg.default {
            certs.insert("*".to_string(), ck.clone());
        }
    }
    Ok(CertificateResolver {
        certs,
        self_signed: self_signed_default(provider)?,
    })
}

fn provider_without_disabled(
    base: &CryptoProvider,
    disabled: &[String],
) -> Result<Arc<CryptoProvider>> {
    if disabled.is_empty() {
        return Ok(Arc::new(base.clone()));
    }
    let mut provider = base.clone();
    provider.cipher_suites.retain(|cs| {
        cs.suite()
            .as_str()
            .map(|name| !disabled.iter().any(|d| d.eq_ignore_ascii_case(name)))
            .unwrap_or(true)
    });
    if provider.cipher_suites.is_empty() {
        return Err(ProxyError::config(
            "disable_cipher_suites removed every available cipher suite",
        ));
    }
    Ok(Arc::new(provider))
}

pub fn build_server_config(
    config: &Config,
    provider: Arc<CryptoProvider>,
) -> Result<Arc<ServerConfig>> {
    let provider =
        provider_without_disabled(&provider, &config.tls.protocols.disable_cipher_suites)?;
    let resolver = build_resolver(config, &provider)?;
    let versions = protocol_versions(&config.tls.protocols.min_version)?;
    let mut server_config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| ProxyError::tls(format!("tls server config: {e}")))?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    server_config.ignore_client_order = config.tls.protocols.ignore_client_order;
    Ok(Arc::new(server_config))
}

#[derive(Debug)]
struct NoVerifier;

fn all_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP521_SHA512,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::ED25519,
    ]
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        all_schemes()
    }
}

#[derive(Debug)]
struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if sha256(end_entity.as_ref()) == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn parse_pin(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.trim().replace(':', "");
    if hex.len() != 64 {
        return Err(ProxyError::config(
            "tls_pinned_cert_sha256 must be 32 bytes (64 hex chars)",
        ));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| ProxyError::config("tls_pinned_cert_sha256 is not valid hex"))?;
    }
    Ok(out)
}

pub fn build_client_config(
    dest: &DestinationConfig,
    provider: Arc<CryptoProvider>,
    is_http: bool,
) -> Result<Arc<ClientConfig>> {
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(TLS12_PLUS)
        .map_err(|e| ProxyError::tls(format!("tls client config: {e}")))?;

    let verified = if dest.tls_allow_invalid_certs {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
    } else if let Some(pin) = &dest.tls_pinned_cert_sha256 {
        let verifier = PinnedVerifier {
            pin: parse_pin(pin)?,
            provider,
        };
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
    } else {
        builder
            .with_platform_verifier()
            .map_err(|e| ProxyError::tls(format!("platform verifier: {e}")))?
    };

    let mut config = match (&dest.tls_client_cert, &dest.tls_client_key) {
        (Some(cert), Some(key)) => {
            let chain = load_certs(cert)?;
            let der = load_key(key)?;
            verified
                .with_client_auth_cert(chain, der)
                .map_err(|e| ProxyError::tls(format!("backend client certificate: {e}")))?
        }
        (None, None) => verified.with_no_client_auth(),
        _ => {
            return Err(ProxyError::config(
                "tls_client_cert and tls_client_key must both be set",
            ));
        }
    };

    if is_http {
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
    }

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Arc<CertifiedKey> {
        let provider = provider();
        self_signed_default(&provider).unwrap()
    }

    fn resolver(
        entries: Vec<(&str, Arc<CertifiedKey>)>,
    ) -> (CertificateResolver, Arc<CertifiedKey>) {
        let self_signed = key();
        let mut certs = AHashMap::new();
        for (name, ck) in entries {
            certs.insert(name.to_string(), ck);
        }
        (
            CertificateResolver {
                certs,
                self_signed: self_signed.clone(),
            },
            self_signed,
        )
    }

    #[test]
    fn sni_exact_then_parent_then_star() {
        let exact = key();
        let wild = key();
        let star = key();
        let (r, _) = resolver(vec![
            ("mail.example.com", exact.clone()),
            ("example.com", wild.clone()),
            ("*", star.clone()),
        ]);

        assert!(Arc::ptr_eq(
            &r.resolve_certificate(Some("mail.example.com")),
            &exact
        ));
        assert!(Arc::ptr_eq(
            &r.resolve_certificate(Some("host.example.com")),
            &wild
        ));
        assert!(Arc::ptr_eq(
            &r.resolve_certificate(Some("nomatch.org")),
            &star
        ));
        assert!(Arc::ptr_eq(&r.resolve_certificate(None), &star));
    }

    #[test]
    fn sni_single_cert_fallback() {
        let only = key();
        let (r, _) = resolver(vec![("mail.example.com", only.clone())]);
        assert!(Arc::ptr_eq(
            &r.resolve_certificate(Some("other.org")),
            &only
        ));
    }

    #[test]
    fn sni_self_signed_when_nothing_matches() {
        let a = key();
        let b = key();
        let (r, self_signed) = resolver(vec![("a.com", a), ("b.com", b)]);
        assert!(Arc::ptr_eq(
            &r.resolve_certificate(Some("z.org")),
            &self_signed
        ));
    }

    #[test]
    fn parse_pin_accepts_hex_and_colons() {
        let raw = "a".repeat(64);
        assert!(parse_pin(&raw).is_ok());
        let colon = "AA:".repeat(31) + "AA";
        assert!(parse_pin(&colon).is_ok());
        assert!(parse_pin("tooshort").is_err());
        assert!(parse_pin(&"z".repeat(64)).is_err());
    }
}
