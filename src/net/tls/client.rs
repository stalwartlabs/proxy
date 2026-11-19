/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use rustls_platform_verifier::BuilderVerifierExt;

use super::{TLS12_PLUS, load_certs, load_key};
use crate::config::DestinationConfig;
use crate::error::{ProxyError, Result};

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

pub fn parse_pin(hex: &str) -> Result<[u8; 32]> {
    let mut digits = hex.trim().bytes().filter(|b| *b != b':');
    let mut out = [0u8; 32];
    for byte in out.iter_mut() {
        let (Some(high), Some(low)) = (digits.next(), digits.next()) else {
            return Err(pin_length_error());
        };
        let (Some(high), Some(low)) = (hex_value(high), hex_value(low)) else {
            return Err(ProxyError::config(
                "tls_pinned_cert_sha256 is not valid hex",
            ));
        };
        *byte = (high << 4) | low;
    }
    if digits.next().is_some() {
        return Err(pin_length_error());
    }
    Ok(out)
}

#[cold]
fn pin_length_error() -> ProxyError {
    ProxyError::config("tls_pinned_cert_sha256 must be 32 bytes (64 hex chars)")
}

fn hex_value(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|v| u8::try_from(v).ok())
}

pub enum TlsVerify {
    Platform,
    Pinned([u8; 32]),
    Insecure,
}

impl TlsVerify {
    pub fn from_destination(dest: &DestinationConfig) -> Result<Self> {
        match (&dest.tls_pinned_cert_sha256, dest.tls_allow_invalid_certs) {
            (Some(_), true) => Err(ProxyError::config(
                "tls_pinned_cert_sha256 cannot be combined with tls_allow_invalid_certs",
            )),
            (Some(pin), false) => parse_pin(pin).map(TlsVerify::Pinned),
            (None, true) => Ok(TlsVerify::Insecure),
            (None, false) => Ok(TlsVerify::Platform),
        }
    }
}

pub struct ClientIdentity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl ClientIdentity {
    pub fn from_destination(dest: &DestinationConfig) -> Result<Option<Self>> {
        match (&dest.tls_client_cert, &dest.tls_client_key) {
            (Some(cert), Some(key)) => Ok(Some(ClientIdentity {
                chain: load_certs(cert)?,
                key: load_key(key)?,
            })),
            (None, None) => Ok(None),
            _ => Err(ProxyError::config(
                "tls_client_cert and tls_client_key must both be set",
            )),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Alpn {
    None,
    Http11,
}

impl TlsVerify {
    pub fn client_config(
        &self,
        identity: Option<&ClientIdentity>,
        alpn: Alpn,
        provider: &Arc<CryptoProvider>,
    ) -> Result<Arc<ClientConfig>> {
        let builder = ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(TLS12_PLUS)
            .map_err(|e| ProxyError::tls(format!("tls client config: {e}")))?;

        let verified = match self {
            TlsVerify::Insecure => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerifier)),
            TlsVerify::Pinned(pin) => {
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(PinnedVerifier {
                        pin: *pin,
                        provider: provider.clone(),
                    }))
            }
            TlsVerify::Platform => builder
                .with_platform_verifier()
                .map_err(|e| ProxyError::tls(format!("platform verifier: {e}")))?,
        };

        let mut config = match identity {
            Some(identity) => verified
                .with_client_auth_cert(identity.chain.clone(), identity.key.clone_key())
                .map_err(|e| ProxyError::tls(format!("backend client certificate: {e}")))?,
            None => verified.with_no_client_auth(),
        };

        if alpn == Alpn::Http11 {
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
        }

        Ok(Arc::new(config))
    }
}
