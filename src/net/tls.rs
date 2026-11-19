/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod client;
pub mod server;

use std::sync::Arc;

use rustls::SupportedProtocolVersion;
use rustls::crypto::CryptoProvider;
use rustls::crypto::aws_lc_rs::ALL_CIPHER_SUITES;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::version::{TLS12, TLS13};

use crate::config::tls::TlsVersion;
use crate::error::{ProxyError, Result};

pub use client::{Alpn, ClientIdentity, TlsVerify, parse_pin};

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::aws_lc_rs::default_provider())
}

static TLS13_ONLY: &[&SupportedProtocolVersion] = &[&TLS13];
static TLS12_PLUS: &[&SupportedProtocolVersion] = &[&TLS12, &TLS13];

impl TlsVersion {
    fn protocol_versions(self) -> &'static [&'static SupportedProtocolVersion] {
        match self {
            TlsVersion::Tls13 => TLS13_ONLY,
            TlsVersion::Tls12 => TLS12_PLUS,
        }
    }
}

pub fn is_known_cipher_suite(name: &str) -> bool {
    ALL_CIPHER_SUITES.iter().any(|cs| {
        cs.suite()
            .as_str()
            .is_some_and(|known| known.eq_ignore_ascii_case(name))
    })
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

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/net/tls/tests.rs"]
mod tests;
