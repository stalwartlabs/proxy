/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::config::Config;
use crate::net::tls;
use crate::proto::common::Ctx;
use crate::route::Router;

pub fn unused_addr() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

pub async fn dummy_backend<F, Fut>(script: F) -> (u16, JoinHandle<()>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind(unused_addr()).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            let _ = socket.set_nodelay(true);
            script(socket).await;
        }
    });
    (port, handle)
}

pub async fn make_ctx(toml: &str) -> Arc<Ctx> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = Arc::new(Config::parse_and_validate(toml).expect("config should validate"));
    let provider = tls::provider();
    let server_config = tls::build_server_config(&config, provider.clone()).unwrap();
    let tls_acceptor = Some(TlsAcceptor::from(server_config));
    let valid: Vec<String> = config.destination.keys().cloned().collect();
    let router = Arc::new(Router::build(&config, valid).await.unwrap());
    let http_router = Arc::new(
        crate::http::router::HttpRouter::build(
            &config.http,
            config.oauth.jwt_username_claim.clone(),
        )
        .unwrap(),
    );
    let dests = Ctx::build_dest_runtimes(&config, &provider).unwrap();
    let dest_health = Ctx::build_dest_health(&config);
    let self_binds = Ctx::build_self_binds(&config);
    let greetings = crate::proto::common::build_greetings(&config);
    Arc::new(Ctx {
        config,
        router,
        http_router,
        tls_acceptor,
        dests,
        dest_health,
        self_binds,
        conns: Arc::new(crate::proto::common::ConnRegistry::default()),
        metrics: Arc::new(crate::proto::common::Metrics::default()),
        greetings,
    })
}

pub async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind(unused_addr()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    (client, server)
}

pub async fn read_until(stream: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];
    loop {
        if find(&buf, needle).is_some() {
            return buf;
        }
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut scratch))
            .await
            .expect("read timed out")
            .unwrap();
        if n == 0 {
            return buf;
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

pub async fn read_line(stream: &mut TcpStream) -> String {
    let buf = read_until(stream, b"\r\n").await;
    let end = find(&buf, b"\r\n").unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

pub async fn read_to_eof(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 4096];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut scratch))
            .await
        {
            Ok(Ok(0)) => return buf,
            Ok(Ok(n)) => buf.extend_from_slice(&scratch[..n]),
            Ok(Err(_)) | Err(_) => return buf,
        }
    }
}

pub async fn send(stream: &mut TcpStream, bytes: &[u8]) {
    stream.write_all(bytes).await.unwrap();
    stream.flush().await.unwrap();
}

pub fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn mapping_file(contents: &str) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(contents.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[derive(Debug)]
struct AcceptAnyCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme::*;
        vec![
            RSA_PKCS1_SHA256,
            RSA_PKCS1_SHA384,
            RSA_PKCS1_SHA512,
            ECDSA_NISTP256_SHA256,
            ECDSA_NISTP384_SHA384,
            ECDSA_NISTP521_SHA512,
            RSA_PSS_SHA256,
            RSA_PSS_SHA384,
            RSA_PSS_SHA512,
            ED25519,
        ]
    }
}

pub async fn tls_connect_client(stream: TcpStream) -> tokio_rustls::client::TlsStream<TcpStream> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    connector.connect(name, stream).await.unwrap()
}

pub async fn admin_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> (u16, String) {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, tcp).await.unwrap();

    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: admin\r\nConnection: close\r\n");
    if let Some(t) = token {
        req.push_str(&format!("Authorization: Bearer {t}\r\n"));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();

    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    (status, body)
}
