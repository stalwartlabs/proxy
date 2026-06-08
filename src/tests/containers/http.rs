/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("response body is not JSON ({e}): {}", self.text()))
    }
}

pub fn basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"))
    )
}

pub async fn upgrade(
    host: &str,
    port: u16,
    tls: bool,
    path: &str,
    headers: &[(&str, &str)],
) -> Result<Response, String> {
    async fn head_only<S: AsyncRead + AsyncWrite + Unpin>(
        mut stream: S,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Result<Response, String> {
        let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n");
        for (name, value) in headers {
            req.push_str(name);
            req.push_str(": ");
            req.push_str(value);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| format!("write: {e}"))?;
        stream.flush().await.map_err(|e| format!("flush: {e}"))?;

        let mut raw = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream
                .read(&mut byte)
                .await
                .map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                break;
            }
            raw.push(byte[0]);
            if raw.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        Ok(parse_head(&raw))
    }

    let tcp = TcpStream::connect((host, port))
        .await
        .map_err(|e| format!("connect {host}:{port}: {e}"))?;
    let _ = tcp.set_nodelay(true);
    let deadline = std::time::Duration::from_secs(20);
    let fut = async {
        if tls {
            head_only(tls_client(tcp, host).await?, host, path, headers).await
        } else {
            head_only(tcp, host, path, headers).await
        }
    };
    tokio::time::timeout(deadline, fut)
        .await
        .unwrap_or_else(|_| Err(format!("upgrade request to {host}:{port} timed out")))
}

fn parse_head(raw: &[u8]) -> Response {
    let head_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let head_text = String::from_utf8_lossy(&raw[..head_end]);
    let mut lines = head_text.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    Response {
        status,
        headers,
        body: Vec::new(),
    }
}

pub async fn request(
    host: &str,
    port: u16,
    tls: bool,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Response {
    try_request(host, port, tls, method, path, headers, body)
        .await
        .unwrap_or_else(|e| panic!("{e}"))
}

pub async fn try_request(
    host: &str,
    port: u16,
    tls: bool,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<Response, String> {
    let deadline = std::time::Duration::from_secs(20);
    tokio::time::timeout(deadline, async {
        let tcp = TcpStream::connect((host, port))
            .await
            .map_err(|e| format!("connect {host}:{port}: {e}"))?;
        let _ = tcp.set_nodelay(true);
        if tls {
            let stream = tls_client(tcp, host).await?;
            exchange(stream, host, method, path, headers, body).await
        } else {
            exchange(tcp, host, method, path, headers, body).await
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err(format!(
            "http request to {host}:{port} timed out after {deadline:?}"
        ))
    })
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    host: &str,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<Response, String> {
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in headers {
        req.push_str(name);
        req.push_str(": ");
        req.push_str(value);
        req.push_str("\r\n");
    }
    if let Some(body) = body {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| format!("write: {e}"))?;
    if let Some(body) = body {
        stream
            .write_all(body)
            .await
            .map_err(|e| format!("write body: {e}"))?;
    }
    stream.flush().await.map_err(|e| format!("flush: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(|e| format!("read: {e}"))?;

    let Some(split) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Err(format!(
            "no header terminator in response: {:?}",
            String::from_utf8_lossy(&raw)
        ));
    };
    let head = &raw[..split];
    let body_raw = raw[split + 4..].to_vec();

    let head_text = String::from_utf8_lossy(head);
    let mut lines = head_text.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();
    let chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked")
    });

    let body = if chunked {
        dechunk(&body_raw)
    } else {
        body_raw
    };
    Ok(Response {
        status,
        headers,
        body,
    })
}

pub async fn get_follow(
    host: &str,
    port: u16,
    tls: bool,
    path: &str,
    headers: &[(&str, &str)],
) -> Response {
    let mut current = path.to_string();
    for _ in 0..5 {
        let resp = request(host, port, tls, "GET", &current, headers, None).await;
        if matches!(resp.status, 301 | 302 | 307 | 308)
            && let Some(location) = resp.header("location")
        {
            current = location_path(location);
            continue;
        }
        return resp;
    }
    request(host, port, tls, "GET", &current, headers, None).await
}

fn location_path(location: &str) -> String {
    if let Some(rest) = location.split_once("://") {
        match rest.1.split_once('/') {
            Some((_authority, path)) => format!("/{path}"),
            None => "/".to_string(),
        }
    } else {
        location.to_string()
    }
}

fn dechunk(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = input;
    while let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") {
        let size_line = &rest[..eol];
        let size_str = String::from_utf8_lossy(size_line);
        let size =
            usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0").trim(), 16)
                .unwrap_or(0);
        rest = &rest[eol + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size {
            out.extend_from_slice(rest);
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        }
    }
    out
}

async fn tls_client(
    tcp: TcpStream,
    sni: &str,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .unwrap_or_else(|_| rustls::pki_types::ServerName::try_from("localhost").unwrap());
    connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| format!("TLS handshake: {e}"))
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
