/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::harness::*;

fn submission_config(port: u16, mapping_path: &str, plain: bool) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{mapping_path}"

[capabilities.submission]
allow_plain_auth_without_tls = {plain}

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.submission]
port = {port}
tls = "plain"

[listener.submission]
protocol = "submission"
bind = ["127.0.0.1:0"]
tls = "plain"
"#
    )
}

async fn submission_backend(mut sock: tokio::net::TcpStream, want_user: &'static str) {
    sock.write_all(b"220 mock ESMTP\r\n").await.unwrap();

    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];

    async fn read_line_into(
        sock: &mut tokio::net::TcpStream,
        buf: &mut Vec<u8>,
        scratch: &mut [u8; 1024],
    ) -> Option<String> {
        loop {
            if let Some(pos) = find(buf, b"\r\n") {
                let line = String::from_utf8_lossy(&buf[..pos]).into_owned();
                buf.drain(..pos + 2);
                return Some(line);
            }
            let n = sock.read(scratch).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&scratch[..n]);
        }
    }

    let ehlo = read_line_into(&mut sock, &mut buf, &mut scratch)
        .await
        .unwrap();
    assert!(
        ehlo.to_uppercase().starts_with("EHLO"),
        "expected EHLO from proxy, got {ehlo}"
    );
    sock.write_all(b"250-mock\r\n250 AUTH PLAIN\r\n")
        .await
        .unwrap();

    let auth = read_line_into(&mut sock, &mut buf, &mut scratch)
        .await
        .unwrap();
    assert!(
        auth.starts_with("AUTH PLAIN "),
        "expected AUTH PLAIN, got {auth}"
    );
    let b64 = auth.split_whitespace().nth(2).unwrap();
    let raw = BASE64.decode(b64).unwrap();
    assert!(
        find(&raw, want_user.as_bytes()).is_some(),
        "decoded IR {:?} should contain {want_user}",
        String::from_utf8_lossy(&raw)
    );
    sock.write_all(b"235 2.7.0 Authentication successful\r\n")
        .await
        .unwrap();
}

#[tokio::test]
async fn submission_ehlo_auth_routes_and_bridges() {
    let (port, backend) = dummy_backend(|sock| submission_backend(sock, "user@example.com")).await;
    let mapping = mapping_file("");
    let toml = submission_config(port, &mapping.path().display().to_string(), true);
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["submission"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::smtp::handle_submission(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40020".parse().unwrap(),
            "127.0.0.1:587".parse().unwrap(),
        )
        .await;
    });

    let greeting = read_line(&mut client).await;
    assert!(greeting.starts_with("220"), "greeting: {greeting}");

    send(&mut client, b"EHLO test\r\n").await;
    let ehlo_resp = read_until(&mut client, b"250 ").await;
    let ehlo_str = String::from_utf8_lossy(&ehlo_resp);
    assert!(
        ehlo_str.contains("250-"),
        "expected multiline EHLO, got {ehlo_str}"
    );
    assert!(
        ehlo_str.to_uppercase().contains("AUTH"),
        "expected AUTH advertised, got {ehlo_str}"
    );

    let ir = BASE64.encode(b"\0user@example.com\0secret");
    send(&mut client, format!("AUTH PLAIN {ir}\r\n").as_bytes()).await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"235").is_some(),
        "expected 235, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn submission_auth_rejected_without_tls_when_plain_disabled() {
    let mapping = mapping_file("");
    let toml = submission_config(1, &mapping.path().display().to_string(), false);
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["submission"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::smtp::handle_submission(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40021".parse().unwrap(),
            "127.0.0.1:587".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    send(&mut client, b"EHLO test\r\n").await;
    let _ehlo = read_until(&mut client, b"250 ").await;

    let ir = BASE64.encode(b"\0user@example.com\0secret");
    send(&mut client, format!("AUTH PLAIN {ir}\r\n").as_bytes()).await;
    let resp = read_until(&mut client, b"\r\n").await;
    let resp_str = String::from_utf8_lossy(&resp);
    assert!(
        resp_str.starts_with("535") || resp_str.starts_with("538"),
        "expected 535/538 refusal, got {resp_str}"
    );
    handler.abort();
}

#[tokio::test]
async fn submission_bad_inline_ir_does_not_loop() {
    let mapping = mapping_file("");
    let toml = submission_config(1, &mapping.path().display().to_string(), true);
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["submission"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::smtp::handle_submission(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40022".parse().unwrap(),
            "127.0.0.1:587".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    send(&mut client, b"EHLO test\r\n").await;
    let _ehlo = read_until(&mut client, b"250 ").await;

    let ir = BASE64.encode(b"nonulhere");
    send(
        &mut client,
        format!("AUTH PLAIN {ir}\r\nNOOP\r\n").as_bytes(),
    )
    .await;

    let resp = read_to_eof(&mut client).await;
    let n535 = resp.windows(3).filter(|w| *w == b"535").count();
    assert_eq!(
        n535,
        1,
        "one bad AUTH must produce exactly one 535, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        find(&resp, b"250 2.0.0 OK").is_some(),
        "the pipelined NOOP after a bad AUTH must still be processed, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    handler.abort();
}

fn passthrough_config(port: u16, mapping_path: &str) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{mapping_path}"

[routing]
default_destination = "legacy"
smtp_passthrough_destination = "relay"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = {port}
tls = "plain"

[destination.relay]
host = "127.0.0.1"
proxy_protocol = false
[destination.relay.protocol.smtp]
port = {port}
tls = "plain"

[listener.smtp]
protocol = "smtp"
bind = ["127.0.0.1:0"]
tls = "plain"
"#
    )
}

async fn passthrough_backend(mut sock: tokio::net::TcpStream) {
    sock.write_all(b"220 relay\r\n").await.unwrap();
    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];
    loop {
        let n = sock.read(&mut scratch).await.unwrap();
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&scratch[..n]);
        if find(&buf, b"\r\n").is_some() {
            break;
        }
    }
    sock.write_all(b"250 x\r\n").await.unwrap();
}

#[tokio::test]
async fn smtp_passthrough_bridges_raw() {
    let (port, backend) = dummy_backend(passthrough_backend).await;
    let mapping = mapping_file("");
    let toml = passthrough_config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["smtp"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::smtp::handle_passthrough(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40022".parse().unwrap(),
            "127.0.0.1:25".parse().unwrap(),
        )
        .await;
    });

    let greeting = read_line(&mut client).await;
    assert!(greeting.starts_with("220 relay"), "greeting: {greeting}");

    send(&mut client, b"EHLO x\r\n").await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"250 x").is_some(),
        "expected 250 x, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    let _ = backend.await;
    handler.abort();
}
