/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::harness::*;

fn config(port: u16, mapping_path: &str) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{mapping_path}"

[capabilities.managesieve]
allow_plain_auth_without_tls = true

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.managesieve]
port = {port}
tls = "plain"

[listener.managesieve]
protocol = "managesieve"
bind = ["127.0.0.1:0"]
tls = "plain"
"#
    )
}

async fn backend_expect_auth(mut sock: tokio::net::TcpStream, want_user: &'static str) {
    sock.write_all(b"\"IMPLEMENTATION\" \"backend\"\r\n")
        .await
        .unwrap();
    sock.write_all(b"\"SASL\" \"PLAIN\"\r\n").await.unwrap();
    sock.write_all(b"OK \"ready\"\r\n").await.unwrap();

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
    let line_end = find(&buf, b"\r\n").unwrap();
    let line = String::from_utf8_lossy(&buf[..line_end]).into_owned();
    assert!(line.starts_with("AUTHENTICATE \"PLAIN\" \""), "got: {line}");
    let b64 = line
        .rsplit('"')
        .nth(1)
        .expect("base64 token between quotes");
    let raw = BASE64.decode(b64).unwrap();
    assert!(
        find(&raw, want_user.as_bytes()).is_some(),
        "decoded IR {:?} should contain {want_user}",
        String::from_utf8_lossy(&raw)
    );
    sock.write_all(b"OK \"authenticated\"\r\n").await.unwrap();
}

#[tokio::test]
async fn managesieve_authenticate_plain_with_ir() {
    let (port, backend) = dummy_backend(|sock| backend_expect_auth(sock, "user@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["managesieve"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::managesieve::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40010".parse().unwrap(),
            "127.0.0.1:4190".parse().unwrap(),
        )
        .await;
    });

    let greeting = read_until(&mut client, b"OK ").await;
    let greeting_str = String::from_utf8_lossy(&greeting);
    assert!(
        greeting_str.contains("\"SASL\""),
        "greeting should advertise SASL, got {greeting_str}"
    );
    assert!(
        greeting_str.contains("\"SIEVE\""),
        "greeting should advertise SIEVE, got {greeting_str}"
    );

    let ir = BASE64.encode(b"\0user@example.com\0secret");
    send(
        &mut client,
        format!("AUTHENTICATE \"PLAIN\" \"{ir}\"\r\n").as_bytes(),
    )
    .await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"OK \"authenticated\"").is_some(),
        "expected OK authenticated, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn managesieve_noop_echoes_tag() {
    let (port, backend) = dummy_backend(|sock| backend_expect_auth(sock, "user@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["managesieve"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::managesieve::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40013".parse().unwrap(),
            "127.0.0.1:4190".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_until(&mut client, b"OK ").await;
    send(&mut client, b"NOOP \"STARTTLS-RESYNC-CAPA\"\r\n").await;
    let resp = read_until(&mut client, b"Done").await;
    let resp = String::from_utf8_lossy(&resp);
    assert!(
        resp.contains("(TAG {20}\r\nSTARTTLS-RESYNC-CAPA)"),
        "NOOP with a tag must echo it (RFC 5804 2.13), got {resp:?}"
    );

    send(&mut client, b"LOGOUT\r\n").await;
    backend.abort();
    handler.abort();
}

#[tokio::test]
async fn managesieve_authenticate_plain_nonsync_literal() {
    let (port, backend) = dummy_backend(|sock| backend_expect_auth(sock, "user@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["managesieve"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::managesieve::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40012".parse().unwrap(),
            "127.0.0.1:4190".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_until(&mut client, b"OK ").await;

    let ir = BASE64.encode(b"\0user@example.com\0secret");
    send(
        &mut client,
        format!("AUTHENTICATE \"PLAIN\" {{{}+}}\r\n", ir.len()).as_bytes(),
    )
    .await;
    send(&mut client, format!("{ir}\r\n").as_bytes()).await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"OK \"authenticated\"").is_some(),
        "non-sync literal auth should succeed, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn managesieve_authenticate_continuation_when_ir_omitted() {
    let (port, backend) = dummy_backend(|sock| backend_expect_auth(sock, "dan@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["managesieve"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::managesieve::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40011".parse().unwrap(),
            "127.0.0.1:4190".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_until(&mut client, b"OK ").await;
    send(&mut client, b"AUTHENTICATE \"PLAIN\"\r\n").await;
    let cont = read_until(&mut client, b"\r\n").await;
    assert!(
        find(&cont, b"{0}").is_some(),
        "expected {{0}} continuation, got {:?}",
        String::from_utf8_lossy(&cont)
    );

    let ir = BASE64.encode(b"\0dan@example.com\0secret");
    send(&mut client, format!("{ir}\r\n").as_bytes()).await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"OK \"authenticated\"").is_some(),
        "continuation auth should succeed, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn managesieve_backend_unavailable_reports_no() {
    let mapping = mapping_file("");
    let toml = format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[capabilities.managesieve]
allow_plain_auth_without_tls = true

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.managesieve]
port = 1
tls = "plain"

[listener.managesieve]
protocol = "managesieve"
bind = ["127.0.0.1:0"]
tls = "plain"
"#,
        mapping.path().display()
    );
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["managesieve"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::managesieve::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40012".parse().unwrap(),
            "127.0.0.1:4190".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_until(&mut client, b"OK ").await;
    let ir = BASE64.encode(b"\0user@example.com\0secret");
    send(
        &mut client,
        format!("AUTHENTICATE \"PLAIN\" \"{ir}\"\r\n").as_bytes(),
    )
    .await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"NO \"backend unavailable\"").is_some(),
        "expected backend unavailable NO, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    handler.abort();
}
