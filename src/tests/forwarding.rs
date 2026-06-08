/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::harness::*;

async fn read_crlf(sock: &mut TcpStream, buf: &mut Vec<u8>) -> String {
    let mut scratch = [0u8; 1024];
    loop {
        if let Some(pos) = find(buf, b"\r\n") {
            let line = String::from_utf8_lossy(&buf[..pos]).into_owned();
            buf.drain(..pos + 2);
            return line;
        }
        let n = sock.read(&mut scratch).await.unwrap();
        if n == 0 {
            return String::from_utf8_lossy(buf).into_owned();
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

fn pop3_config(port: u16, mapping_path: &str) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{mapping_path}"

[capabilities.pop3]
allow_plain_auth_without_tls = true

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
forwarding = "xclient"
allow_plaintext_auth = true
[destination.legacy.protocol.pop3]
port = {port}
tls = "plain"

[listener.pop3]
protocol = "pop3"
bind = ["127.0.0.1:0"]
tls = "plain"
"#
    )
}

#[tokio::test]
async fn pop3_xclient_is_sent_when_advertised() {
    let (port, backend) = dummy_backend(|mut sock| async move {
        sock.write_all(b"+OK ready [XCLIENT]\r\n").await.unwrap();
        let mut buf = Vec::new();
        let xclient = read_crlf(&mut sock, &mut buf).await;
        assert!(xclient.starts_with("XCLIENT "), "got: {xclient}");
        assert!(xclient.contains("ADDR=203.0.113.7"), "addr: {xclient}");
        assert!(xclient.contains("PORT=40000"), "port: {xclient}");
        assert!(xclient.contains("TTL=6"), "ttl decremented: {xclient}");
        assert!(
            xclient.contains("CLIENT-TRANSPORT=insecure"),
            "transport: {xclient}"
        );
        sock.write_all(b"+OK\r\n").await.unwrap();
        let auth = read_crlf(&mut sock, &mut buf).await;
        assert!(auth.starts_with("AUTH PLAIN "), "got: {auth}");
        sock.write_all(b"+OK logged in\r\n").await.unwrap();
    })
    .await;

    let mapping = mapping_file("");
    let toml = pop3_config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["pop3"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::pop3::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "203.0.113.7:40000".parse().unwrap(),
            "127.0.0.1:110".parse().unwrap(),
        )
        .await;
    });

    let _ = read_line(&mut client).await;
    send(&mut client, b"USER user@example.com\r\nPASS secret\r\n").await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"+OK logged in").is_some(),
        "expected login, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn pop3_master_login_routes_on_account() {
    let (port, backend) = dummy_backend(|mut sock| async move {
        sock.write_all(b"+OK ready\r\n").await.unwrap();
        let mut buf = Vec::new();
        let auth = read_crlf(&mut sock, &mut buf).await;
        assert!(auth.starts_with("AUTH PLAIN "), "got: {auth}");
        let b64 = auth.split_whitespace().nth(2).unwrap();
        let raw = BASE64.decode(b64).unwrap();
        assert!(
            find(&raw, b"user@example.com%admin").is_some(),
            "credential replayed verbatim: {:?}",
            String::from_utf8_lossy(&raw)
        );
        sock.write_all(b"+OK logged in\r\n").await.unwrap();
    })
    .await;

    let mapping = mapping_file("user@example.com\tlegacy\n");
    let toml = format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[capabilities.pop3]
allow_plain_auth_without_tls = true

[routing]
default_destination = "blackhole"
master_user_separators = ["%"]

[destination.legacy]
host = "127.0.0.1"
forwarding = "none"
allow_plaintext_auth = true
[destination.legacy.protocol.pop3]
port = {port}
tls = "plain"

[destination.blackhole]
host = "127.0.0.1"
forwarding = "none"
allow_plaintext_auth = true
[destination.blackhole.protocol.pop3]
port = 1
tls = "plain"

[listener.pop3]
protocol = "pop3"
bind = ["127.0.0.1:0"]
tls = "plain"
"#,
        mapping.path().display(),
    );
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["pop3"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::pop3::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "203.0.113.7:40000".parse().unwrap(),
            "127.0.0.1:110".parse().unwrap(),
        )
        .await;
    });

    let _ = read_line(&mut client).await;
    send(
        &mut client,
        b"USER user@example.com%admin\r\nPASS secret\r\n",
    )
    .await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"+OK logged in").is_some(),
        "master login should route to legacy, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    let _ = backend.await;
    handler.abort();
}

fn imap_config(port: u16, mapping_path: &str) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{mapping_path}"

[capabilities.imap]
allow_plain_auth_without_tls = true

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
forwarding = "xclient"
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = {port}
tls = "plain"

[listener.imap]
protocol = "imap"
bind = ["127.0.0.1:0"]
tls = "plain"
"#
    )
}

#[tokio::test]
async fn imap_id_is_sent_when_advertised() {
    let (port, backend) = dummy_backend(|mut sock| async move {
        sock.write_all(b"* OK [CAPABILITY IMAP4rev1 SASL-IR AUTH=PLAIN ID] ready\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let id = read_crlf(&mut sock, &mut buf).await;
        assert!(id.starts_with("F1 ID ("), "got: {id}");
        assert!(
            id.contains("\"x-originating-ip\" \"203.0.113.8\""),
            "id fields: {id}"
        );
        assert!(id.contains("\"x-proxy-ttl\" \"6\""), "ttl: {id}");
        sock.write_all(b"* ID NIL\r\nF1 OK ID completed\r\n")
            .await
            .unwrap();
        let auth = read_crlf(&mut sock, &mut buf).await;
        assert!(auth.contains("AUTHENTICATE PLAIN "), "got: {auth}");
        sock.write_all(b"a1 OK logged in\r\n").await.unwrap();
    })
    .await;

    let mapping = mapping_file("");
    let toml = imap_config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["imap"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "203.0.113.8:40000".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _ = read_line(&mut client).await;
    let ir = BASE64.encode(b"\0user@example.com\0secret");
    send(
        &mut client,
        format!("a1 AUTHENTICATE PLAIN {ir}\r\n").as_bytes(),
    )
    .await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"a1 OK logged in").is_some(),
        "expected login reply, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    let _ = backend.await;
    handler.abort();
}
