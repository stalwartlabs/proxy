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

[capabilities.pop3]
allow_plain_auth_without_tls = true

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
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

async fn backend_expect_auth(mut sock: tokio::net::TcpStream, want_user: &'static str) {
    sock.write_all(b"+OK backend ready\r\n").await.unwrap();

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
    assert!(line.starts_with("AUTH PLAIN "), "got: {line}");
    let b64 = line.split_whitespace().nth(2).unwrap();
    let raw = BASE64.decode(b64).unwrap();
    assert!(
        find(&raw, want_user.as_bytes()).is_some(),
        "decoded IR {:?} should contain {want_user}",
        String::from_utf8_lossy(&raw)
    );
    sock.write_all(b"+OK logged in\r\n").await.unwrap();

    let mut rest = buf[line_end + 2..].to_vec();
    loop {
        if find(&rest, b"STAT").is_some() {
            break;
        }
        let n = sock.read(&mut scratch).await.unwrap();
        if n == 0 {
            return;
        }
        rest.extend_from_slice(&scratch[..n]);
    }
    sock.write_all(b"+OK 0 0\r\n").await.unwrap();
}

#[tokio::test]
async fn pop3_user_pass_routes_replays_and_bridges() {
    let (port, backend) = dummy_backend(|sock| backend_expect_auth(sock, "user@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["pop3"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::pop3::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40000".parse().unwrap(),
            "127.0.0.1:110".parse().unwrap(),
        )
        .await;
    });

    let greeting = read_line(&mut client).await;
    assert!(greeting.starts_with("+OK"), "greeting: {greeting}");

    send(
        &mut client,
        b"USER user@example.com\r\nPASS secret\r\nSTAT\r\n",
    )
    .await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"+OK logged in").is_some(),
        "expected +OK logged in, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        find(&resp, b"+OK 0 0").is_some(),
        "expected bridged STAT reply, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn pop3_auth_plain_with_ir() {
    let (port, backend) =
        dummy_backend(|sock| backend_expect_auth(sock, "alice@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["pop3"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::pop3::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40001".parse().unwrap(),
            "127.0.0.1:110".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    let ir = BASE64.encode(b"\0alice@example.com\0secret");
    send(
        &mut client,
        format!("AUTH PLAIN {ir}\r\nSTAT\r\n").as_bytes(),
    )
    .await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"+OK logged in").is_some(),
        "expected +OK logged in, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
    handler.abort();
}

fn count(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return 0;
    }
    haystack
        .windows(needle.len())
        .filter(|w| *w == needle)
        .count()
}

async fn spawn_pop3(ctx: &std::sync::Arc<crate::proto::common::Ctx>) -> tokio::net::TcpStream {
    let listener = ctx.config.listener["pop3"].clone();
    let (client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    tokio::spawn(async move {
        let _ = crate::proto::pop3::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40010".parse().unwrap(),
            "127.0.0.1:110".parse().unwrap(),
        )
        .await;
    });
    client
}

#[tokio::test]
async fn pop3_bad_inline_ir_does_not_loop() {
    let mapping = mapping_file("");
    let toml = config(1, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let mut client = spawn_pop3(&ctx).await;

    let _greeting = read_line(&mut client).await;
    let ir = BASE64.encode(b"nonulhere");
    send(
        &mut client,
        format!("AUTH PLAIN {ir}\r\nQUIT\r\n").as_bytes(),
    )
    .await;

    let resp = read_to_eof(&mut client).await;
    assert_eq!(
        count(&resp, b"-ERR"),
        1,
        "one bad AUTH must produce exactly one -ERR, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        find(&resp, b"+OK Bye").is_some(),
        "the pipelined QUIT after a bad AUTH must still be processed, got {:?}",
        String::from_utf8_lossy(&resp)
    );
}

#[tokio::test]
async fn pop3_bare_pass_is_rejected() {
    let mapping = mapping_file("");
    let toml = config(1, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let mut client = spawn_pop3(&ctx).await;

    let _greeting = read_line(&mut client).await;
    send(&mut client, b"PASS secret\r\n").await;
    let resp = read_until(&mut client, b"\r\n").await;
    assert!(
        find(&resp, b"-ERR").is_some(),
        "bare PASS must be rejected, got {:?}",
        String::from_utf8_lossy(&resp)
    );
}

#[tokio::test]
async fn pop3_auth_continuation_when_ir_omitted() {
    let (port, backend) =
        dummy_backend(|sock| backend_expect_auth(sock, "carol@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let mut client = spawn_pop3(&ctx).await;

    let _greeting = read_line(&mut client).await;
    send(&mut client, b"AUTH PLAIN\r\n").await;
    let cont = read_until(&mut client, b"\r\n").await;
    assert!(
        cont.starts_with(b"+ "),
        "expected continuation prompt, got {:?}",
        String::from_utf8_lossy(&cont)
    );

    let ir = BASE64.encode(b"\0carol@example.com\0secret");
    send(&mut client, format!("{ir}\r\nSTAT\r\n").as_bytes()).await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"+OK logged in").is_some(),
        "continuation auth should succeed, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
}

#[tokio::test]
async fn pop3_aborts_when_backend_does_not_advertise_stls() {
    async fn backend_no_stls(mut sock: tokio::net::TcpStream) {
        sock.write_all(b"+OK backend ready\r\n").await.unwrap();
        let mut scratch = [0u8; 1024];
        let _ = sock.read(&mut scratch).await;
        sock.write_all(b"+OK capa\r\nTOP\r\nUIDL\r\n.\r\n")
            .await
            .unwrap();
        let _ = sock.read(&mut scratch).await;
    }

    let (port, backend) = dummy_backend(backend_no_stls).await;
    let mapping = mapping_file("");
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
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
tls_server_name = "backend.example.com"
proxy_protocol = false
[destination.legacy.protocol.pop3]
port = {port}
tls = "starttls"

[listener.pop3]
protocol = "pop3"
bind = ["127.0.0.1:0"]
tls = "plain"
"#,
        mapping.path().display()
    );
    let ctx = make_ctx(&toml).await;
    let mut client = spawn_pop3(&ctx).await;

    let _greeting = read_line(&mut client).await;
    send(&mut client, b"USER user@example.com\r\nPASS secret\r\n").await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"-ERR backend unavailable").is_some(),
        "credentials must not egress to a backend that won't do STLS; got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
}

#[tokio::test]
async fn pop3_user_rejected_without_tls_when_plain_disabled() {
    let mapping = mapping_file("");
    let toml = format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[capabilities.pop3]
allow_plain_auth_without_tls = false

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
tls_server_name = "backend.example.com"
[destination.legacy.protocol.pop3]
port = 1
tls = "implicit"

[listener.pop3]
protocol = "pop3"
bind = ["127.0.0.1:0"]
tls = "plain"
"#,
        mapping.path().display()
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
            "127.0.0.1:40002".parse().unwrap(),
            "127.0.0.1:110".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;

    send(&mut client, b"CAPA\r\n").await;
    let capa = read_until(&mut client, b".\r\n").await;
    let capa_str = String::from_utf8_lossy(&capa);
    assert!(
        !capa_str.contains("USER\r\n"),
        "CAPA should omit USER, got {capa_str}"
    );
    assert!(
        !capa_str.to_uppercase().contains("PLAIN"),
        "CAPA should omit PLAIN, got {capa_str}"
    );

    send(&mut client, b"USER user@example.com\r\n").await;
    let resp = read_until(&mut client, b"-ERR").await;
    assert!(
        find(&resp, b"-ERR").is_some(),
        "expected -ERR, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    handler.abort();
}
