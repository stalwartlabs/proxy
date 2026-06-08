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

[capabilities.imap]
allow_plain_auth_without_tls = true

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = {port}
tls = "plain"

[destination.primary]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.primary.protocol.imap]
port = {port}
tls = "plain"

[listener.imap]
protocol = "imap"
bind = ["127.0.0.1:0"]
tls = "plain"
"#
    )
}

async fn backend_expect_auth(sock: tokio::net::TcpStream, want_user: &'static str) {
    backend_expect_mech(sock, "PLAIN", want_user).await
}

async fn backend_expect_mech(
    mut sock: tokio::net::TcpStream,
    mech: &'static str,
    want_user: &'static str,
) {
    sock.write_all(b"* OK [CAPABILITY IMAP4rev2] backend ready\r\n")
        .await
        .unwrap();

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
    let tag = line.split(' ').next().unwrap().to_string();
    assert!(
        line.contains(&format!("AUTHENTICATE {mech}")),
        "got: {line}"
    );
    let b64 = line.split_whitespace().nth(3).unwrap();
    let raw = BASE64.decode(b64).unwrap();
    assert!(
        find(&raw, want_user.as_bytes()).is_some(),
        "decoded IR {:?} should contain {want_user}",
        String::from_utf8_lossy(&raw)
    );
    sock.write_all(format!("{tag} OK [CAPABILITY IMAP4rev2] authenticated\r\n").as_bytes())
        .await
        .unwrap();

    let mut rest = buf[line_end + 2..].to_vec();
    loop {
        if find(&rest, b"NOOP").is_some() {
            break;
        }
        let n = sock.read(&mut scratch).await.unwrap();
        if n == 0 {
            return;
        }
        rest.extend_from_slice(&scratch[..n]);
    }
    sock.write_all(b"a2 OK NOOP done\r\n").await.unwrap();
}

#[tokio::test]
async fn imap_login_routes_replays_and_bridges() {
    let (port, backend) = dummy_backend(|sock| backend_expect_auth(sock, "user@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["imap"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40000".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let greeting = read_line(&mut client).await;
    assert!(
        greeting.starts_with("* OK [CAPABILITY"),
        "greeting: {greeting}"
    );

    send(
        &mut client,
        b"a1 LOGIN user@example.com secret\r\na2 NOOP\r\n",
    )
    .await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"a1 OK").is_some(),
        "expected a1 OK, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        find(&resp, b"a2 OK").is_some(),
        "expected bridged a2 OK, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn imap_authenticate_plain_with_ir() {
    let (port, backend) =
        dummy_backend(|sock| backend_expect_auth(sock, "alice@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["imap"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40001".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    let ir = BASE64.encode(b"\0alice@example.com\0secret");
    send(
        &mut client,
        format!("a1 AUTHENTICATE PLAIN {ir}\r\na2 NOOP\r\n").as_bytes(),
    )
    .await;

    let resp = read_until(&mut client, b"a1 OK").await;
    assert!(find(&resp, b"a1 OK").is_some());
    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn imap_authenticate_oauthbearer_extracts_identifier() {
    let (port, backend) =
        dummy_backend(|sock| backend_expect_mech(sock, "OAUTHBEARER", "carol@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["imap"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40003".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    let frame = "n,a=carol@example.com,\x01auth=Bearer token-xyz\x01\x01";
    let ir = BASE64.encode(frame.as_bytes());
    send(
        &mut client,
        format!("a1 AUTHENTICATE OAUTHBEARER {ir}\r\na2 NOOP\r\n").as_bytes(),
    )
    .await;

    let resp = read_to_eof(&mut client).await;
    assert!(find(&resp, b"a1 OK").is_some());
    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn imap_backend_unavailable_returns_no() {
    let mapping = mapping_file("");
    let toml = config(1, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["imap"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40004".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    send(&mut client, b"a1 LOGIN user@example.com secret\r\n").await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"a1 NO [UNAVAILABLE]").is_some(),
        "expected backend-unavailable NO, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    handler.abort();
}

#[tokio::test]
async fn imap_login_rejected_without_tls_when_plain_disabled() {
    let mapping = mapping_file("");
    let toml = format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[capabilities.imap]
allow_plain_auth_without_tls = false

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
tls_server_name = "backend.example.com"
[destination.legacy.protocol.imap]
port = 1
tls = "implicit"

[listener.imap]
protocol = "imap"
bind = ["127.0.0.1:0"]
tls = "starttls"
"#,
        mapping.path().display()
    );
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["imap"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40002".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let greeting = read_line(&mut client).await;
    assert!(greeting.contains("LOGINDISABLED"), "greeting: {greeting}");
    assert!(greeting.contains("STARTTLS"), "greeting: {greeting}");

    send(&mut client, b"a1 LOGIN user@example.com secret\r\n").await;
    let resp = read_until(&mut client, b"a1 NO").await;
    assert!(
        find(&resp, b"PRIVACYREQUIRED").is_some(),
        "expected PRIVACYREQUIRED, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    handler.abort();
}

#[tokio::test]
async fn imap_malformed_credentials_rejected_without_closing() {
    let mapping = mapping_file("");
    let toml = config(1, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["imap"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40050".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    let ir = BASE64.encode(b"nonulhere");
    send(
        &mut client,
        format!("a1 AUTHENTICATE PLAIN {ir}\r\na2 CAPABILITY\r\n").as_bytes(),
    )
    .await;

    let resp = read_until(&mut client, b"a2 OK").await;
    let s = String::from_utf8_lossy(&resp);
    assert!(
        s.contains("a1 NO"),
        "malformed credentials must get a tagged NO, got {s}"
    );
    assert!(
        s.contains("a2 OK"),
        "connection must stay usable after a rejected AUTH, got {s}"
    );
    handler.abort();
}

#[tokio::test]
async fn imap_starttls_discards_buffered_plaintext() {
    let mapping = mapping_file("");
    let toml = format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 1
tls = "plain"

[listener.imap]
protocol = "imap"
bind = ["127.0.0.1:0"]
tls = "starttls"
"#,
        mapping.path().display()
    );
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["imap"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40070".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let greeting = read_line(&mut client).await;
    assert!(
        greeting.contains("STARTTLS"),
        "starttls listener must advertise STARTTLS, got {greeting}"
    );

    send(&mut client, b"a STARTTLS\r\nz NOOP\r\n").await;
    let _ = read_until(&mut client, b"a OK").await;

    let mut tls = tls_connect_client(client).await;
    tls.write_all(b"b CAPABILITY\r\n").await.unwrap();
    tls.flush().await.unwrap();

    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];
    loop {
        if find(&buf, b"b OK").is_some() {
            break;
        }
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), tls.read(&mut scratch))
            .await
            .expect("read timed out")
            .unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&scratch[..n]);
    }

    assert!(
        find(&buf, b"b OK").is_some(),
        "CAPABILITY over TLS should succeed, got {:?}",
        String::from_utf8_lossy(&buf)
    );
    assert!(
        find(&buf, b"z OK").is_none() && find(&buf, b"z BAD").is_none(),
        "injected pre-TLS command must never be processed, got {:?}",
        String::from_utf8_lossy(&buf)
    );
    handler.abort();
}
