/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use encodify::base64::STANDARD as BASE64;
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
    sock.write_all(b"* OK [CAPABILITY IMAP4rev2 SASL-IR] backend ready\r\n")
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

#[tokio::test]
async fn imap_authenticate_login_replays_as_plain() {
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
            "127.0.0.1:40060".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let greeting = read_line(&mut client).await;
    assert!(
        greeting.contains("AUTH=LOGIN"),
        "capability must advertise AUTH=LOGIN, got {greeting}"
    );

    send(&mut client, b"a1 AUTHENTICATE LOGIN\r\n").await;
    let user_prompt = read_line(&mut client).await;
    assert_eq!(user_prompt.trim_end(), "+ VXNlcm5hbWU6", "{user_prompt}");
    send(
        &mut client,
        format!("{}\r\n", BASE64.encode("user@example.com")).as_bytes(),
    )
    .await;

    let pass_prompt = read_line(&mut client).await;
    assert_eq!(pass_prompt.trim_end(), "+ UGFzc3dvcmQ6", "{pass_prompt}");
    send(
        &mut client,
        format!("{}\r\n", BASE64.encode("secret")).as_bytes(),
    )
    .await;

    send(&mut client, b"a2 NOOP\r\n").await;
    let resp = read_to_eof(&mut client).await;
    let resp = String::from_utf8_lossy(&resp).into_owned();
    assert!(resp.contains("a1 OK"), "expected a1 OK, got {resp}");
    assert!(resp.contains("a2 OK"), "expected bridged a2 OK, got {resp}");

    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn imap_authenticate_login_accepts_username_as_initial_response() {
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
            "127.0.0.1:40061".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    send(
        &mut client,
        format!(
            "a1 AUTHENTICATE LOGIN {}\r\n",
            BASE64.encode("alice@example.com")
        )
        .as_bytes(),
    )
    .await;
    let pass_prompt = read_line(&mut client).await;
    assert_eq!(pass_prompt.trim_end(), "+ UGFzc3dvcmQ6", "{pass_prompt}");
    send(
        &mut client,
        format!("{}\r\n", BASE64.encode("secret")).as_bytes(),
    )
    .await;
    send(&mut client, b"a2 NOOP\r\n").await;

    let resp = read_until(&mut client, b"a1 OK").await;
    assert!(find(&resp, b"a1 OK").is_some());
    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn imap_authenticate_login_cancelled_by_client() {
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
            "127.0.0.1:40062".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    send(&mut client, b"a1 AUTHENTICATE LOGIN\r\n").await;
    let _user_prompt = read_line(&mut client).await;
    send(&mut client, b"*\r\n").await;

    let resp = read_until(&mut client, b"a1 NO").await;
    assert!(
        find(&resp, b"a1 NO").is_some(),
        "expected tagged NO, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    send(&mut client, b"a2 CAPABILITY\r\n").await;
    let resp = read_until(&mut client, b"a2 OK").await;
    assert!(
        find(&resp, b"a2 OK").is_some(),
        "session must survive a cancelled AUTHENTICATE, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    handler.abort();
}

#[tokio::test]
async fn imap_authenticate_login_refused_without_tls_when_plain_disabled() {
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
            "127.0.0.1:40063".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let greeting = read_line(&mut client).await;
    assert!(
        !greeting.contains("AUTH=LOGIN"),
        "AUTH=LOGIN must not be advertised without TLS, got {greeting}"
    );

    send(&mut client, b"a1 AUTHENTICATE LOGIN\r\n").await;
    let resp = read_until(&mut client, b"a1 NO").await;
    assert!(
        find(&resp, b"PRIVACYREQUIRED").is_some(),
        "expected PRIVACYREQUIRED, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    handler.abort();
}

const EXCHANGE_GREETING: &[u8] =
    b"* OK [CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN AUTH=NTLM AUTH=GSSAPI UIDPLUS MOVE ID \
      CHILDREN IDLE NAMESPACE LITERAL+] backend ready\r\n";

async fn backend_without_sasl_ir(mut sock: tokio::net::TcpStream, want_user: &'static str) {
    sock.write_all(EXCHANGE_GREETING).await.unwrap();

    let command = read_line(&mut sock).await;
    assert_eq!(
        command, "a1 AUTHENTICATE PLAIN",
        "backend without SASL-IR must not receive an inline initial response"
    );
    sock.write_all(b"+ \r\n").await.unwrap();

    let response = read_line(&mut sock).await;
    let raw = BASE64.decode(response.trim()).unwrap();
    assert_eq!(
        raw,
        format!("\0{want_user}\0secret").into_bytes(),
        "deferred initial response should carry the credentials"
    );
    sock.write_all(b"a1 OK [CAPABILITY IMAP4rev1] authenticated\r\n")
        .await
        .unwrap();

    let _ = read_until(&mut sock, b"NOOP").await;
    sock.write_all(b"a2 OK NOOP done\r\n").await.unwrap();
}

async fn run_against_backend_without_sasl_ir(
    ctx: std::sync::Arc<crate::proto::common::Ctx>,
    first: &[u8],
) -> Vec<u8> {
    let listener = ctx.config.listener["imap"].clone();
    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "127.0.0.1:40010".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    send(&mut client, first).await;
    let resp = read_until(&mut client, b"a1 OK").await;
    send(&mut client, b"a2 NOOP\r\n").await;
    let mut resp = resp;
    resp.extend_from_slice(&read_until(&mut client, b"a2 OK").await);
    handler.abort();
    resp
}

#[tokio::test]
async fn imap_defers_initial_response_when_backend_lacks_sasl_ir() {
    let (port, backend) =
        dummy_backend(|sock| backend_without_sasl_ir(sock, "alice@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;

    let ir = BASE64.encode(b"\0alice@example.com\0secret");
    let resp = run_against_backend_without_sasl_ir(
        ctx,
        format!("a1 AUTHENTICATE PLAIN {ir}\r\n").as_bytes(),
    )
    .await;

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
}

#[tokio::test]
async fn imap_login_defers_initial_response_when_backend_lacks_sasl_ir() {
    let (port, backend) =
        dummy_backend(|sock| backend_without_sasl_ir(sock, "bob@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;

    let resp =
        run_against_backend_without_sasl_ir(ctx, b"a1 LOGIN bob@example.com secret\r\n").await;

    assert!(
        find(&resp, b"a1 OK").is_some(),
        "expected a1 OK, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
}

#[tokio::test]
async fn imap_keeps_inline_initial_response_when_backend_advertises_sasl_ir() {
    let (port, backend) = dummy_backend(|mut sock: tokio::net::TcpStream| async move {
        sock.write_all(b"* OK [CAPABILITY IMAP4rev2 SASL-IR] backend ready\r\n")
            .await
            .unwrap();
        let command = read_line(&mut sock).await;
        let ir = BASE64.encode(b"\0dave@example.com\0secret");
        assert_eq!(command, format!("a1 AUTHENTICATE PLAIN {ir}"));
        sock.write_all(b"a1 OK authenticated\r\n").await.unwrap();
        let _ = read_until(&mut sock, b"NOOP").await;
        sock.write_all(b"a2 OK NOOP done\r\n").await.unwrap();
    })
    .await;
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
            "127.0.0.1:40011".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    let ir = BASE64.encode(b"\0dave@example.com\0secret");
    send(
        &mut client,
        format!("a1 AUTHENTICATE PLAIN {ir}\r\n").as_bytes(),
    )
    .await;
    let resp = read_until(&mut client, b"a1 OK").await;
    assert!(find(&resp, b"a1 OK").is_some());
    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn imap_pipelined_command_after_failed_auth_is_parsed_not_bridged() {
    let (port, backend) = dummy_backend(|mut sock| async move {
        sock.write_all(b"* OK [CAPABILITY IMAP4rev2 SASL-IR] backend ready\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        let mut scratch = [0u8; 1024];
        while find(&buf, b"AUTHENTICATE").is_none() || find(&buf, b"\r\n").is_none() {
            match sock.read(&mut scratch).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&scratch[..n]),
            }
        }
        let _ = sock
            .write_all(b"a1 NO [AUTHENTICATIONFAILED] nope\r\n")
            .await;
        let mut sink = [0u8; 1024];
        loop {
            match sock.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    assert!(
                        find(&sink[..n], b"CAPABILITY").is_none(),
                        "pipelined client bytes must not reach the backend after a failed auth"
                    );
                }
            }
        }
    })
    .await;

    let mapping = mapping_file("user@example.com\tlegacy\n");
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
            "203.0.113.9:40010".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _ = read_line(&mut client).await;
    send(
        &mut client,
        b"a1 LOGIN user@example.com wrong\r\na2 CAPABILITY\r\n",
    )
    .await;

    let seen = read_until(&mut client, b"a2 OK").await;
    assert!(
        find(&seen, b"a1 NO").is_some(),
        "expected the backend rejection, got {:?}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        find(&seen, b"a2 OK CAPABILITY completed").is_some(),
        "the pipelined command must be answered by the proxy, got {:?}",
        String::from_utf8_lossy(&seen)
    );

    drop(client);
    let _ = backend.await;
    let _ = handler.await;
}

async fn preauth_only_ctx() -> (
    std::sync::Arc<crate::proto::common::Ctx>,
    tokio::task::JoinHandle<()>,
) {
    let (port, backend) = dummy_backend(|_sock| async move {}).await;
    let mapping = mapping_file("user@example.com\tlegacy\n");
    let toml = config(port, &mapping.path().display().to_string());
    (make_ctx(&toml).await, backend)
}

#[tokio::test]
async fn imap_rejected_sasl_response_is_not_reparsed_as_a_command() {
    let (ctx, backend) = preauth_only_ctx().await;
    let listener = ctx.config.listener["imap"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "203.0.113.9:40011".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _ = read_line(&mut client).await;
    send(
        &mut client,
        b"a1 AUTHENTICATE PLAIN\r\n@@@\r\na2 CAPABILITY\r\n",
    )
    .await;

    let seen = read_until(&mut client, b"a2 OK").await;
    assert!(
        find(&seen, b"a1 NO").is_some(),
        "expected the SASL response to be rejected, got {:?}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        find(&seen, b"* BAD").is_none(),
        "the rejected SASL response must not be re-parsed as a command, got {:?}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        find(&seen, b"a2 OK CAPABILITY completed").is_some(),
        "the pipelined command must still be answered, got {:?}",
        String::from_utf8_lossy(&seen)
    );

    drop(client);
    backend.abort();
    let _ = handler.await;
}

#[tokio::test]
async fn imap_command_pipelined_behind_a_rejected_sasl_response_is_not_lost() {
    let (ctx, backend) = preauth_only_ctx().await;
    let listener = ctx.config.listener["imap"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "203.0.113.9:40012".parse().unwrap(),
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _ = read_line(&mut client).await;
    send(&mut client, b"a1 AUTHENTICATE PLAIN\r\n").await;
    let challenge = read_until(&mut client, b"+ ").await;
    assert!(find(&challenge, b"+ ").is_some(), "expected a continuation");

    send(&mut client, b"@@@\r\na2 CAPABILITY\r\n").await;
    let seen = read_until(&mut client, b"a2 OK").await;
    assert!(
        find(&seen, b"a1 NO").is_some(),
        "expected the SASL response to be rejected, got {:?}",
        String::from_utf8_lossy(&seen)
    );
    assert!(
        find(&seen, b"a2 OK CAPABILITY completed").is_some(),
        "the command behind the rejected response must not be dropped, got {:?}",
        String::from_utf8_lossy(&seen)
    );

    drop(client);
    backend.abort();
    let _ = handler.await;
}
