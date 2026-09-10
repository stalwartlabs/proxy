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

#[tokio::test]
async fn pop3_auth_login_replays_as_plain() {
    let (port, backend) = dummy_backend(|sock| backend_expect_auth(sock, "user@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let mut client = spawn_pop3(&ctx).await;

    let _greeting = read_line(&mut client).await;

    send(&mut client, b"CAPA\r\n").await;
    let capa = read_until(&mut client, b".\r\n").await;
    let capa = String::from_utf8_lossy(&capa).into_owned();
    assert!(
        capa.contains("LOGIN"),
        "CAPA must advertise SASL LOGIN, got {capa}"
    );

    send(&mut client, b"AUTH LOGIN\r\n").await;
    let user_prompt = read_until(&mut client, b"\r\n").await;
    assert_eq!(
        String::from_utf8_lossy(&user_prompt).trim_end(),
        "+ VXNlcm5hbWU6"
    );
    send(
        &mut client,
        format!("{}\r\n", BASE64.encode("user@example.com")).as_bytes(),
    )
    .await;

    let pass_prompt = read_until(&mut client, b"\r\n").await;
    assert_eq!(
        String::from_utf8_lossy(&pass_prompt).trim_end(),
        "+ UGFzc3dvcmQ6"
    );
    send(
        &mut client,
        format!("{}\r\nSTAT\r\n", BASE64.encode("secret")).as_bytes(),
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
}

#[tokio::test]
async fn pop3_auth_login_accepts_username_as_initial_response() {
    let (port, backend) =
        dummy_backend(|sock| backend_expect_auth(sock, "alice@example.com")).await;
    let mapping = mapping_file("");
    let toml = config(port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let mut client = spawn_pop3(&ctx).await;

    let _greeting = read_line(&mut client).await;
    send(
        &mut client,
        format!("AUTH LOGIN {}\r\n", BASE64.encode("alice@example.com")).as_bytes(),
    )
    .await;
    let pass_prompt = read_until(&mut client, b"\r\n").await;
    assert_eq!(
        String::from_utf8_lossy(&pass_prompt).trim_end(),
        "+ UGFzc3dvcmQ6"
    );
    send(
        &mut client,
        format!("{}\r\nSTAT\r\n", BASE64.encode("secret")).as_bytes(),
    )
    .await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"+OK logged in").is_some(),
        "expected +OK logged in, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
}

#[tokio::test]
async fn pop3_auth_login_cancelled_by_client() {
    let mapping = mapping_file("");
    let toml = config(1, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let mut client = spawn_pop3(&ctx).await;

    let _greeting = read_line(&mut client).await;
    send(&mut client, b"AUTH LOGIN\r\n").await;
    let _user_prompt = read_until(&mut client, b"\r\n").await;
    send(&mut client, b"*\r\nQUIT\r\n").await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"-ERR authentication cancelled").is_some(),
        "expected a cancel error, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        find(&resp, b"+OK Bye").is_some(),
        "session must survive a cancelled AUTH, got {:?}",
        String::from_utf8_lossy(&resp)
    );
}

#[tokio::test]
async fn pop3_auth_login_refused_without_tls_when_plain_disabled() {
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
    let mut client = spawn_pop3(&ctx).await;

    let _greeting = read_line(&mut client).await;
    send(&mut client, b"CAPA\r\n").await;
    let capa = read_until(&mut client, b".\r\n").await;
    let capa = String::from_utf8_lossy(&capa).into_owned();
    assert!(
        !capa.to_uppercase().contains("LOGIN"),
        "CAPA must omit LOGIN without TLS, got {capa}"
    );

    send(&mut client, b"AUTH LOGIN\r\n").await;
    let resp = read_until(&mut client, b"-ERR").await;
    assert!(
        find(&resp, b"cleartext authentication requires TLS").is_some(),
        "expected a cleartext refusal, got {:?}",
        String::from_utf8_lossy(&resp)
    );
}

#[tokio::test]
async fn pop3_auth_login_rejected_when_not_configured() {
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
sasl = ["PLAIN", "OAUTHBEARER"]

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.pop3]
port = 1
tls = "plain"

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
    send(&mut client, b"AUTH LOGIN\r\n").await;
    let resp = read_until(&mut client, b"-ERR").await;
    assert!(
        find(&resp, b"unsupported mechanism").is_some(),
        "expected an unsupported-mechanism error, got {:?}",
        String::from_utf8_lossy(&resp)
    );
}

fn retry_config(backend_port: u16, mapping_path: &str, max_auth_attempts: u32) -> String {
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
forwarding = "none"
allow_plaintext_auth = true
[destination.legacy.protocol.pop3]
port = {backend_port}
tls = "plain"

[listener.pop3]
protocol = "pop3"
bind = ["127.0.0.1:0"]
tls = "plain"
max_auth_attempts = {max_auth_attempts}
"#
    )
}

async fn rejecting_backend(
    attempts: std::sync::Arc<std::sync::atomic::AtomicUsize>,
) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(unused_addr()).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = sock.set_nodelay(true);
            tokio::spawn(async move {
                if sock.write_all(b"+OK ready\r\n").await.is_err() {
                    return;
                }
                let mut buf = Vec::new();
                let mut scratch = [0u8; 1024];
                while find(&buf, b"\r\n").is_none() {
                    match sock.read(&mut scratch).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&scratch[..n]),
                    }
                }
                let _ = sock.write_all(b"-ERR bad password\r\n").await;
                let mut sink = [0u8; 1024];
                loop {
                    match sock.read(&mut sink).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
    });
    (port, handle)
}

#[tokio::test]
async fn pop3_failed_backend_auth_does_not_hand_the_client_a_raw_bridge() {
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (backend_port, backend) = rejecting_backend(attempts.clone()).await;

    let mapping = mapping_file("user@example.com\tlegacy\n");
    let toml = retry_config(backend_port, &mapping.path().display().to_string(), 10);
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["pop3"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::pop3::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "203.0.113.9:40000".parse().unwrap(),
            "127.0.0.1:110".parse().unwrap(),
        )
        .await;
    });

    let greeting = read_line(&mut client).await;
    assert!(greeting.starts_with("+OK"), "greeting: {greeting}");

    send(&mut client, b"USER user@example.com\r\nPASS wrong\r\n").await;
    let failure = read_until(&mut client, b"-ERR").await;
    assert!(find(&failure, b"-ERR").is_some(), "expected a rejection");

    send(&mut client, b"CAPA\r\n").await;
    let capa = read_until(&mut client, b"\r\n.\r\n").await;
    assert!(
        find(&capa, b"USER").is_some(),
        "the proxy must still be parsing after a failed auth, got {:?}",
        String::from_utf8_lossy(&capa)
    );
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "CAPA must be answered by the proxy, not forwarded to a backend"
    );

    drop(client);
    backend.abort();
    let _ = handler.await;
}

#[tokio::test]
async fn pop3_rejected_auth_closes_the_backend_leg_with_quit() {
    let (backend_port, backend) = dummy_backend(|mut sock| async move {
        sock.write_all(b"+OK ready\r\n").await.unwrap();
        let mut buf = Vec::new();
        let mut scratch = [0u8; 1024];
        while find(&buf, b"\r\n").is_none() {
            match sock.read(&mut scratch).await {
                Ok(0) | Err(_) => return,
                Ok(n) => buf.extend_from_slice(&scratch[..n]),
            }
        }
        let _ = sock.write_all(b"-ERR bad password\r\n").await;
        buf.clear();
        loop {
            match sock.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(n) => buf.extend_from_slice(&scratch[..n]),
            }
        }
        assert!(
            find(&buf, b"QUIT").is_some(),
            "backend leg must be closed with QUIT, saw {:?}",
            String::from_utf8_lossy(&buf)
        );
    })
    .await;

    let mapping = mapping_file("user@example.com\tlegacy\n");
    let toml = retry_config(backend_port, &mapping.path().display().to_string(), 10);
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["pop3"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::pop3::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "203.0.113.9:40003".parse().unwrap(),
            "127.0.0.1:110".parse().unwrap(),
        )
        .await;
    });

    let _ = read_line(&mut client).await;
    send(&mut client, b"USER user@example.com\r\nPASS wrong\r\n").await;
    let _ = read_until(&mut client, b"-ERR").await;

    drop(client);
    backend.await.expect("backend assertion failed");
    let _ = handler.await;
}

#[tokio::test]
async fn pop3_backend_auth_failures_count_toward_max_auth_attempts() {
    let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (backend_port, backend) = rejecting_backend(attempts.clone()).await;

    let mapping = mapping_file("user@example.com\tlegacy\n");
    let toml = retry_config(backend_port, &mapping.path().display().to_string(), 2);
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["pop3"].clone();

    let (mut client, server) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::pop3::handle(
            &ctx2,
            &listener,
            Box::new(server),
            "203.0.113.9:40001".parse().unwrap(),
            "127.0.0.1:110".parse().unwrap(),
        )
        .await;
    });

    let _ = read_line(&mut client).await;
    send(&mut client, b"USER user@example.com\r\nPASS wrong\r\n").await;
    let _ = read_until(&mut client, b"-ERR").await;
    send(&mut client, b"USER user@example.com\r\nPASS wrong\r\n").await;

    let tail = read_to_eof(&mut client).await;
    assert!(
        find(&tail, b"-ERR").is_some(),
        "expected the second rejection, got {:?}",
        String::from_utf8_lossy(&tail)
    );
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "max_auth_attempts must bound the backend connections a client can force"
    );

    backend.abort();
    let _ = handler.await;
}

#[tokio::test]
async fn pop3_retry_after_failed_auth_is_routed_and_registered_for_its_own_account() {
    async fn accepting_backend(
        seen: std::sync::Arc<tokio::sync::Mutex<Vec<u8>>>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind(unused_addr()).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let seen = seen.clone();
                let _ = sock.set_nodelay(true);
                tokio::spawn(async move {
                    if sock.write_all(b"+OK ready\r\n").await.is_err() {
                        return;
                    }
                    let mut buf = Vec::new();
                    let mut scratch = [0u8; 1024];
                    while find(&buf, b"\r\n").is_none() {
                        match sock.read(&mut scratch).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&scratch[..n]),
                        }
                    }
                    seen.lock().await.extend_from_slice(&buf);
                    let _ = sock.write_all(b"+OK logged in\r\n").await;
                    let mut sink = [0u8; 1024];
                    loop {
                        match sock.read(&mut sink).await {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                });
            }
        });
        (port, handle)
    }

    let rejects = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (legacy_port, legacy) = rejecting_backend(rejects.clone()).await;
    let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let (modern_port, modern) = accepting_backend(seen.clone()).await;

    let mapping = mapping_file("alice@example.com\tlegacy\nbob@example.com\tmodern\n");
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
forwarding = "none"
allow_plaintext_auth = true
[destination.legacy.protocol.pop3]
port = {legacy_port}
tls = "plain"

[destination.modern]
host = "127.0.0.1"
forwarding = "none"
allow_plaintext_auth = true
[destination.modern.protocol.pop3]
port = {modern_port}
tls = "plain"

[listener.pop3]
protocol = "pop3"
bind = ["127.0.0.1:0"]
tls = "plain"
max_auth_attempts = 10
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
            "203.0.113.9:40002".parse().unwrap(),
            "127.0.0.1:110".parse().unwrap(),
        )
        .await;
    });

    let _ = read_line(&mut client).await;
    send(&mut client, b"USER alice@example.com\r\nPASS wrong\r\n").await;
    let _ = read_until(&mut client, b"-ERR").await;

    send(&mut client, b"USER bob@example.com\r\nPASS right\r\n").await;
    let ok = read_until(&mut client, b"+OK logged in").await;
    assert!(
        find(&ok, b"+OK logged in").is_some(),
        "second account should authenticate, got {:?}",
        String::from_utf8_lossy(&ok)
    );

    let replayed = seen.lock().await.clone();
    let expected = BASE64.encode("\0bob@example.com\0right");
    assert!(
        find(&replayed, expected.as_bytes()).is_some(),
        "the retry must be re-routed to bob's destination, backend saw {:?}",
        String::from_utf8_lossy(&replayed)
    );
    assert_eq!(
        rejects.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "alice's destination must see only the first attempt"
    );

    assert_eq!(
        ctx.conns.kick(&ctx.router.normalize("alice@example.com")),
        0,
        "the failed account must not hold a registration"
    );
    assert_eq!(
        ctx.conns.kick(&ctx.router.normalize("bob@example.com")),
        1,
        "the account that actually authenticated must be kickable"
    );

    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read(&mut [0u8; 64]),
    )
    .await
    .expect("kick did not disconnect the client in time")
    .unwrap();
    assert_eq!(n, 0, "expected EOF after kick, got {n} bytes");

    legacy.abort();
    modern.abort();
    let _ = handler.await;
}
