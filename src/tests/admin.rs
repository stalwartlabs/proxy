/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::Ordering;

use tokio::net::TcpListener;

use super::harness::*;

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123";

fn config(mapping_path: &str, lockout_threshold: u32) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{mapping_path}"

[routing]
default_destination = "legacy"

[destination.legacy]
host = "mail.legacy.example.com"
[destination.legacy.protocol.imap]
port = 993
tls = "implicit"

[admin]
bind = "127.0.0.1:0"
tls = "implicit"
bearer_token = "{TOKEN}"
min_token_len = 32
lockout_threshold = {lockout_threshold}
lockout_duration = "5m"
"#
    )
}

async fn start_admin(
    toml: &str,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<crate::proto::common::Ctx>,
) {
    let ctx = make_ctx(toml).await;
    let listener = TcpListener::bind(unused_addr()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ctx2 = ctx.clone();
    let config = ctx.config.clone();
    tokio::spawn(async move {
        let shared = std::sync::Arc::new(arc_swap::ArcSwap::new(ctx2));
        let _ = crate::admin::serve(shared, config, None, listener).await;
    });
    (addr, ctx)
}

#[tokio::test]
async fn admin_auth_and_routing() {
    let mapping = mapping_file("user@example.com\tlegacy\n");
    let toml = config(&mapping.path().display().to_string(), 100);
    let (addr, ctx) = start_admin(&toml).await;

    let (status, _) = admin_request(addr, "POST", "/cache/invalidate", Some(TOKEN)).await;
    assert_eq!(status, 200);

    let (status, _) = admin_request(addr, "POST", "/cache/invalidate", None).await;
    assert_eq!(status, 401);

    let (status, _) = admin_request(
        addr,
        "POST",
        "/cache/invalidate",
        Some("wrong-but-long-enough-token-aaaaaaaa"),
    )
    .await;
    assert_eq!(status, 401);

    let (status, _) = admin_request(addr, "GET", "/cache/invalidate", Some(TOKEN)).await;
    assert_eq!(status, 405);

    let (status, _) = admin_request(addr, "POST", "/nope", Some(TOKEN)).await;
    assert_eq!(status, 404);

    let (status, _) = admin_request(addr, "POST", "/mappings/reload", Some(TOKEN)).await;
    assert_eq!(status, 200);

    let _ = ctx;
}

#[tokio::test]
async fn admin_cache_invalidate_clears_entry() {
    let mapping = mapping_file("user@example.com\tlegacy\n");
    let toml = config(&mapping.path().display().to_string(), 100);
    let (addr, ctx) = start_admin(&toml).await;

    ctx.router.resolve(Some("user@example.com")).await;
    let misses_before = ctx.router.stats.misses.load(Ordering::Relaxed);
    ctx.router.resolve(Some("user@example.com")).await;
    assert_eq!(
        ctx.router.stats.misses.load(Ordering::Relaxed),
        misses_before
    );

    let (status, _) = admin_request(
        addr,
        "POST",
        "/cache/invalidate?identifier=user@example.com",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);

    ctx.router.resolve(Some("user@example.com")).await;
    assert_eq!(
        ctx.router.stats.misses.load(Ordering::Relaxed),
        misses_before + 1
    );
}

#[tokio::test]
async fn admin_lockout_after_repeated_failures() {
    let mapping = mapping_file("");
    let toml = config(&mapping.path().display().to_string(), 3);
    let (addr, _ctx) = start_admin(&toml).await;

    let bad = "this-is-a-wrong-token-but-long-enough-xx";
    for _ in 0..3 {
        let (status, _) = admin_request(addr, "POST", "/cache/invalidate", Some(bad)).await;
        assert_eq!(status, 401);
    }
    let (status, _) = admin_request(addr, "POST", "/cache/invalidate", Some(TOKEN)).await;
    assert_eq!(status, 429);
}

fn kick_config(backend_port: u16, mapping_path: &str) -> String {
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

[admin]
bind = "127.0.0.1:0"
tls = "implicit"
bearer_token = "{TOKEN}"
min_token_len = 32
lockout_threshold = 100
lockout_duration = "5m"
"#
    )
}

#[tokio::test]
async fn admin_kick_disconnects_live_session() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (backend_port, backend) = dummy_backend(|mut sock| async move {
        sock.write_all(b"+OK ready\r\n").await.unwrap();
        let mut buf = Vec::new();
        let mut scratch = [0u8; 1024];
        while find(&buf, b"AUTH PLAIN").is_none() || find(&buf, b"\r\n").is_none() {
            let n = sock.read(&mut scratch).await.unwrap();
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&scratch[..n]);
        }
        sock.write_all(b"+OK logged in\r\n").await.unwrap();
        loop {
            match sock.read(&mut scratch).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await;

    let mapping = mapping_file("user@example.com\tlegacy\n");
    let toml = kick_config(backend_port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;

    let admin_listener = TcpListener::bind(unused_addr()).await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    let admin_ctx = ctx.clone();
    let admin_config = ctx.config.clone();
    tokio::spawn(async move {
        let shared = std::sync::Arc::new(arc_swap::ArcSwap::new(admin_ctx));
        let _ = crate::admin::serve(shared, admin_config, None, admin_listener).await;
    });

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
    send(&mut client, b"USER user@example.com\r\nPASS secret\r\n").await;

    let mut seen = Vec::new();
    let mut scratch = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut scratch))
            .await
            .expect("login reply timed out")
            .unwrap();
        assert!(n > 0, "client closed before login");
        seen.extend_from_slice(&scratch[..n]);
        if find(&seen, b"+OK logged in").is_some() {
            break;
        }
    }

    let (status, body) = admin_request(
        admin_addr,
        "POST",
        "/connections/kick?identifier=user@example.com",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("kicked 1"), "kick body: {body}");

    let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut scratch))
        .await
        .expect("kick did not disconnect the client in time")
        .unwrap();
    assert_eq!(n, 0, "expected EOF after kick, got {n} bytes");

    let _ = backend.await;
    let _ = handler.await;
}

#[tokio::test]
async fn admin_delay_holds_new_login() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (backend_port, backend) = dummy_backend(|mut sock| async move {
        sock.write_all(b"+OK ready\r\n").await.unwrap();
        let mut buf = Vec::new();
        let mut scratch = [0u8; 1024];
        while find(&buf, b"AUTH PLAIN").is_none() || find(&buf, b"\r\n").is_none() {
            let n = sock.read(&mut scratch).await.unwrap();
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&scratch[..n]);
        }
        sock.write_all(b"+OK logged in\r\n").await.unwrap();
        let _ = sock.read(&mut scratch).await;
    })
    .await;

    let mapping = mapping_file("user@example.com\tlegacy\n");
    let toml = kick_config(backend_port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;

    let admin_listener = TcpListener::bind(unused_addr()).await.unwrap();
    let admin_addr = admin_listener.local_addr().unwrap();
    let admin_ctx = ctx.clone();
    let admin_config = ctx.config.clone();
    tokio::spawn(async move {
        let shared = std::sync::Arc::new(arc_swap::ArcSwap::new(admin_ctx));
        let _ = crate::admin::serve(shared, admin_config, None, admin_listener).await;
    });

    let (status, _) = admin_request(
        admin_addr,
        "POST",
        "/connections/delay?identifier=user@example.com&seconds=2",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);

    let (status, _) = admin_request(
        admin_addr,
        "POST",
        "/connections/delay?identifier=user@example.com",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = admin_request(
        admin_addr,
        "POST",
        "/connections/delay?identifier=user@example.com&seconds=abc",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 400);

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

    let started = std::time::Instant::now();
    send(&mut client, b"USER user@example.com\r\nPASS secret\r\n").await;

    let mut seen = Vec::new();
    let mut scratch = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.read(&mut scratch),
        )
        .await
        .expect("delayed login reply timed out")
        .unwrap();
        assert!(n > 0, "client closed before login");
        seen.extend_from_slice(&scratch[..n]);
        if find(&seen, b"+OK logged in").is_some() {
            break;
        }
    }
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(1500),
        "login should be held for ~2s, but completed in {:?}",
        started.elapsed()
    );

    drop(client);
    let _ = backend.await;
    let _ = handler.await;
}

#[tokio::test]
async fn admin_kick_unknown_identifier_reports_zero() {
    let mapping = mapping_file("user@example.com\tlegacy\n");
    let toml = config(&mapping.path().display().to_string(), 100);
    let (addr, _ctx) = start_admin(&toml).await;

    let (status, body) = admin_request(
        addr,
        "POST",
        "/connections/kick?identifier=nobody@example.com",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("kicked 0"), "body: {body}");

    let (status, _) = admin_request(addr, "POST", "/connections/kick", Some(TOKEN)).await;
    assert_eq!(status, 400);
}

#[tokio::test]
async fn admin_rejects_plaintext_connection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mapping = mapping_file("");
    let toml = config(&mapping.path().display().to_string(), 100);
    let (addr, _ctx) = start_admin(&toml).await;

    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST /cache/invalidate HTTP/1.1\r\nHost: admin\r\nAuthorization: Bearer {TOKEN}\r\nConnection: close\r\n\r\n"
    );
    let _ = tcp.write_all(req.as_bytes()).await;
    let _ = tcp.flush().await;

    let mut buf = Vec::new();
    let _ =
        tokio::time::timeout(std::time::Duration::from_secs(3), tcp.read_to_end(&mut buf)).await;
    assert!(
        find(&buf, b"200").is_none(),
        "a plaintext admin request must not be served, got {:?}",
        String::from_utf8_lossy(&buf)
    );
}

fn two_dest_config(mapping_path: &str, default_dest: &str) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{mapping_path}"

[routing]
default_destination = "{default_dest}"

[destination.legacy]
host = "mail.legacy.example.com"
[destination.legacy.protocol.imap]
port = 993
tls = "implicit"

[destination.secondary]
host = "mail.secondary.example.com"
[destination.secondary.protocol.imap]
port = 993
tls = "implicit"

[admin]
bind = "127.0.0.1:0"
tls = "implicit"
bearer_token = "{TOKEN}"
min_token_len = 32
lockout_threshold = 100
lockout_duration = "5m"
"#
    )
}

#[tokio::test]
async fn admin_mapping_crud_and_reads() {
    let mapping = mapping_file("");
    let toml = two_dest_config(&mapping.path().display().to_string(), "legacy");
    let (addr, ctx) = start_admin(&toml).await;

    let (status, _) = admin_request(addr, "GET", "/healthz", None).await;
    assert_eq!(status, 200);
    let (status, _) = admin_request(addr, "GET", "/healthz", Some(TOKEN)).await;
    assert_eq!(status, 200);

    let (status, body) = admin_request(addr, "GET", "/stats", Some(TOKEN)).await;
    assert_eq!(status, 200);
    assert!(body.contains("cache_hits"), "body: {body}");

    let (status, body) = admin_request(addr, "GET", "/destinations", Some(TOKEN)).await;
    assert_eq!(status, 200);
    assert!(
        body.contains("legacy") && body.contains("secondary"),
        "body: {body}"
    );

    let (status, _) = admin_request(
        addr,
        "PUT",
        "/mappings?identifier=alice@example.com&destination=secondary",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        &*ctx.router.resolve(Some("alice@example.com")).await,
        "secondary"
    );
    let on_disk = std::fs::read_to_string(mapping.path()).unwrap();
    assert!(
        on_disk.contains("alice@example.com\tsecondary"),
        "{on_disk}"
    );

    let (status, body) = admin_request(
        addr,
        "GET",
        "/mappings?identifier=alice@example.com",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.contains("\"destination\":\"secondary\""),
        "body: {body}"
    );
    assert!(body.contains("\"routed_to_default\":false"), "body: {body}");

    let (status, _) = admin_request(
        addr,
        "PUT",
        "/mappings?identifier=bob@example.com&destination=ghost",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 400);

    let (status, body) = admin_request(
        addr,
        "DELETE",
        "/mappings?identifier=alice@example.com",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("removed"), "body: {body}");
    let (status, body) = admin_request(
        addr,
        "DELETE",
        "/mappings?identifier=alice@example.com",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("absent"), "body: {body}");
    assert_eq!(
        &*ctx.router.resolve(Some("alice@example.com")).await,
        "legacy"
    );

    let (status, _) = admin_request(
        addr,
        "POST",
        "/destinations/reset?destination=legacy",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    let (status, _) = admin_request(
        addr,
        "POST",
        "/destinations/reset?destination=ghost",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn admin_config_reload_swaps_routing() {
    let mapping = mapping_file("");
    let mapping_path = mapping.path().display().to_string();
    let toml_v1 = two_dest_config(&mapping_path, "legacy");

    let cfg_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(cfg_file.path(), toml_v1.as_bytes()).unwrap();
    let cfg_path: std::sync::Arc<str> = std::sync::Arc::from(cfg_file.path().display().to_string());

    let ctx = make_ctx(&toml_v1).await;
    let listener = TcpListener::bind(unused_addr()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let admin_config = ctx.config.clone();
    let shared = std::sync::Arc::new(arc_swap::ArcSwap::new(ctx.clone()));
    let serve_shared = shared.clone();
    tokio::spawn(async move {
        let _ = crate::admin::serve(serve_shared, admin_config, Some(cfg_path), listener).await;
    });

    let (status, body) = admin_request(
        addr,
        "GET",
        "/mappings?identifier=x@example.com",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    assert!(body.contains("\"destination\":\"legacy\""), "body: {body}");

    let toml_v2 = two_dest_config(&mapping_path, "secondary");
    std::fs::write(cfg_file.path(), toml_v2.as_bytes()).unwrap();
    let (status, body) = admin_request(addr, "POST", "/config/reload", Some(TOKEN)).await;
    assert_eq!(status, 200, "body: {body}");

    let (status, body) = admin_request(
        addr,
        "GET",
        "/mappings?identifier=x@example.com",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    assert!(
        body.contains("\"destination\":\"secondary\""),
        "body: {body}"
    );
    assert_eq!(
        &*shared.load().router.resolve(Some("y@example.com")).await,
        "secondary"
    );
}

#[tokio::test]
async fn admin_config_reload_rejects_invalid() {
    let mapping = mapping_file("");
    let mapping_path = mapping.path().display().to_string();
    let toml_v1 = two_dest_config(&mapping_path, "legacy");

    let cfg_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(cfg_file.path(), toml_v1.as_bytes()).unwrap();
    let cfg_path: std::sync::Arc<str> = std::sync::Arc::from(cfg_file.path().display().to_string());

    let ctx = make_ctx(&toml_v1).await;
    let listener = TcpListener::bind(unused_addr()).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let admin_config = ctx.config.clone();
    let shared = std::sync::Arc::new(arc_swap::ArcSwap::new(ctx.clone()));
    let serve_shared = shared.clone();
    tokio::spawn(async move {
        let _ = crate::admin::serve(serve_shared, admin_config, Some(cfg_path), listener).await;
    });

    std::fs::write(
        cfg_file.path(),
        b"[routing]\ndefault_destination = \"nope\"\n",
    )
    .unwrap();
    let (status, _) = admin_request(addr, "POST", "/config/reload", Some(TOKEN)).await;
    assert_eq!(status, 400);
    assert_eq!(
        &*shared.load().router.resolve(Some("y@example.com")).await,
        "legacy"
    );
}
