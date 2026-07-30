/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::harness::*;
use crate::proto::common::Ctx;

fn config(port: u16, mapping_path: &str, threshold: u32, min_clients: u32) -> String {
    format!(
        r#"
[server]
host_down_threshold = {threshold}
host_down_min_clients = {min_clients}
host_down_cooldown = "60s"
backend_connect_retries = 0

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

[listener.imap]
protocol = "imap"
bind = ["127.0.0.1:0"]
tls = "plain"
"#
    )
}

struct Backend {
    port: u16,
    serving: Arc<AtomicBool>,
    accepted: Arc<AtomicU32>,
    handle: JoinHandle<()>,
}

async fn banning_backend() -> Backend {
    let listener = TcpListener::bind(unused_addr()).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let serving = Arc::new(AtomicBool::new(false));
    let accepted = Arc::new(AtomicU32::new(0));
    let serving_task = serving.clone();
    let accepted_task = accepted.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let _ = socket.set_nodelay(true);
            accepted_task.fetch_add(1, Ordering::Relaxed);
            if serving_task.load(Ordering::Relaxed) {
                tokio::spawn(serve_imap_auth(socket));
            } else {
                drop(socket);
            }
        }
    });
    Backend {
        port,
        serving,
        accepted,
        handle,
    }
}

async fn serve_imap_auth(mut socket: TcpStream) {
    let _ = socket
        .write_all(b"* OK [CAPABILITY IMAP4rev2] backend ready\r\n")
        .await;

    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];
    let tag = loop {
        let Ok(n) = socket.read(&mut scratch).await else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&scratch[..n]);
        if let Some(end) = find(&buf, b"\r\n") {
            let line = String::from_utf8_lossy(&buf[..end]).into_owned();
            break line.split(' ').next().unwrap_or("a1").to_string();
        }
    };
    let _ = socket
        .write_all(format!("{tag} OK [CAPABILITY IMAP4rev2] authenticated\r\n").as_bytes())
        .await;

    loop {
        if find(&buf, b"NOOP").is_some() {
            break;
        }
        let Ok(n) = socket.read(&mut scratch).await else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&scratch[..n]);
    }
    let _ = socket.write_all(b"a2 OK NOOP done\r\n").await;
}

async fn imap_login(ctx: &Arc<Ctx>, peer: &str, user: &str) -> Vec<u8> {
    let listener = ctx.config.listener["imap"].clone();
    let peer: SocketAddr = peer.parse().unwrap();
    let (mut client, server) = tcp_pair().await;
    let ctx_task = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::proto::imap::handle(
            &ctx_task,
            &listener,
            Box::new(server),
            peer,
            "127.0.0.1:143".parse().unwrap(),
        )
        .await;
    });

    let _greeting = read_line(&mut client).await;
    send(
        &mut client,
        format!("a1 LOGIN {user} secret\r\na2 NOOP\r\n").as_bytes(),
    )
    .await;
    let resp = read_to_eof(&mut client).await;
    handler.abort();
    resp
}

#[tokio::test]
async fn one_banned_client_does_not_mark_the_destination_down() {
    let backend = banning_backend().await;
    let mapping = mapping_file("");
    let toml = config(backend.port, &mapping.path().display().to_string(), 3, 2);
    let ctx = make_ctx(&toml).await;

    for i in 0..5 {
        let resp = imap_login(&ctx, "198.51.100.7:40000", "banned@example.com").await;
        assert!(
            find(&resp, b"a1 NO [UNAVAILABLE]").is_some(),
            "attempt {i} should report the backend unavailable, got {:?}",
            String::from_utf8_lossy(&resp)
        );
    }

    let health = ctx.dest_health.get("legacy").unwrap().snapshot();
    assert_eq!(health.consecutive_failures, 5);
    assert_eq!(health.failure_sources, 1);
    assert!(!health.host_level_failure);
    assert!(
        !health.down,
        "a single client must not open the circuit breaker"
    );

    backend.serving.store(true, Ordering::Relaxed);
    let resp = imap_login(&ctx, "203.0.113.4:40000", "alice@example.com").await;
    assert!(
        find(&resp, b"a1 OK").is_some(),
        "an unrelated account must still reach the backend, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(!ctx.dest_health.get("legacy").unwrap().snapshot().down);
    assert!(backend.accepted.load(Ordering::Relaxed) >= 6);

    backend.handle.abort();
}

#[tokio::test]
async fn rejections_spanning_distinct_clients_mark_the_destination_down() {
    let backend = banning_backend().await;
    let mapping = mapping_file("");
    let toml = config(backend.port, &mapping.path().display().to_string(), 3, 2);
    let ctx = make_ctx(&toml).await;

    for peer in [
        "198.51.100.7:40000",
        "198.51.100.7:40001",
        "203.0.113.4:40000",
    ] {
        let resp = imap_login(&ctx, peer, "user@example.com").await;
        assert!(find(&resp, b"a1 NO [UNAVAILABLE]").is_some());
    }

    let health = ctx.dest_health.get("legacy").unwrap().snapshot();
    assert_eq!(health.failure_sources, 2);
    assert!(
        health.down,
        "failures from distinct clients are evidence the host is unhealthy"
    );

    let accepted_before = backend.accepted.load(Ordering::Relaxed);
    backend.serving.store(true, Ordering::Relaxed);
    let resp = imap_login(&ctx, "192.0.2.9:40000", "alice@example.com").await;
    assert!(find(&resp, b"a1 NO [UNAVAILABLE]").is_some());
    assert_eq!(
        backend.accepted.load(Ordering::Relaxed),
        accepted_before,
        "an open breaker must short-circuit before dialing the backend"
    );

    backend.handle.abort();
}

#[tokio::test]
async fn min_clients_zero_restores_counting_by_failures_alone() {
    let backend = banning_backend().await;
    let mapping = mapping_file("");
    let toml = config(backend.port, &mapping.path().display().to_string(), 3, 0);
    let ctx = make_ctx(&toml).await;

    for _ in 0..3 {
        let resp = imap_login(&ctx, "198.51.100.7:40000", "banned@example.com").await;
        assert!(find(&resp, b"a1 NO [UNAVAILABLE]").is_some());
    }

    let health = ctx.dest_health.get("legacy").unwrap().snapshot();
    assert_eq!(health.failure_sources, 1);
    assert!(
        health.down,
        "without the breadth requirement a single client still opens the breaker"
    );

    backend.handle.abort();
}

#[tokio::test]
async fn unreachable_host_marks_the_destination_down_from_one_client() {
    let closed_port = {
        let l = TcpListener::bind(unused_addr()).await.unwrap();
        l.local_addr().unwrap().port()
    };
    let mapping = mapping_file("");
    let toml = config(closed_port, &mapping.path().display().to_string(), 3, 2);
    let ctx = make_ctx(&toml).await;

    for _ in 0..3 {
        let resp = imap_login(&ctx, "198.51.100.7:40000", "user@example.com").await;
        assert!(find(&resp, b"a1 NO [UNAVAILABLE]").is_some());
    }

    let health = ctx.dest_health.get("legacy").unwrap().snapshot();
    assert!(health.host_level_failure);
    assert!(
        health.down,
        "connect-stage failures are host evidence regardless of how many clients saw them"
    );
}
