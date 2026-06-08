/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use super::{Proxy, pick_free_port};
use crate::tests::harness::{dummy_backend, mapping_file};

async fn idle_pop3_backend() -> (u16, tokio::task::JoinHandle<()>) {
    dummy_backend(|mut sock| async move {
        sock.write_all(b"+OK dummy ready\r\n").await.unwrap();
        let mut buf = [0u8; 256];
        let _ = sock.read(&mut buf).await;
    })
    .await
}

fn pop3_config(listen_port: u16, backend_port: u16, map_path: &str, knobs: &str) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{map_path}"

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
forwarding = "none"
allow_plaintext_auth = true
[destination.legacy.protocol.pop3]
port = {backend_port}
tls = "plain"

[capabilities.pop3]
allow_plain_auth_without_tls = true

[listener.pop3]
protocol = "pop3"
bind = ["127.0.0.1:{listen_port}"]
tls = "plain"
{knobs}
"#
    )
}

async fn read_some(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = [0u8; 512];
    match stream.read(&mut buf).await {
        Ok(n) => buf[..n].to_vec(),
        Err(_) => Vec::new(),
    }
}

#[tokio::test]
async fn max_connections_drops_over_limit_connections() {
    let (backend_port, backend) = idle_pop3_backend().await;
    let map = mapping_file("user@example.com\tlegacy\n");
    let listen = pick_free_port();
    let toml = pop3_config(
        listen,
        backend_port,
        map.path().to_str().unwrap(),
        "max_connections = 2",
    );
    let proxy = Proxy::launch(&toml).await;
    let port = proxy.port("pop3");

    let mut held = Vec::new();
    for _ in 0..2 {
        let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let greeting = read_some(&mut c).await;
        assert!(
            greeting.starts_with(b"+OK"),
            "within-limit connection should be greeted, got {:?}",
            String::from_utf8_lossy(&greeting)
        );
        held.push(c);
    }

    let mut over = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let greeting = timeout(Duration::from_secs(2), read_some(&mut over))
        .await
        .expect("over-limit connection should be closed, not left hanging");
    assert!(
        greeting.is_empty(),
        "over-limit connection must be dropped with no greeting, got {:?}",
        String::from_utf8_lossy(&greeting)
    );

    drop(held);
    drop(proxy);
    backend.abort();
}

#[tokio::test]
async fn preauth_timeout_closes_idle_connection() {
    let (backend_port, backend) = idle_pop3_backend().await;
    let map = mapping_file("user@example.com\tlegacy\n");
    let listen = pick_free_port();
    let toml = pop3_config(
        listen,
        backend_port,
        map.path().to_str().unwrap(),
        "preauth_timeout = \"1s\"",
    );
    let proxy = Proxy::launch(&toml).await;
    let port = proxy.port("pop3");

    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let greeting = read_some(&mut c).await;
    assert!(greeting.starts_with(b"+OK"), "expected greeting");

    let started = Instant::now();
    let tail = timeout(Duration::from_secs(5), read_some(&mut c))
        .await
        .expect("idle connection must be closed by preauth_timeout");
    assert!(
        tail.is_empty(),
        "connection should close on timeout, got {:?}",
        String::from_utf8_lossy(&tail)
    );
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "should not close before the 1s timeout elapses"
    );

    drop(proxy);
    backend.abort();
}

#[tokio::test]
async fn max_auth_attempts_disconnects_after_limit() {
    let (backend_port, backend) = idle_pop3_backend().await;
    let map = mapping_file("user@example.com\tlegacy\n");
    let listen = pick_free_port();
    let toml = pop3_config(
        listen,
        backend_port,
        map.path().to_str().unwrap(),
        "max_auth_attempts = 2",
    );
    let proxy = Proxy::launch(&toml).await;
    let port = proxy.port("pop3");

    let mut c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let greeting = read_some(&mut c).await;
    assert!(greeting.starts_with(b"+OK"), "expected greeting");

    c.write_all(b"AUTH FROBNICATE\r\n").await.unwrap();
    let first = read_some(&mut c).await;
    assert!(
        first.starts_with(b"-ERR"),
        "first bad attempt should be rejected but not disconnected, got {:?}",
        String::from_utf8_lossy(&first)
    );

    c.write_all(b"AUTH FROBNICATE\r\n").await.unwrap();
    let second = timeout(Duration::from_secs(2), read_to_eof(&mut c))
        .await
        .expect("second bad attempt must reach the limit and disconnect");
    assert!(
        !second.windows(4).any(|w| w == b"+OK "),
        "connection must be closed after hitting max_auth_attempts"
    );

    drop(proxy);
    backend.abort();
}

async fn read_to_eof(stream: &mut TcpStream) -> Vec<u8> {
    let mut acc = Vec::new();
    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => acc.extend_from_slice(&buf[..n]),
        }
    }
    acc
}
