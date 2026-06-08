/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::clients::{self, Tls};
use super::legacy::{Legacy, MASTER_PASSWORD, MASTER_USER};
use super::{Proxy, pick_free_port};
use crate::tests::harness::mapping_file;

fn legacy_imap_config(
    listen: u16,
    legacy_port: u16,
    map_path: &str,
    tls: &str,
    extra: &str,
) -> String {
    format!(
        r#"
[server]
hostname = "proxy.test"

[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{map_path}"

[routing]
default_destination = "legacy"
master_user_separators = ["%"]

[destination.legacy]
host = "127.0.0.1"
tls_server_name = "legacy.test"
tls_allow_invalid_certs = true
forwarding = "xclient"
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = {legacy_port}
tls = "{tls}"

[capabilities.imap]
allow_plain_auth_without_tls = true

[listener.l]
protocol = "imap"
bind = ["0.0.0.0:{listen}"]
tls = "{tls}"
{extra}
"#
    )
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn master_user_login_routes_on_account_and_authenticates() {
    let legacy = Legacy::start().await;

    let map = mapping_file("alice@legacy.test\tlegacy\n");
    let listen = pick_free_port();
    let toml = legacy_imap_config(
        listen,
        legacy.imaps,
        map.path().to_str().unwrap(),
        "implicit",
        "",
    );
    let proxy = Proxy::launch(&toml).await;

    let master_login = format!("alice@legacy.test{}{}", "%", MASTER_USER);
    let reply = clients::imap_auth(
        "127.0.0.1",
        proxy.port("l"),
        Tls::Implicit,
        &master_login,
        MASTER_PASSWORD,
    )
    .await;
    assert!(
        reply.contains("a1 OK"),
        "master login {master_login:?} should authenticate as alice via Dovecot master passdb: {reply:?}"
    );
}

async fn read_until_tag(s: &mut TcpStream, tag: &str) -> String {
    let mut buf = [0u8; 1024];
    let mut acc = String::new();
    for _ in 0..16 {
        match s.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => acc.push_str(&String::from_utf8_lossy(&buf[..n])),
        }
        if acc.contains(tag) {
            break;
        }
    }
    acc
}

async fn plain_imap_auth(port: u16, login: &str, password: &str) -> bool {
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)).await else {
        return false;
    };
    let mut buf = [0u8; 1024];
    if s.read(&mut buf).await.unwrap_or(0) == 0 {
        return false;
    }
    let ir = B64.encode(format!("\0{login}\0{password}"));
    if s.write_all(format!("a1 AUTHENTICATE PLAIN {ir}\r\n").as_bytes())
        .await
        .is_err()
    {
        return false;
    }
    if !read_until_tag(&mut s, "a1 ").await.contains("a1 OK") {
        return false;
    }
    if s.write_all(b"a2 SELECT INBOX\r\n").await.is_err() {
        return false;
    }
    read_until_tag(&mut s, "a2 ").await.contains("a2 OK")
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn concurrent_sessions_stay_stable() {
    let legacy = Legacy::start().await;

    let map = mapping_file("alice@legacy.test\tlegacy\n");
    let listen = pick_free_port();
    let toml = legacy_imap_config(
        listen,
        legacy.imap,
        map.path().to_str().unwrap(),
        "plain",
        "max_connections = 4096",
    );
    let proxy = Proxy::launch(&toml).await;
    let port = proxy.port("l");

    const SESSIONS: usize = 150;
    let mut handles = Vec::with_capacity(SESSIONS);
    for _ in 0..SESSIONS {
        handles.push(tokio::spawn(async move {
            plain_imap_auth(port, "alice@legacy.test", "AlicePass#2026").await
        }));
    }

    let mut ok = 0usize;
    for h in handles {
        if h.await.unwrap_or(false) {
            ok += 1;
        }
    }
    assert_eq!(
        ok, SESSIONS,
        "all {SESSIONS} concurrent sessions should authenticate and bridge ({ok} succeeded)"
    );
}
