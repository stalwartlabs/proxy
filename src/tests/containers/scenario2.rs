/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::clients::Tls;
use super::scenario1::{assert_authenticated, assert_rejected, drive, stalwart_endpoint, tls_str};
use super::stalwart::{Edition, Stalwart};
use super::{Proxy, http, pick_free_port};
use crate::tests::harness::mapping_file;

const OLD_DOMAIN: &str = "old.test";
const NEW_DOMAIN: &str = "new.test";

fn mail_config(
    proto: &str,
    mode: Tls,
    listen_port: u16,
    old_port: u16,
    new_port: u16,
    map_path: &str,
) -> String {
    let tls = tls_str(mode);
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
default_destination = "old"

[destination.old]
host = "127.0.0.1"
tls_server_name = "old.test"
tls_allow_invalid_certs = true
forwarding = "proxy"
proxy_protocol = true
[destination.old.protocol.{proto}]
port = {old_port}
tls = "{tls}"

[destination.new]
host = "127.0.0.1"
tls_server_name = "new.test"
tls_allow_invalid_certs = true
forwarding = "proxy"
proxy_protocol = true
[destination.new.protocol.{proto}]
port = {new_port}
tls = "{tls}"

[listener.l]
protocol = "{proto}"
bind = ["0.0.0.0:{listen_port}"]
tls = "{tls}"
"#
    )
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn scenario2_routes_all_mail_protocols_in_all_tls_modes() {
    let old = Stalwart::start_proxied(
        Edition::Old,
        OLD_DOMAIN,
        &[("frank", "FrankPass#2026"), ("grace", "GracePass#2026")],
    )
    .await;
    let new = Stalwart::start_proxied(
        Edition::New,
        NEW_DOMAIN,
        &[("heidi", "HeidiPass#2026"), ("ivan", "IvanPass#2026")],
    )
    .await;

    let old_user = ("frank", "FrankPass#2026");
    let new_user = ("heidi@new.test", "HeidiPass#2026");
    let map = mapping_file(&format!("{}\told\n{}\tnew\n", old_user.0, new_user.0));

    let matrix: &[(&str, &[Tls])] = &[
        ("imap", &[Tls::Starttls, Tls::Implicit]),
        ("pop3", &[Tls::Starttls, Tls::Implicit]),
        ("submission", &[Tls::Starttls, Tls::Implicit]),
        ("managesieve", &[Tls::Starttls]),
    ];

    for (proto, modes) in matrix {
        for &mode in *modes {
            let old_port = stalwart_endpoint(&old, proto, mode);
            let new_port = stalwart_endpoint(&new, proto, mode);
            let listen = pick_free_port();
            let toml = mail_config(
                proto,
                mode,
                listen,
                old_port,
                new_port,
                map.path().to_str().unwrap(),
            );
            let proxy = Proxy::launch(&toml).await;
            let port = proxy.port("l");

            let to_old = drive(proto, mode, port, old_user.0, old_user.1).await;
            assert_authenticated(proto, &format!("old {proto}/{mode:?}"), &to_old);

            let to_new = drive(proto, mode, port, new_user.0, new_user.1).await;
            assert_authenticated(proto, &format!("new {proto}/{mode:?}"), &to_new);

            let wrong = drive(proto, mode, port, old_user.0, "WrongPass#0000").await;
            assert_rejected(proto, &format!("old bad-pass {proto}/{mode:?}"), &wrong);
        }
    }
}

fn http_config(
    listen_port: u16,
    old_https: u16,
    new_https: u16,
    map_path: &str,
    listener_tls: &str,
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
default_destination = "old"

[destination.old]
host = "127.0.0.1"
tls_server_name = "old.test"
tls_allow_invalid_certs = true
proxy_protocol = false
forwarded = true
[destination.old.protocol.http]
port = {old_https}
tls = "implicit"

[destination.new]
host = "127.0.0.1"
tls_server_name = "new.test"
tls_allow_invalid_certs = true
proxy_protocol = false
forwarded = true
[destination.new.protocol.http]
port = {new_https}
tls = "implicit"

[[http.route]]
match = "/**"
extract = {{ from = "authorization" }}
fallback = "default"

[listener.http]
protocol = "http"
bind = ["0.0.0.0:{listen_port}"]
tls = "{listener_tls}"
"#
    )
}

async fn jmap_session_account(host: &str, port: u16, tls: bool, bearer: &str) -> String {
    let resp = http::get_follow(
        host,
        port,
        tls,
        "/.well-known/jmap",
        &[("Authorization", bearer)],
    )
    .await;
    resp.json()["primaryAccounts"]
        .as_object()
        .and_then(|m| m.values().next())
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

async fn run_bearer_routing(listener_tls: &str) {
    let old =
        Stalwart::start_proxied(Edition::Old, OLD_DOMAIN, &[("frank", "FrankPass#2026")]).await;
    let new =
        Stalwart::start_proxied(Edition::New, NEW_DOMAIN, &[("heidi", "HeidiPass#2026")]).await;

    let old_token = old.accounts[0].token.clone();
    let new_token = new.accounts[0].token.clone();

    let map = mapping_file("heidi@new.test\tnew\nheidi\tnew\n");
    let listen = pick_free_port();
    let toml = http_config(
        listen,
        old.https,
        new.https,
        map.path().to_str().unwrap(),
        listener_tls,
    );
    let proxy = Proxy::launch(&toml).await;
    let port = proxy.port("http");
    let via_tls = listener_tls != "plain";

    let new_routed =
        jmap_session_account("127.0.0.1", port, via_tls, &format!("Bearer {new_token}")).await;
    let new_direct =
        jmap_session_account("127.0.0.1", new.https, true, &format!("Bearer {new_token}")).await;
    let old_direct =
        jmap_session_account("127.0.0.1", old.https, true, &format!("Bearer {old_token}")).await;
    assert!(
        !new_direct.is_empty() && !old_direct.is_empty(),
        "both systems must return a primary account directly (else the comparison is vacuous)"
    );
    assert_ne!(
        new_direct, old_direct,
        "the two systems must have distinct primary accounts for routing to be observable"
    );
    assert_eq!(
        new_routed, new_direct,
        "an sw1. token must route to the new system and return its session"
    );

    let old_routed =
        jmap_session_account("127.0.0.1", port, via_tls, &format!("Bearer {old_token}")).await;
    assert_eq!(
        old_routed, old_direct,
        "an opaque (non-sw1) token must fall back to the default destination (old system)"
    );
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn scenario2_http_routes_by_bearer_token() {
    run_bearer_routing("plain").await;
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn scenario2_https_routes_by_bearer_token() {
    run_bearer_routing("implicit").await;
}

async fn run_basic_routing(listener_tls: &str) {
    let old =
        Stalwart::start_proxied(Edition::Old, OLD_DOMAIN, &[("frank", "FrankPass#2026")]).await;
    let new =
        Stalwart::start_proxied(Edition::New, NEW_DOMAIN, &[("heidi", "HeidiPass#2026")]).await;

    let map = mapping_file("heidi@new.test\tnew\nfrank\told\n");
    let listen = pick_free_port();
    let toml = http_config(
        listen,
        old.https,
        new.https,
        map.path().to_str().unwrap(),
        listener_tls,
    );
    let proxy = Proxy::launch(&toml).await;
    let port = proxy.port("http");
    let via_tls = listener_tls != "plain";

    let new_auth = http::basic_auth("heidi@new.test", "HeidiPass#2026");
    let old_auth = http::basic_auth("frank", "FrankPass#2026");
    let new_routed = jmap_session_account("127.0.0.1", port, via_tls, &new_auth).await;
    let new_direct = jmap_session_account("127.0.0.1", new.https, true, &new_auth).await;
    let old_direct = jmap_session_account("127.0.0.1", old.https, true, &old_auth).await;
    assert!(
        !new_direct.is_empty() && !old_direct.is_empty(),
        "both systems must return a primary account directly (else the comparison is vacuous)"
    );
    assert_ne!(
        new_direct, old_direct,
        "the two systems must have distinct primary accounts for routing to be observable"
    );
    assert_eq!(
        new_routed, new_direct,
        "Basic auth for a new-system user must route to the new system"
    );

    let old_routed = jmap_session_account("127.0.0.1", port, via_tls, &old_auth).await;
    assert_eq!(
        old_routed, old_direct,
        "Basic auth for an old-system user must route to the old system"
    );
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn scenario2_http_routes_by_basic_auth() {
    run_basic_routing("plain").await;
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn scenario2_https_routes_by_basic_auth() {
    run_basic_routing("implicit").await;
}

async fn run_websocket_passthrough(listener_tls: &str) {
    let new =
        Stalwart::start_proxied(Edition::New, NEW_DOMAIN, &[("heidi", "HeidiPass#2026")]).await;
    let token = new.accounts[0].token.clone();
    let map = mapping_file("heidi@new.test\tnew\nheidi\tnew\n");
    let listen = pick_free_port();
    let toml = http_config(
        listen,
        new.https,
        new.https,
        map.path().to_str().unwrap(),
        listener_tls,
    );
    let proxy = Proxy::launch(&toml).await;
    let port = proxy.port("http");
    let via_tls = listener_tls != "plain";

    let bearer = format!("Bearer {token}");
    let headers = [
        ("Authorization", bearer.as_str()),
        ("Connection", "upgrade"),
        ("Upgrade", "websocket"),
        ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ("Sec-WebSocket-Version", "13"),
        ("Sec-WebSocket-Protocol", "jmap"),
    ];

    let direct = http::upgrade("127.0.0.1", new.https, true, "/jmap/ws", &headers)
        .await
        .expect("direct WS upgrade");
    assert_eq!(
        direct.status, 101,
        "backend should accept the WS upgrade directly"
    );

    let proxied = http::upgrade("127.0.0.1", port, via_tls, "/jmap/ws", &headers)
        .await
        .expect("proxied WS upgrade");
    assert_eq!(proxied.status, 101, "proxy must relay the WS upgrade");
    assert_eq!(
        proxied.header("sec-websocket-accept"),
        direct.header("sec-websocket-accept"),
        "the backend's Sec-WebSocket-Accept must be relayed unchanged"
    );
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn scenario2_http_websocket_upgrade_passes_through() {
    run_websocket_passthrough("plain").await;
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn scenario2_https_websocket_upgrade_passes_through() {
    run_websocket_passthrough("implicit").await;
}
