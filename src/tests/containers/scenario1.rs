/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::clients::{self, Tls};
use super::legacy::Legacy;
use super::stalwart::{Edition, Stalwart};
use super::{Proxy, pick_free_port};
use crate::tests::harness::mapping_file;

pub(crate) fn tls_str(mode: Tls) -> &'static str {
    match mode {
        Tls::Implicit => "implicit",
        Tls::Starttls => "starttls",
    }
}

fn legacy_endpoint(l: &Legacy, proto: &str, mode: Tls) -> u16 {
    match (proto, mode) {
        ("imap", Tls::Implicit) => l.imaps,
        ("imap", _) => l.imap,
        ("pop3", Tls::Implicit) => l.pop3s,
        ("pop3", _) => l.pop3,
        ("submission", Tls::Implicit) => l.smtps,
        ("submission", _) => l.submission,
        ("managesieve", _) => l.sieve,
        _ => panic!("bad endpoint {proto}/{mode:?}"),
    }
}

pub(crate) fn stalwart_endpoint(s: &Stalwart, proto: &str, mode: Tls) -> u16 {
    match (proto, mode) {
        ("imap", Tls::Implicit) => s.imaps,
        ("imap", _) => s.imap,
        ("pop3", Tls::Implicit) => s.pop3s,
        ("pop3", _) => s.pop3,
        ("submission", Tls::Implicit) => s.smtps,
        ("submission", _) => s.submission,
        ("managesieve", _) => s.sieve,
        _ => panic!("bad endpoint {proto}/{mode:?}"),
    }
}

fn build_config(
    proto: &str,
    mode: Tls,
    listen_port: u16,
    legacy_port: u16,
    stalwart_port: u16,
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
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
tls_server_name = "legacy.test"
tls_allow_invalid_certs = true
forwarding = "xclient"
[destination.legacy.protocol.{proto}]
port = {legacy_port}
tls = "{tls}"

[destination.stalwartnew]
host = "127.0.0.1"
tls_server_name = "new.test"
tls_allow_invalid_certs = true
forwarding = "proxy"
proxy_protocol = true
[destination.stalwartnew.protocol.{proto}]
port = {stalwart_port}
tls = "{tls}"

[listener.l]
protocol = "{proto}"
bind = ["0.0.0.0:{listen_port}"]
tls = "{tls}"
"#
    )
}

pub(crate) async fn drive(
    proto: &str,
    mode: Tls,
    port: u16,
    login: &str,
    password: &str,
) -> String {
    match proto {
        "imap" => clients::imap_auth("127.0.0.1", port, mode, login, password).await,
        "pop3" => clients::pop3_auth("127.0.0.1", port, mode, login, password).await,
        "managesieve" => clients::managesieve_auth("127.0.0.1", port, mode, login, password).await,
        "submission" => clients::submission_send("127.0.0.1", port, mode, login, password).await,
        other => panic!("no driver for {other}"),
    }
}

pub(crate) fn assert_authenticated(proto: &str, who: &str, reply: &str) {
    let ok = match proto {
        "imap" => reply.contains("a1 OK"),
        "pop3" => reply.trim_start().starts_with("+OK"),
        "managesieve" => reply.trim_start().starts_with("OK"),
        "submission" => reply.contains("235"),
        _ => false,
    };
    assert!(ok, "{proto} auth for {who} failed: {reply:?}");
}

pub(crate) fn assert_rejected(proto: &str, who: &str, reply: &str) {
    let rejected = match proto {
        "imap" => reply.contains("a1 NO") || reply.contains("a1 BAD"),
        "pop3" => reply.trim_start().starts_with("-ERR"),
        "managesieve" => reply.trim_start().starts_with("NO"),
        "submission" => reply.contains("535") || reply.contains("454"),
        _ => false,
    };
    assert!(
        rejected,
        "{proto} auth for {who} should be rejected through the proxy: {reply:?}"
    );
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn scenario1_routes_all_protocols_in_all_tls_modes() {
    let legacy = Legacy::start().await;
    let stalwart = Stalwart::start_proxied(
        Edition::New,
        "new.test",
        &[("carol", "CarolPass#2026"), ("dave", "DavePass#2026")],
    )
    .await;

    let legacy_user = ("alice@legacy.test", "AlicePass#2026");
    let stalwart_user = ("carol@new.test", "CarolPass#2026");
    let map = mapping_file(&format!(
        "{}\tlegacy\n{}\tstalwartnew\n",
        legacy_user.0, stalwart_user.0
    ));

    let matrix: &[(&str, &[Tls])] = &[
        ("imap", &[Tls::Starttls, Tls::Implicit]),
        ("pop3", &[Tls::Starttls, Tls::Implicit]),
        ("submission", &[Tls::Starttls, Tls::Implicit]),
        ("managesieve", &[Tls::Starttls]),
    ];

    for (proto, modes) in matrix {
        for &mode in *modes {
            let lport = legacy_endpoint(&legacy, proto, mode);
            let sport = stalwart_endpoint(&stalwart, proto, mode);
            let listen = pick_free_port();
            let toml = build_config(
                proto,
                mode,
                listen,
                lport,
                sport,
                map.path().to_str().unwrap(),
            );
            let proxy = Proxy::launch(&toml).await;
            let port = proxy.port("l");

            let to_legacy = drive(proto, mode, port, legacy_user.0, legacy_user.1).await;
            assert_authenticated(proto, &format!("legacy {proto}/{mode:?}"), &to_legacy);

            let to_stalwart = drive(proto, mode, port, stalwart_user.0, stalwart_user.1).await;
            assert_authenticated(proto, &format!("stalwart {proto}/{mode:?}"), &to_stalwart);

            let wrong = drive(proto, mode, port, legacy_user.0, "WrongPass#0000").await;
            assert_rejected(proto, &format!("legacy bad-pass {proto}/{mode:?}"), &wrong);
        }
    }
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn scenario1_smtp_passthrough_to_stalwart() {
    let stalwart =
        Stalwart::start_proxied(Edition::New, "new.test", &[("carol", "CarolPass#2026")]).await;
    let map = mapping_file("placeholder@new.test\tstalwartnew\n");
    let listen = pick_free_port();
    let toml = format!(
        r#"
[server]
hostname = "proxy.test"

[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[routing]
default_destination = "stalwartnew"
smtp_passthrough_destination = "stalwartnew"

[destination.stalwartnew]
host = "127.0.0.1"
tls_server_name = "new.test"
tls_allow_invalid_certs = true
proxy_protocol = true
forwarding = "proxy"
[destination.stalwartnew.protocol.smtp]
port = {}
tls = "plain"

[listener.smtp]
protocol = "smtp"
bind = ["0.0.0.0:{listen}"]
tls = "plain"
"#,
        map.path().to_str().unwrap(),
        stalwart.smtp,
    );
    let proxy = Proxy::launch(&toml).await;
    let reply = clients::smtp_passthrough_send(
        "127.0.0.1",
        proxy.port("smtp"),
        "sender@example.com",
        "carol@new.test",
    )
    .await;
    assert!(
        reply.contains("250") || reply.contains("251"),
        "passthrough RCPT to a hosted Stalwart user should be accepted: {reply:?}"
    );
}
