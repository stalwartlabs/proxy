/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use futures_util::StreamExt;
use jmap_client::client::{Client, Credentials};
use jmap_client::client_ws::WebSocketMessage;
use jmap_client::event_source::PushNotification;
use jmap_client::mailbox::Role;
use tokio::time::timeout;

use super::stalwart::{Edition, Stalwart};
use super::{Proxy, pick_free_port};
use crate::tests::harness::mapping_file;

fn proxy_config(proxy_port: u16, new_https: u16, old_https: u16, map_path: &str) -> String {
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
default_destination = "new"

[destination.new]
host = "127.0.0.1"
tls_server_name = "new.test"
tls_allow_invalid_certs = true
proxy_protocol = false
forwarded = true
[destination.new.protocol.http]
port = {new_https}
tls = "implicit"

[destination.old]
host = "127.0.0.1"
tls_server_name = "old.test"
tls_allow_invalid_certs = true
proxy_protocol = false
forwarded = true
[destination.old.protocol.http]
port = {old_https}
tls = "implicit"

[[http.route]]
match = "/**"
extract = {{ from = "authorization" }}
fallback = "default"

[listener.http]
protocol = "http"
bind = ["0.0.0.0:{proxy_port}"]
tls = "plain"
"#
    )
}

async fn connect_via_proxy(proxy_port: u16, login: &str, password: &str) -> Client {
    Client::new()
        .credentials(Credentials::basic(login, password))
        .accept_invalid_certs(true)
        .follow_redirects(["127.0.0.1"])
        .connect(&format!("http://127.0.0.1:{proxy_port}"))
        .await
        .expect("jmap-client session via proxy")
}

async fn exercise_websocket(client: &Client, who: &str) {
    let mut ws = client
        .connect_ws()
        .await
        .unwrap_or_else(|e| panic!("[{who}] connect_ws: {e:?}"));

    let mut request = client.build();
    request.get_mailbox();
    let request_id = request.send_ws().await.expect("send_ws");

    let message = timeout(Duration::from_secs(10), ws.next())
        .await
        .unwrap_or_else(|_| panic!("[{who}] WebSocket response timed out"))
        .unwrap_or_else(|| panic!("[{who}] WebSocket stream ended"))
        .unwrap_or_else(|e| panic!("[{who}] WebSocket error: {e:?}"));
    match message {
        WebSocketMessage::Response(response) => assert_eq!(
            response.request_id(),
            Some(request_id.as_str()),
            "[{who}] the WebSocket response must echo our request id"
        ),
        other => panic!("[{who}] expected a method response over WebSocket, got {other:?}"),
    }
}

async fn exercise_event_source(client: &Client, who: &str) {
    let mut events = client
        .event_source(None::<Vec<_>>, false, Some(1), None)
        .await
        .expect("event_source");

    let mailbox_id = client
        .mailbox_create("EventSource Test", None::<String>, Role::None)
        .await
        .expect("mailbox_create")
        .take_id();

    let account_id = client.default_account_id().to_string();
    let mut saw_change = false;
    for _ in 0..20 {
        match timeout(Duration::from_secs(5), events.next()).await {
            Ok(Some(Ok(PushNotification::StateChange(changes)))) => {
                if changes.changes(&account_id).is_some() {
                    saw_change = true;
                    break;
                }
            }
            Ok(Some(Ok(_))) => {}
            _ => break,
        }
    }

    client.mailbox_destroy(&mailbox_id, true).await.ok();
    assert!(
        saw_change,
        "[{who}] EventSource must deliver a state change for account {account_id}"
    );
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn jmap_client_ws_and_sse_through_proxy() {
    let proxy_port = pick_free_port();
    let public_url = format!("http://127.0.0.1:{proxy_port}");

    let new = Stalwart::start_fronted(
        Edition::New,
        "new.test",
        &[("ivan", "IvanPass#2026")],
        &public_url,
    )
    .await;
    let old = Stalwart::start_fronted(
        Edition::Old,
        "old.test",
        &[("judy", "JudyPass#2026")],
        &public_url,
    )
    .await;

    let map = mapping_file("ivan@new.test\tnew\njudy\told\n");
    let toml = proxy_config(
        proxy_port,
        new.https,
        old.https,
        map.path().to_str().unwrap(),
    );
    let proxy = Proxy::launch(&toml).await;
    assert_eq!(proxy.port("http"), proxy_port);

    let new_client = connect_via_proxy(proxy_port, "ivan@new.test", "IvanPass#2026").await;
    exercise_websocket(&new_client, "new").await;
    exercise_event_source(&new_client, "new").await;

    let old_client = connect_via_proxy(proxy_port, "judy", "JudyPass#2026").await;
    exercise_websocket(&old_client, "old").await;
    exercise_event_source(&old_client, "old").await;
}
