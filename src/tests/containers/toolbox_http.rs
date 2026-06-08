/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::stalwart::{Edition, Stalwart};
use super::toolbox::Toolbox;
use super::{HOST_GATEWAY, Proxy, pick_free_port};
use crate::tests::harness::mapping_file;

const USER: &str = "ivan@new.test";
const PASS: &str = "IvanPass#2026";

fn proxy_config(proxy_port: u16, new_https: u16, map_path: &str) -> String {
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

const JMAPC_SCRIPT: &str = r#"
import sys, functools
import requests
from jmapc import Client
from jmapc.session import Session
from jmapc.methods import MailboxGet

class HttpClient(Client):
    @functools.cached_property
    def jmap_session(self):
        r = self.requests_session.get(
            f"http://{self._host}/.well-known/jmap", timeout=30
        )
        r.raise_for_status()
        return Session.from_dict(r.json())

host, user, password = sys.argv[1], sys.argv[2], sys.argv[3]
c = HttpClient.create_with_password(host=host, user=user, password=password)
session = c.jmap_session
account = c.account_id
resp = c.request(MailboxGet(ids=None), single_response=True)
api = session.api_url
assert host in api, f"apiUrl must point at the proxy, got {api}"
print(f"JMAPC_OK account={account} mailboxes={len(resp.data)} api={api}")
"#;

struct Client {
    name: &'static str,
    script: String,
    expect: String,
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn toolbox_http_clients_through_proxy() {
    let proxy_port = pick_free_port();
    let public_url = format!("http://{HOST_GATEWAY}:{proxy_port}");
    let new =
        Stalwart::start_fronted(Edition::New, "new.test", &[("ivan", PASS)], &public_url).await;

    let map = mapping_file(&format!("{USER}\tnew\n"));
    let toml = proxy_config(proxy_port, new.https, map.path().to_str().unwrap());
    let proxy = Proxy::launch(&toml).await;
    assert_eq!(proxy.port("http"), proxy_port);

    let toolbox = Toolbox::start().await;
    let gw = format!("{HOST_GATEWAY}:{proxy_port}");
    let account = USER.replace('@', "%40");

    let clients = vec![
        Client {
            name: "curl/jmap-session",
            script: format!(
                "curl -sS -L --url 'http://{gw}/.well-known/jmap' --user '{USER}:{PASS}'"
            ),
            expect: format!("\"apiUrl\":\"http://{gw}/"),
        },
        Client {
            name: "jmapc/jmap",
            script: format!("python3 -c '{JMAPC_SCRIPT}' '{gw}' '{USER}' '{PASS}'"),
            expect: "JMAPC_OK".to_string(),
        },
        Client {
            name: "curl/dav-propfind",
            script: format!(
                "curl -sS -i -X PROPFIND --url 'http://{gw}/dav/cal/{account}/' \
                 --user '{USER}:{PASS}' -H 'Depth: 0' -H 'Content-Type: application/xml' \
                 --data '<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:prop><D:current-user-principal/><D:resourcetype/></D:prop></D:propfind>'"
            ),
            expect: "207".to_string(),
        },
        Client {
            name: "curl/carddav-propfind",
            script: format!(
                "curl -sS -i -X PROPFIND --url 'http://{gw}/dav/card/{account}/' \
                 --user '{USER}:{PASS}' -H 'Depth: 0' -H 'Content-Type: application/xml' \
                 --data '<?xml version=\"1.0\"?><D:propfind xmlns:D=\"DAV:\"><D:prop><D:current-user-principal/><D:resourcetype/></D:prop></D:propfind>'"
            ),
            expect: "207".to_string(),
        },
        Client {
            name: "curl/caldav-report",
            script: format!(
                "curl -sS -i -X REPORT --url 'http://{gw}/dav/cal/{account}/default/' \
                 --user '{USER}:{PASS}' -H 'Depth: 1' -H 'Content-Type: application/xml' \
                 --data '<?xml version=\"1.0\"?><C:calendar-query xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\"><D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name=\"VCALENDAR\"/></C:filter></C:calendar-query>'"
            ),
            expect: "207".to_string(),
        },
        Client {
            name: "curl/sse-stream",
            script: format!(
                "curl -sS -i --max-time 3 \
                 --url 'http://{gw}/jmap/eventsource/?types=*&closeafter=no&ping=1' \
                 --user '{USER}:{PASS}' || true"
            ),
            expect: "text/event-stream".to_string(),
        },
        Client {
            name: "vdirsyncer/dav",
            script: format!(
                "mkdir -p /tmp/vd/status /tmp/vd/cal; \
                 cat > /tmp/vd.conf <<EOF\n\
[general]\n\
status_path = \"/tmp/vd/status\"\n\
[pair cal]\n\
a = \"local\"\n\
b = \"dav\"\n\
collections = [\"from b\"]\n\
[storage local]\n\
type = \"filesystem\"\n\
path = \"/tmp/vd/cal\"\n\
fileext = \".ics\"\n\
[storage dav]\n\
type = \"caldav\"\n\
url = \"http://{gw}/dav/cal/{account}/\"\n\
username = \"{USER}\"\n\
password = \"{PASS}\"\n\
EOF\n\
                 vdirsyncer -c /tmp/vd.conf discover cal < /dev/null"
            ),
            expect: "Stalwart Calendar".to_string(),
        },
        Client {
            name: "websocat/ws",
            script: format!(
                "printf '%s' '{{\"@type\":\"Request\",\"using\":[\"urn:ietf:params:jmap:core\"],\"methodCalls\":[[\"Core/echo\",{{\"hello\":\"m6\"}},\"c0\"]]}}' \
                 | timeout 15 websocat -1 -n --protocol jmap \
                   -H='Authorization: Basic '$(printf '%s' '{USER}:{PASS}' | base64 -w0) \
                   'ws://{gw}/jmap/ws'"
            ),
            expect: "m6".to_string(),
        },
        Client {
            name: "curl/ws-handshake",
            script: format!(
                "curl -sS -i --max-time 8 \
                   -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
                   -H 'Sec-WebSocket-Version: 13' \
                   -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
                   -H 'Sec-WebSocket-Protocol: jmap' \
                   --user '{USER}:{PASS}' \
                   'http://{gw}/jmap/ws' || true"
            ),
            expect: "101".to_string(),
        },
    ];

    let mut failures = Vec::new();
    for c in &clients {
        let out = toolbox.sh(&c.script).await;
        let combined = out.combined();
        let ok = if c.expect.is_empty() {
            out.ok()
        } else {
            combined.contains(c.expect.as_str())
        };
        if !ok {
            failures.push(format!(
                "[{}] exit={} expect={:?}\n--- output ---\n{}\n--------------",
                c.name, out.code, c.expect, combined
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} HTTP toolbox clients failed:\n\n{}",
        failures.len(),
        clients.len(),
        failures.join("\n\n")
    );
}
