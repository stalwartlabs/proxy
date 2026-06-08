/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::legacy::Legacy;
use super::toolbox::Toolbox;
use super::{Proxy, pick_free_port};
use crate::tests::harness::mapping_file;

const USER: &str = "alice@legacy.test";
const PASS: &str = "AlicePass#2026";
const GW: &str = "host.docker.internal";

fn proxy_config(
    map_path: &str,
    imap_listen: u16,
    pop3_listen: u16,
    sub_listen: u16,
    sieve_listen: u16,
    legacy: &Legacy,
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

[destination.legacy]
host = "127.0.0.1"
tls_server_name = "legacy.test"
tls_allow_invalid_certs = true
forwarding = "xclient"
[destination.legacy.protocol.imap]
port = {imap}
tls = "starttls"
[destination.legacy.protocol.pop3]
port = {pop3}
tls = "starttls"
[destination.legacy.protocol.submission]
port = {sub}
tls = "starttls"
[destination.legacy.protocol.managesieve]
port = {sieve}
tls = "starttls"

[listener.imap]
protocol = "imap"
bind = ["0.0.0.0:{imap_listen}"]
tls = "starttls"

[listener.pop3]
protocol = "pop3"
bind = ["0.0.0.0:{pop3_listen}"]
tls = "starttls"

[listener.submission]
protocol = "submission"
bind = ["0.0.0.0:{sub_listen}"]
tls = "starttls"

[listener.managesieve]
protocol = "managesieve"
bind = ["0.0.0.0:{sieve_listen}"]
tls = "starttls"
"#,
        imap = legacy.imap,
        pop3 = legacy.pop3,
        sub = legacy.submission,
        sieve = legacy.sieve,
    )
}

struct Client {
    name: &'static str,
    script: String,
    expect: &'static str,
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn toolbox_mail_clients_through_proxy_legacy() {
    let legacy = Legacy::start().await;
    let toolbox = Toolbox::start().await;

    let map = mapping_file(&format!("{USER}\tlegacy\n"));
    let (ip, pp, sp, mp) = (
        pick_free_port(),
        pick_free_port(),
        pick_free_port(),
        pick_free_port(),
    );
    let toml = proxy_config(map.path().to_str().unwrap(), ip, pp, sp, mp, &legacy);
    let proxy = Proxy::launch(&toml).await;
    let (imap, pop3, sub, sieve) = (
        proxy.port("imap"),
        proxy.port("pop3"),
        proxy.port("submission"),
        proxy.port("managesieve"),
    );

    let clients = vec![
        Client {
            name: "curl/imap",
            script: format!(
                "curl -sS -k --ssl-reqd --url 'imap://{GW}:{imap}/' --user '{USER}:{PASS}' --request 'LIST \"\" \"*\"'"
            ),
            expect: "INBOX",
        },
        Client {
            name: "imtest/imap",
            script: format!(
                "printf 'C01 SELECT INBOX\\r\\nC02 LOGOUT\\r\\n' | \
                 imtest -t '' -m PLAIN -a '{USER}' -w '{PASS}' -p {imap} {GW}"
            ),
            expect: "Authenticated",
        },
        Client {
            name: "curl/pop3",
            script: format!(
                "curl -sS -v -k --ssl-reqd --url 'pop3://{GW}:{pop3}/' --user '{USER}:{PASS}' --request 'STAT'"
            ),
            expect: "+OK",
        },
        Client {
            name: "pop3test/pop3",
            script: format!(
                "printf 'STAT\\r\\nQUIT\\r\\n' | \
                 pop3test -t '' -m PLAIN -a '{USER}' -w '{PASS}' -p {pop3} {GW}"
            ),
            expect: "Authenticated",
        },
        Client {
            name: "swaks/submission",
            script: format!(
                "swaks --server {GW}:{sub} --tls --auth PLAIN --au '{USER}' --ap '{PASS}' \
                 --from '{USER}' --to 'bob@legacy.test' --h-Subject m6 --body hi"
            ),
            expect: "250",
        },
        Client {
            name: "msmtp/submission",
            script: format!(
                "printf 'Subject: m6\\r\\n\\r\\nhi\\r\\n' | \
                 msmtp --host={GW} --port={sub} --tls=on --tls-starttls=on --tls-certcheck=off \
                   --auth=plain --user='{USER}' --passwordeval=\"printf '%s' '{PASS}'\" \
                   --from='{USER}' --debug 'bob@legacy.test'"
            ),
            expect: "235",
        },
        Client {
            name: "smtptest/submission",
            script: format!(
                "printf 'QUIT\\r\\n' | \
                 smtptest -t '' -m PLAIN -a '{USER}' -w '{PASS}' -p {sub} {GW}"
            ),
            expect: "Authenticated",
        },
        Client {
            name: "sieve-connect/managesieve",
            script: format!(
                "printf 'keep;\\n' > /tmp/m6.sieve; \
                 printf '%s' '{PASS}' | sieve-connect --server {GW} --port {sieve} \
                   --user '{USER}' --passwordfd 0 --notlsverify \
                   --upload --localsieve /tmp/m6.sieve --remotesieve m6test; \
                 printf '%s' '{PASS}' | sieve-connect --server {GW} --port {sieve} \
                   --user '{USER}' --passwordfd 0 --notlsverify --list"
            ),
            expect: "m6test",
        },
        Client {
            name: "sivtest/managesieve",
            script: format!(
                "printf 'LISTSCRIPTS\\r\\nLOGOUT\\r\\n' | \
                 sivtest -t '' -m PLAIN -a '{USER}' -w '{PASS}' -p {sieve} {GW}"
            ),
            expect: "Authenticated",
        },
    ];

    let mut failures = Vec::new();
    for c in &clients {
        let out = toolbox.sh(&c.script).await;
        let combined = out.combined();
        let ok = if c.expect.is_empty() {
            out.ok()
        } else {
            combined.contains(c.expect)
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
        "{} of {} toolbox clients failed:\n\n{}",
        failures.len(),
        clients.len(),
        failures.join("\n\n")
    );
}
