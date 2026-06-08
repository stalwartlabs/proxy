/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::stalwart::{Edition, Stalwart};
use super::toolbox::Toolbox;
use super::{HOST_GATEWAY, Proxy, pick_free_port};
use crate::tests::harness::{mapping_file, tls_connect_client};

const DOMAIN: &str = "new.test";

#[derive(Clone, Copy, Debug)]
enum Mech {
    OAuthBearer,
    XOauth2,
}

impl Mech {
    fn name(self) -> &'static str {
        match self {
            Mech::OAuthBearer => "OAUTHBEARER",
            Mech::XOauth2 => "XOAUTH2",
        }
    }

    fn ir(self, email: &str, token: &str) -> String {
        let frame = match self {
            Mech::OAuthBearer => format!("n,a={email},\x01auth=Bearer {token}\x01\x01"),
            Mech::XOauth2 => format!("user={email}\x01auth=Bearer {token}\x01\x01"),
        };
        B64.encode(frame.as_bytes())
    }
}

async fn read_until<S: AsyncRead + Unpin>(stream: &mut S, needle: &str) -> String {
    let mut acc = String::new();
    let mut buf = [0u8; 4096];
    for _ in 0..64 {
        let n = match stream.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        acc.push_str(&String::from_utf8_lossy(&buf[..n]));
        if acc.contains(needle) {
            break;
        }
    }
    acc
}

async fn read_one<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).into_owned()
}

fn config(proto: &str, tls: &str, listen: u16, backend: u16, map_path: &str) -> String {
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
forwarding = "proxy"
proxy_protocol = true
[destination.new.protocol.{proto}]
port = {backend}
tls = "{tls}"

[listener.l]
protocol = "{proto}"
bind = ["0.0.0.0:{listen}"]
tls = "{tls}"
"#
    )
}

async fn imap_oauth(port: u16, mech: Mech, email: &str, token: &str) -> Result<(), String> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.map_err(de)?;
    let mut s = tls_connect_client(tcp).await;
    let _ = read_until(&mut s, "OK").await;
    let cmd = format!(
        "a1 AUTHENTICATE {} {}\r\n",
        mech.name(),
        mech.ir(email, token)
    );
    s.write_all(cmd.as_bytes()).await.map_err(de)?;
    let auth = read_until(&mut s, "a1 ").await;
    if !auth.contains("a1 OK") {
        return Err(format!("auth: {auth:?}"));
    }
    s.write_all(b"a2 SELECT INBOX\r\n").await.map_err(de)?;
    let action = read_until(&mut s, "a2 ").await;
    if action.contains("a2 OK") {
        Ok(())
    } else {
        Err(format!("SELECT: {action:?}"))
    }
}

async fn pop3_oauth(port: u16, mech: Mech, email: &str, token: &str) -> Result<(), String> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.map_err(de)?;
    let mut s = tls_connect_client(tcp).await;
    let _ = read_one(&mut s).await;
    let cmd = format!("AUTH {} {}\r\n", mech.name(), mech.ir(email, token));
    s.write_all(cmd.as_bytes()).await.map_err(de)?;
    let auth = read_until(&mut s, "\r\n").await;
    if !auth.trim_start().starts_with("+OK") {
        return Err(format!("auth: {auth:?}"));
    }
    s.write_all(b"STAT\r\n").await.map_err(de)?;
    let action = read_until(&mut s, "\r\n").await;
    if action.trim_start().starts_with("+OK") {
        Ok(())
    } else {
        Err(format!("STAT: {action:?}"))
    }
}

async fn submission_oauth(port: u16, mech: Mech, email: &str, token: &str) -> Result<(), String> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.map_err(de)?;
    let mut s = tls_connect_client(tcp).await;
    let _ = read_one(&mut s).await;
    s.write_all(b"EHLO proxy.test\r\n").await.map_err(de)?;
    let _ = read_until(&mut s, "250 ").await;
    let cmd = format!("AUTH {} {}\r\n", mech.name(), mech.ir(email, token));
    s.write_all(cmd.as_bytes()).await.map_err(de)?;
    let auth = read_until(&mut s, "\r\n").await;
    if !auth.contains("235") {
        return Err(format!("auth: {auth:?}"));
    }
    s.write_all(format!("MAIL FROM:<{email}>\r\n").as_bytes())
        .await
        .map_err(de)?;
    let from = read_until(&mut s, "\r\n").await;
    if !from.contains("250") {
        return Err(format!("MAIL FROM: {from:?}"));
    }
    s.write_all(format!("RCPT TO:<{email}>\r\n").as_bytes())
        .await
        .map_err(de)?;
    let rcpt = read_until(&mut s, "\r\n").await;
    if rcpt.contains("250") {
        Ok(())
    } else {
        Err(format!("RCPT TO: {rcpt:?}"))
    }
}

async fn managesieve_oauth(port: u16, mech: Mech, email: &str, token: &str) -> Result<(), String> {
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).await.map_err(de)?;
    let _ = read_until(&mut tcp, "OK").await;
    tcp.write_all(b"STARTTLS\r\n").await.map_err(de)?;
    let _ = read_until(&mut tcp, "OK").await;
    let mut s = tls_connect_client(tcp).await;
    let _ = read_until(&mut s, "OK").await;
    let cmd = format!(
        "AUTHENTICATE \"{}\" \"{}\"\r\n",
        mech.name(),
        mech.ir(email, token)
    );
    s.write_all(cmd.as_bytes()).await.map_err(de)?;
    let auth = read_until(&mut s, "\r\n").await;
    if !auth.trim_start().starts_with("OK") {
        return Err(format!("auth: {auth:?}"));
    }
    s.write_all(b"LISTSCRIPTS\r\n").await.map_err(de)?;
    let action = read_until(&mut s, "OK").await;
    if action.contains("OK") {
        Ok(())
    } else {
        Err(format!("LISTSCRIPTS: {action:?}"))
    }
}

fn de<E: std::fmt::Debug>(e: E) -> String {
    format!("{e:?}")
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn oauth_mail_mechanisms_through_proxy() {
    let new = Stalwart::start_proxied(Edition::New, DOMAIN, &[("ivan", "IvanPass#2026")]).await;
    let email = new.accounts[0].login.clone();
    let token = new.accounts[0].token.clone();
    assert!(!token.is_empty(), "harness must mint a real access token");

    let map = mapping_file(&format!("{email}\tnew\n"));
    let map_path = map.path().to_str().unwrap();

    let mechs = [Mech::OAuthBearer, Mech::XOauth2];
    let mut failures = Vec::new();

    for mech in mechs {
        let listen = pick_free_port();
        let toml = config("imap", "implicit", listen, new.imaps, map_path);
        let proxy = Proxy::launch(&toml).await;
        if let Err(e) = imap_oauth(proxy.port("l"), mech, &email, &token).await {
            failures.push(format!("imap/{}: {e}", mech.name()));
        }

        let listen = pick_free_port();
        let toml = config("pop3", "implicit", listen, new.pop3s, map_path);
        let proxy = Proxy::launch(&toml).await;
        if let Err(e) = pop3_oauth(proxy.port("l"), mech, &email, &token).await {
            failures.push(format!("pop3/{}: {e}", mech.name()));
        }

        let listen = pick_free_port();
        let toml = config("submission", "implicit", listen, new.smtps, map_path);
        let proxy = Proxy::launch(&toml).await;
        if let Err(e) = submission_oauth(proxy.port("l"), mech, &email, &token).await {
            failures.push(format!("submission/{}: {e}", mech.name()));
        }

        let listen = pick_free_port();
        let toml = config("managesieve", "starttls", listen, new.sieve, map_path);
        let proxy = Proxy::launch(&toml).await;
        if let Err(e) = managesieve_oauth(proxy.port("l"), mech, &email, &token).await {
            failures.push(format!("managesieve/{}: {e}", mech.name()));
        }
    }

    assert!(
        failures.is_empty(),
        "{} OAuth mail mechanism/protocol combinations failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

fn toolbox_config(map_path: &str, imap_listen: u16, sub_listen: u16, new: &Stalwart) -> String {
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
forwarding = "proxy"
proxy_protocol = true
[destination.new.protocol.imap]
port = {imaps}
tls = "implicit"
[destination.new.protocol.submission]
port = {smtps}
tls = "implicit"

[listener.imap]
protocol = "imap"
bind = ["0.0.0.0:{imap_listen}"]
tls = "starttls"

[listener.submission]
protocol = "submission"
bind = ["0.0.0.0:{sub_listen}"]
tls = "starttls"
"#,
        imaps = new.imaps,
        smtps = new.smtps,
    )
}

struct OauthClient {
    name: &'static str,
    script: String,
    expect: &'static str,
}

#[tokio::test]
#[ignore = "requires Docker"]
async fn oauth_mail_real_clients_through_proxy() {
    let new = Stalwart::start_proxied(Edition::New, DOMAIN, &[("ivan", "IvanPass#2026")]).await;
    let email = new.accounts[0].login.clone();
    let token = new.accounts[0].token.clone();
    assert!(!token.is_empty(), "harness must mint a real access token");

    let map = mapping_file(&format!("{email}\tnew\n"));
    let (imap_listen, sub_listen) = (pick_free_port(), pick_free_port());
    let toml = toolbox_config(map.path().to_str().unwrap(), imap_listen, sub_listen, &new);
    let proxy = Proxy::launch(&toml).await;
    let imap = proxy.port("imap");
    let sub = proxy.port("submission");

    let toolbox = Toolbox::start().await;
    let gw = HOST_GATEWAY;

    let clients = vec![
        OauthClient {
            name: "curl/imap-oauthbearer",
            script: format!(
                "curl -sS -k --ssl-reqd --url 'imap://{gw}:{imap}/' \
                 --login-options 'AUTH=OAUTHBEARER' --oauth2-bearer '{token}' \
                 --user '{email}:' --request 'LIST \"\" \"*\"'"
            ),
            expect: "INBOX",
        },
        OauthClient {
            name: "msmtp/submission-oauthbearer",
            script: format!(
                "printf 'Subject: m6\\r\\n\\r\\nhi\\r\\n' | \
                 msmtp --host={gw} --port={sub} --tls=on --tls-starttls=on --tls-certcheck=off \
                   --auth=oauthbearer --user='{email}' --passwordeval=\"printf '%s' '{token}'\" \
                   --from='{email}' --debug '{email}'"
            ),
            expect: "235",
        },
    ];

    let mut failures = Vec::new();
    for c in &clients {
        let out = toolbox.sh(&c.script).await;
        let combined = out.combined();
        if !combined.contains(c.expect) {
            failures.push(format!(
                "[{}] exit={} expect={:?}\n--- output ---\n{}\n--------------",
                c.name, out.code, c.expect, combined
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} OAuth mail clients failed:\n\n{}",
        failures.len(),
        clients.len(),
        failures.join("\n\n")
    );
}
