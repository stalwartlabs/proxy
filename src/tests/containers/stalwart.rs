/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use serde_json::{Value, json};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::http::{self, basic_auth};
use super::pick_free_port;

pub const NEW_IMAGE: &str = "stalwartlabs/stalwart";
pub const NEW_TAG: &str = "latest";
pub const OLD_IMAGE: &str = "stalwartlabs/stalwart";
pub const OLD_TAG: &str = "v0.15.5";

const CONFIG_JSON: &str = r#"{"@type":"RocksDb","blobSize":16834,"bufferSize":134217728,"path":"/var/lib/stalwart","poolWorkers":null}"#;

const ADMIN_USER: &str = "admin";
const ADMIN_PASSWORD: &str = "admin";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Edition {
    New,
    Old,
}

#[derive(Clone, Debug)]
pub struct Account {
    pub login: String,
    pub password: String,
    pub token: String,
}

pub struct Stalwart {
    _container: ContainerAsync<GenericImage>,
    pub host: String,
    pub https: u16,
    pub imap: u16,
    pub imaps: u16,
    pub pop3: u16,
    pub pop3s: u16,
    pub submission: u16,
    pub smtps: u16,
    pub sieve: u16,
    pub smtp: u16,
    pub accounts: Vec<Account>,
}

impl Stalwart {
    pub async fn start(edition: Edition, domain: &str, users: &[(&str, &str)]) -> Stalwart {
        Self::start_inner(edition, domain, users, false, None).await
    }

    pub async fn start_proxied(edition: Edition, domain: &str, users: &[(&str, &str)]) -> Stalwart {
        Self::start_inner(edition, domain, users, true, None).await
    }

    pub async fn start_fronted(
        edition: Edition,
        domain: &str,
        users: &[(&str, &str)],
        public_url: &str,
    ) -> Stalwart {
        Self::start_inner(edition, domain, users, false, Some(public_url.to_string())).await
    }

    async fn start_inner(
        edition: Edition,
        domain: &str,
        users: &[(&str, &str)],
        proxy_trust: bool,
        public_url: Option<String>,
    ) -> Stalwart {
        match edition {
            Edition::New => Self::start_new(domain, users, proxy_trust, public_url).await,
            Edition::Old => Self::start_old(domain, users, proxy_trust, public_url).await,
        }
    }

    async fn start_new(
        domain: &str,
        users: &[(&str, &str)],
        proxy_trust: bool,
        public_url: Option<String>,
    ) -> Stalwart {
        let ports = Ports::pick();
        let container = GenericImage::new(NEW_IMAGE, NEW_TAG)
            .with_wait_for(WaitFor::seconds(3))
            .with_env_var(
                "STALWART_PUBLIC_URL",
                public_url
                    .clone()
                    .unwrap_or_else(|| format!("https://127.0.0.1:{}", ports.https)),
            )
            .with_env_var(
                "STALWART_RECOVERY_ADMIN",
                format!("{ADMIN_USER}:{ADMIN_PASSWORD}"),
            )
            .with_copy_to("/etc/stalwart/config.json", CONFIG_JSON.as_bytes().to_vec())
            .with_mapped_port(ports.https, 443u16.tcp())
            .with_mapped_port(ports.http, 8080u16.tcp())
            .with_mapped_port(ports.imap, 143u16.tcp())
            .with_mapped_port(ports.imaps, 993u16.tcp())
            .with_mapped_port(ports.pop3, 110u16.tcp())
            .with_mapped_port(ports.pop3s, 995u16.tcp())
            .with_mapped_port(ports.submission, 587u16.tcp())
            .with_mapped_port(ports.smtps, 465u16.tcp())
            .with_mapped_port(ports.sieve, 4190u16.tcp())
            .with_mapped_port(ports.smtp, 25u16.tcp())
            .with_startup_timeout(Duration::from_secs(180))
            .start()
            .await
            .expect("start new stalwart");

        let host = container.get_host().await.expect("host").to_string();
        wait_jmap_ready(&host, ports.https).await;

        let admin = basic_auth(ADMIN_USER, ADMIN_PASSWORD);
        let (api_path, admin_account) = jmap_session(&host, ports.https, &admin).await;
        let domain_id = create_domain_new(
            &host,
            ports.https,
            &api_path,
            &admin,
            &admin_account,
            domain,
        )
        .await;
        let mut accounts = Vec::new();
        for (name, password) in users {
            create_account_new(
                &host,
                ports.https,
                &api_path,
                &admin,
                &admin_account,
                &domain_id,
                (name, password),
            )
            .await;
            accounts.push(Account {
                login: format!("{name}@{domain}"),
                password: password.to_string(),
                token: String::new(),
            });
        }
        invalidate_caches_new(&host, ports.https, &api_path, &admin, &admin_account).await;
        configure_listeners(
            &host,
            ports.https,
            &api_path,
            &admin,
            &admin_account,
            proxy_trust,
        )
        .await;

        container
            .stop_with_timeout(Some(10))
            .await
            .expect("stop for restart");
        container.start().await.expect("restart");
        wait_jmap_ready(&host, ports.https).await;

        for account in &mut accounts {
            account.token =
                mint_token_new(&host, ports.https, &account.login, &account.password).await;
        }

        Self::assemble(container, host, ports, accounts)
    }

    async fn start_old(
        domain: &str,
        users: &[(&str, &str)],
        proxy_trust: bool,
        public_url: Option<String>,
    ) -> Stalwart {
        let ports = Ports::pick();
        let container = GenericImage::new(OLD_IMAGE, OLD_TAG)
            .with_wait_for(WaitFor::seconds(3))
            .with_mapped_port(ports.https, 443u16.tcp())
            .with_mapped_port(ports.http, 8080u16.tcp())
            .with_mapped_port(ports.imap, 143u16.tcp())
            .with_mapped_port(ports.imaps, 993u16.tcp())
            .with_mapped_port(ports.pop3, 110u16.tcp())
            .with_mapped_port(ports.pop3s, 995u16.tcp())
            .with_mapped_port(ports.submission, 587u16.tcp())
            .with_mapped_port(ports.smtps, 465u16.tcp())
            .with_mapped_port(ports.sieve, 4190u16.tcp())
            .with_mapped_port(ports.smtp, 25u16.tcp())
            .with_startup_timeout(Duration::from_secs(180))
            .start()
            .await
            .expect("start old stalwart");

        let host = container.get_host().await.expect("host").to_string();
        let http = ports.http;
        let admin_password = scrape_admin_password(&container).await;
        wait_old_api_ready(&host, http).await;

        if proxy_trust || public_url.is_some() {
            let admin = format!(
                "Bearer {}",
                mint_token_old(&host, http, ADMIN_USER, &admin_password).await
            );
            if proxy_trust {
                set_old_proxy_trust(&host, http, &admin).await;
            }
            if let Some(url) = &public_url {
                set_old_setting(&host, http, &admin, "http.url", &format!("'{url}'")).await;
            }
            container
                .stop_with_timeout(Some(10))
                .await
                .expect("stop for restart");
            container.start().await.expect("restart");
            wait_old_api_ready(&host, http).await;
        }

        let admin = format!(
            "Bearer {}",
            mint_token_old(&host, http, ADMIN_USER, &admin_password).await
        );
        create_principal_old(&host, http, &admin, json!({"type":"domain","name":domain})).await;
        let mut accounts = Vec::new();
        for (name, password) in users {
            let secret = pwhash::sha512_crypt::hash(password).expect("sha512-crypt");
            create_principal_old(
                &host,
                http,
                &admin,
                json!({
                    "type":"individual","name":name,"secrets":[secret],
                    "emails":[format!("{name}@{domain}")],"roles":["user"]
                }),
            )
            .await;
            accounts.push(Account {
                login: name.to_string(),
                password: password.to_string(),
                token: String::new(),
            });
        }
        for account in &mut accounts {
            account.token = mint_token_old(&host, http, &account.login, &account.password).await;
        }

        Self::assemble(container, host, ports, accounts)
    }

    fn assemble(
        container: ContainerAsync<GenericImage>,
        host: String,
        ports: Ports,
        accounts: Vec<Account>,
    ) -> Stalwart {
        Stalwart {
            imap: ports.imap,
            imaps: ports.imaps,
            pop3: ports.pop3,
            pop3s: ports.pop3s,
            submission: ports.submission,
            smtps: ports.smtps,
            sieve: ports.sieve,
            smtp: ports.smtp,
            https: ports.https,
            host,
            accounts,
            _container: container,
        }
    }
}

struct Ports {
    https: u16,
    http: u16,
    imap: u16,
    imaps: u16,
    pop3: u16,
    pop3s: u16,
    submission: u16,
    smtps: u16,
    sieve: u16,
    smtp: u16,
}

impl Ports {
    fn pick() -> Ports {
        Ports {
            https: pick_free_port(),
            http: pick_free_port(),
            imap: pick_free_port(),
            imaps: pick_free_port(),
            pop3: pick_free_port(),
            pop3s: pick_free_port(),
            submission: pick_free_port(),
            smtps: pick_free_port(),
            sieve: pick_free_port(),
            smtp: pick_free_port(),
        }
    }
}

async fn wait_jmap_ready(host: &str, https: u16) {
    let admin = basic_auth(ADMIN_USER, ADMIN_PASSWORD);
    for _ in 0..240 {
        if let Ok(resp) = http::try_request(
            host,
            https,
            true,
            "GET",
            "/.well-known/jmap",
            &[("Authorization", &admin)],
            None,
        )
        .await
            && resp.status != 0
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("stalwart JMAP never became ready on {host}:{https}");
}

async fn jmap_session(host: &str, https: u16, admin: &str) -> (String, String) {
    let resp = http::get_follow(
        host,
        https,
        true,
        "/.well-known/jmap",
        &[("Authorization", admin)],
    )
    .await;
    let session = resp.json();
    let api_url = session["apiUrl"].as_str().expect("apiUrl").to_string();
    let api_path = path_of(&api_url);
    let admin_account = session["primaryAccounts"]
        .as_object()
        .and_then(|m| m.values().next())
        .and_then(|v| v.as_str())
        .expect("admin primary account")
        .to_string();
    (api_path, admin_account)
}

async fn jmap_call(host: &str, https: u16, api_path: &str, admin: &str, calls: Value) -> Value {
    let envelope = json!({
        "using":["urn:ietf:params:jmap:core","urn:stalwart:jmap"],
        "methodCalls": calls,
    });
    let body = serde_json::to_vec(&envelope).unwrap();
    let resp = http::request(
        host,
        https,
        true,
        "POST",
        api_path,
        &[
            ("Authorization", admin),
            ("Content-Type", "application/json"),
        ],
        Some(&body),
    )
    .await;
    assert_eq!(resp.status, 200, "jmap call failed: {}", resp.text());
    resp.json()
}

async fn create_domain_new(
    host: &str,
    https: u16,
    api_path: &str,
    admin: &str,
    account: &str,
    domain: &str,
) -> String {
    let resp = jmap_call(
        host,
        https,
        api_path,
        admin,
        json!([["x:Domain/set", {"accountId":account,"create":{"v":{"name":domain}}}, "c0"]]),
    )
    .await;
    resp["methodResponses"][0][1]["created"]["v"]["id"]
        .as_str()
        .unwrap_or_else(|| panic!("domain not created: {resp}"))
        .to_string()
}

async fn create_account_new(
    host: &str,
    https: u16,
    api_path: &str,
    admin: &str,
    account: &str,
    domain_id: &str,
    cred: (&str, &str),
) {
    let (name, password) = cred;
    let create = json!({
        "@type":"User","name":name,"domainId":domain_id,
        "credentials":{"0":{"@type":"Password","secret":password}},
        "encryptionAtRest":{"@type":"Disabled"},
        "permissions":{"@type":"Inherit"},
        "roles":{"@type":"User"},"locale":"en_US"
    });
    let resp = jmap_call(
        host,
        https,
        api_path,
        admin,
        json!([["x:Account/set", {"accountId":account,"create":{"a":create}}, "c0"]]),
    )
    .await;
    assert!(
        resp["methodResponses"][0][1]["created"]["a"].is_object(),
        "account {name} not created: {resp}"
    );
}

async fn invalidate_caches_new(host: &str, https: u16, api_path: &str, admin: &str, account: &str) {
    jmap_call(
        host,
        https,
        api_path,
        admin,
        json!([["x:Action/set", {"accountId":account,"create":{"c":{"@type":"InvalidateCaches"}}}, "c0"]]),
    )
    .await;
}

fn trust_map() -> serde_json::Map<String, Value> {
    let mut trust = serde_json::Map::new();
    for net in [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ] {
        trust.insert(net.to_string(), Value::Bool(true));
    }
    trust
}

async fn configure_listeners(
    host: &str,
    https: u16,
    api_path: &str,
    admin: &str,
    account: &str,
    proxy_trust: bool,
) {
    for (name, proto, port) in [
        ("imap-plain", "imap", 143),
        ("pop3-plain", "pop3", 110),
        ("submission-plain", "smtp", 587),
    ] {
        let mut bind = serde_json::Map::new();
        bind.insert(format!("0.0.0.0:{port}"), Value::Bool(true));
        let mut listener = serde_json::Map::new();
        listener.insert("name".into(), json!(name));
        listener.insert("bind".into(), Value::Object(bind));
        listener.insert("protocol".into(), json!(proto));
        listener.insert("tlsImplicit".into(), json!(false));
        listener.insert("useTls".into(), json!(true));
        if proxy_trust {
            listener.insert(
                "overrideProxyTrustedNetworks".into(),
                Value::Object(trust_map()),
            );
        }
        let resp = jmap_call(
            host,
            https,
            api_path,
            admin,
            json!([[
                "x:NetworkListener/set",
                {"accountId":account,"create":{"l":Value::Object(listener)}},
                "c0"
            ]]),
        )
        .await;
        assert!(
            resp["methodResponses"][0][1]["created"]["l"].is_object(),
            "listener {name} not created: {resp}"
        );
    }
    if proxy_trust {
        trust_existing_mail_listeners(host, https, api_path, admin, account).await;
    }
}

async fn trust_existing_mail_listeners(
    host: &str,
    https: u16,
    api_path: &str,
    admin: &str,
    account: &str,
) {
    let query = jmap_call(
        host,
        https,
        api_path,
        admin,
        json!([["x:NetworkListener/query", {"accountId":account}, "c0"]]),
    )
    .await;
    let ids: Vec<String> = query["methodResponses"][0][1]["ids"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let got = jmap_call(
        host,
        https,
        api_path,
        admin,
        json!([["x:NetworkListener/get", {"accountId":account,"ids":ids}, "c0"]]),
    )
    .await;
    let listeners = got["methodResponses"][0][1]["list"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    for listener in listeners {
        let id = listener["id"].as_str().unwrap_or_default();
        let protocol = listener["protocol"].as_str().unwrap_or_default();
        if id.is_empty() || protocol == "http" {
            continue;
        }
        let mut update = serde_json::Map::new();
        update.insert(
            id.to_string(),
            json!({"overrideProxyTrustedNetworks": trust_map()}),
        );
        jmap_call(
            host,
            https,
            api_path,
            admin,
            json!([["x:NetworkListener/set", {"accountId":account,"update":update}, "c0"]]),
        )
        .await;
    }
}

async fn mint_token_new(host: &str, https: u16, login: &str, password: &str) -> String {
    let login_body = serde_json::to_vec(&json!({
        "type":"authCode","accountName":login,"accountSecret":password,
        "clientId":"stalwart-webui","redirectUri":"https://localhost/oauth/callback"
    }))
    .unwrap();
    let resp = http::request(
        host,
        https,
        true,
        "POST",
        "/api/auth",
        &[("Content-Type", "application/json")],
        Some(&login_body),
    )
    .await;
    assert_eq!(
        resp.status,
        200,
        "new login failed for {login}: {}",
        resp.text()
    );
    let code = resp.json()["client_code"]
        .as_str()
        .expect("client_code")
        .to_string();
    let form = format!(
        "grant_type=authorization_code&code={code}&client_id=stalwart-webui&redirect_uri=https://localhost/oauth/callback"
    );
    let resp = http::request(
        host,
        https,
        true,
        "POST",
        "/auth/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(form.as_bytes()),
    )
    .await;
    assert_eq!(
        resp.status,
        200,
        "new token exchange failed: {}",
        resp.text()
    );
    resp.json()["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

async fn mint_token_old(host: &str, http_port: u16, login: &str, password: &str) -> String {
    let code_body = serde_json::to_vec(&json!({
        "type":"code","client_id":"webadmin","redirect_uri":"stalwart://auth","nonce":"proxytests0"
    }))
    .unwrap();
    let resp = http::request(
        host,
        http_port,
        false,
        "POST",
        "/api/oauth",
        &[
            ("Authorization", &basic_auth(login, password)),
            ("Content-Type", "application/json"),
        ],
        Some(&code_body),
    )
    .await;
    assert_eq!(
        resp.status,
        200,
        "old oauth code failed for {login}: {}",
        resp.text()
    );
    let code = resp.json()["data"]["code"]
        .as_str()
        .expect("code")
        .to_string();
    let form = format!(
        "grant_type=authorization_code&client_id=webadmin&code={code}&redirect_uri=stalwart://auth"
    );
    let resp = http::request(
        host,
        http_port,
        false,
        "POST",
        "/auth/token",
        &[("Content-Type", "application/x-www-form-urlencoded")],
        Some(form.as_bytes()),
    )
    .await;
    assert_eq!(
        resp.status,
        200,
        "old token exchange failed: {}",
        resp.text()
    );
    resp.json()["access_token"]
        .as_str()
        .expect("access_token")
        .to_string()
}

async fn wait_old_api_ready(host: &str, http_port: u16) {
    for _ in 0..240 {
        if let Ok(resp) = http::try_request(host, http_port, false, "GET", "/", &[], None).await
            && resp.status != 0
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("old stalwart API never became ready on {host}:{http_port}");
}

async fn set_old_proxy_trust(host: &str, http_port: u16, admin: &str) {
    let mail_listeners = [
        "smtp",
        "submission",
        "submissions",
        "imap",
        "imaptls",
        "pop3",
        "pop3s",
        "sieve",
    ];
    let nets = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ];
    let mut values: Vec<Value> = Vec::new();
    for id in mail_listeners {
        values.push(json!([
            format!("server.listener.{id}.proxy.override"),
            "true"
        ]));
        for (i, net) in nets.iter().enumerate() {
            values.push(json!([
                format!("server.listener.{id}.proxy.trusted-networks.{i}"),
                net
            ]));
        }
    }
    let body = serde_json::to_vec(&json!([{
        "type":"insert",
        "values": values,
        "assert_empty": false
    }]))
    .unwrap();
    let resp = http::request(
        host,
        http_port,
        false,
        "POST",
        "/api/settings",
        &[
            ("Authorization", admin),
            ("Content-Type", "application/json"),
        ],
        Some(&body),
    )
    .await;
    assert_eq!(
        resp.status,
        200,
        "old settings update failed: {}",
        resp.text()
    );
    http::request(
        host,
        http_port,
        false,
        "GET",
        "/api/reload",
        &[("Authorization", admin)],
        None,
    )
    .await;
}

async fn set_old_setting(host: &str, http_port: u16, admin: &str, key: &str, value: &str) {
    let body = serde_json::to_vec(&json!([{
        "type":"insert",
        "values": [[key, value]],
        "assert_empty": false
    }]))
    .unwrap();
    let resp = http::request(
        host,
        http_port,
        false,
        "POST",
        "/api/settings",
        &[
            ("Authorization", admin),
            ("Content-Type", "application/json"),
        ],
        Some(&body),
    )
    .await;
    assert_eq!(
        resp.status,
        200,
        "old setting {key} update failed: {}",
        resp.text()
    );
}

async fn create_principal_old(host: &str, http_port: u16, admin: &str, principal: Value) {
    let body = serde_json::to_vec(&principal).unwrap();
    let resp = http::request(
        host,
        http_port,
        false,
        "POST",
        "/api/principal",
        &[
            ("Authorization", admin),
            ("Content-Type", "application/json"),
        ],
        Some(&body),
    )
    .await;
    assert_eq!(
        resp.status,
        200,
        "old principal create failed: {}",
        resp.text()
    );
}

async fn scrape_admin_password(container: &ContainerAsync<GenericImage>) -> String {
    for _ in 0..120 {
        for raw in [
            container.stdout_to_vec().await.unwrap_or_default(),
            container.stderr_to_vec().await.unwrap_or_default(),
        ] {
            let text = String::from_utf8_lossy(&raw);
            if let Some(pw) = parse_admin_password(&text) {
                return pw;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("old stalwart never printed an administrator password");
}

fn parse_admin_password(logs: &str) -> Option<String> {
    let marker = "with password '";
    let start = logs.find(marker)? + marker.len();
    let rest = &logs[start..];
    let end = rest.find('\'')?;
    Some(rest[..end].to_string())
}

fn path_of(url: &str) -> String {
    match url.split_once("://") {
        Some((_scheme, rest)) => match rest.split_once('/') {
            Some((_authority, path)) => format!("/{path}"),
            None => "/".to_string(),
        },
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn imaps_auth(host: &str, port: u16, login: &str, password: &str) -> String {
        let tcp = tokio::net::TcpStream::connect((host, port)).await.unwrap();
        let mut stream = crate::tests::harness::tls_connect_client(tcp).await;
        let mut buf = [0u8; 512];
        let _ = stream.read(&mut buf).await.unwrap();
        let ir = base64::engine::general_purpose::STANDARD.encode(format!("\0{login}\0{password}"));
        stream
            .write_all(format!("a1 AUTHENTICATE PLAIN {ir}\r\n").as_bytes())
            .await
            .unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn new_stalwart_seeds_accounts_tokens_and_plaintext_ports() {
        let sw = Stalwart::start(Edition::New, "new.test", &[("carol", "CarolPass#2026")]).await;
        assert_eq!(sw.accounts.len(), 1);
        assert!(!sw.accounts[0].token.is_empty(), "token minted");
        assert!(
            sw.accounts[0].token.starts_with("sw1."),
            "0.16.8 must mint sw1. access tokens (got {:?}); HTTP Bearer routing depends on this",
            sw.accounts[0].token
        );

        let reply = imaps_auth(
            &sw.host,
            sw.imaps,
            &sw.accounts[0].login,
            &sw.accounts[0].password,
        )
        .await;
        assert!(reply.contains("a1 OK"), "IMAPS auth (email login): {reply}");

        let mut plain = tokio::net::TcpStream::connect((sw.host.as_str(), sw.imap))
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = plain.read(&mut buf).await.unwrap();
        assert!(
            buf[..n].windows(4).any(|w| w == b"* OK"),
            "plaintext IMAP 143 enabled: {:?}",
            String::from_utf8_lossy(&buf[..n])
        );
    }

    #[tokio::test]
    #[ignore = "requires Docker"]
    async fn old_stalwart_seeds_accounts_and_tokens() {
        let sw = Stalwart::start(Edition::Old, "old.test", &[("dave", "DavePass#2026")]).await;
        assert_eq!(sw.accounts.len(), 1);
        assert!(!sw.accounts[0].token.is_empty(), "token minted");
        assert_eq!(sw.accounts[0].login, "dave", "old login is the username");

        let reply = imaps_auth(
            &sw.host,
            sw.imaps,
            &sw.accounts[0].login,
            &sw.accounts[0].password,
        )
        .await;
        assert!(reply.contains("a1 OK"), "IMAPS auth (name login): {reply}");
    }
}
