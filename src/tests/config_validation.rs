/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use crate::config::Config;

use super::harness::mapping_file;

fn mapping_block(path: &str) -> String {
    format!(
        r#"
[mapping]
source = "file"
[mapping.file]
path = "{path}"
"#
    )
}

#[test]
fn rejects_unknown_default_destination() {
    let m = mapping_file("");
    let toml = format!(
        r#"
{}
[routing]
default_destination = "ghost"

[destination.real]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.real.protocol.imap]
port = 143
tls = "plain"
"#,
        mapping_block(&m.path().display().to_string())
    );
    assert!(Config::parse_and_validate(&toml).is_err());
}

#[test]
fn rejects_plaintext_credential_destination_without_override() {
    let m = mapping_file("");
    let toml = format!(
        r#"
{}
[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
[destination.legacy.protocol.imap]
port = 143
tls = "plain"
"#,
        mapping_block(&m.path().display().to_string())
    );
    assert!(Config::parse_and_validate(&toml).is_err());
}

#[test]
fn rejects_ip_host_tls_without_server_name() {
    let m = mapping_file("");
    let toml = format!(
        r#"
{}
[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
[destination.legacy.protocol.imap]
port = 993
tls = "implicit"
"#,
        mapping_block(&m.path().display().to_string())
    );
    assert!(Config::parse_and_validate(&toml).is_err());
}

#[test]
fn rejects_smtp_listener_without_passthrough_destination() {
    let m = mapping_file("");
    let toml = format!(
        r#"
{}
[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"

[listener.smtp]
protocol = "smtp"
bind = ["127.0.0.1:25"]
tls = "plain"
"#,
        mapping_block(&m.path().display().to_string())
    );
    assert!(Config::parse_and_validate(&toml).is_err());
}

#[test]
fn rejects_listener_protocol_not_in_default_destination() {
    let m = mapping_file("");
    let toml = format!(
        r#"
{}
[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"

[listener.pop3]
protocol = "pop3"
bind = ["127.0.0.1:110"]
tls = "plain"
"#,
        mapping_block(&m.path().display().to_string())
    );
    assert!(Config::parse_and_validate(&toml).is_err());
}

fn passthrough_base(path: &str, extra: &str) -> String {
    format!(
        r#"
{}
[routing]
default_destination = "legacy"
smtp_passthrough_destination = "relay"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"

[destination.relay]
host = "127.0.0.1"
proxy_protocol = false
[destination.relay.protocol.imap]
port = 143
tls = "plain"

{extra}
"#,
        mapping_block(path)
    )
}

#[test]
fn rejects_passthrough_destination_missing_smtp() {
    let m = mapping_file("");
    let toml = passthrough_base(
        &m.path().display().to_string(),
        r#"
[listener.smtp]
protocol = "smtp"
bind = ["127.0.0.1:25"]
tls = "plain"
"#,
    );
    assert!(Config::parse_and_validate(&toml).is_err());
}

#[test]
fn rejects_starttls_passthrough_listener() {
    let m = mapping_file("");
    let toml = format!(
        r#"
{}
[routing]
default_destination = "legacy"
smtp_passthrough_destination = "relay"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"

[destination.relay]
host = "127.0.0.1"
proxy_protocol = false
[destination.relay.protocol.smtp]
port = 25
tls = "plain"

[listener.smtp]
protocol = "smtp"
bind = ["127.0.0.1:25"]
tls = "starttls"
"#,
        mapping_block(&m.path().display().to_string())
    );
    assert!(Config::parse_and_validate(&toml).is_err());
}

fn admin_base(path: &str, admin: &str) -> String {
    format!(
        r#"
{}
[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"

{admin}
"#,
        mapping_block(path)
    )
}

#[test]
fn rejects_admin_plaintext_tls() {
    let m = mapping_file("");
    let toml = admin_base(
        &m.path().display().to_string(),
        r#"
[admin]
bind = "127.0.0.1:9443"
tls = "plain"
bearer_token = "0123456789abcdef0123456789abcdef"
"#,
    );
    assert!(Config::parse_and_validate(&toml).is_err());
}

#[test]
fn rejects_admin_without_token_source() {
    let m = mapping_file("");
    let toml = admin_base(
        &m.path().display().to_string(),
        r#"
[admin]
bind = "127.0.0.1:9443"
tls = "implicit"
"#,
    );
    assert!(Config::parse_and_validate(&toml).is_err());
}

#[test]
fn rejects_http_route_extract_body_without_regex() {
    let m = mapping_file("");
    let toml = admin_base(
        &m.path().display().to_string(),
        r#"
[[http.route]]
match = "/auth"
extract = { from = "body" }
"#,
    );
    assert!(Config::parse_and_validate(&toml).is_err());
}

#[test]
fn rejects_mapping_source_redis_without_section() {
    let toml = r#"
[mapping]
source = "redis"

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"
"#;
    assert!(Config::parse_and_validate(toml).is_err());
}

#[test]
fn accepts_passthrough_with_smtp_declared() {
    let m = mapping_file("");
    let toml = format!(
        r#"
{}
[routing]
default_destination = "legacy"
smtp_passthrough_destination = "relay"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"

[destination.relay]
host = "127.0.0.1"
proxy_protocol = false
[destination.relay.protocol.smtp]
port = 25
tls = "plain"

[listener.smtp]
protocol = "smtp"
bind = ["127.0.0.1:25"]
tls = "plain"
"#,
        mapping_block(&m.path().display().to_string())
    );
    assert!(Config::parse_and_validate(&toml).is_ok());
}

#[test]
fn accepts_minimal_valid_config() {
    let m = mapping_file("");
    let toml = format!(
        r#"
{}
[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"

[listener.imap]
protocol = "imap"
bind = ["127.0.0.1:143"]
tls = "plain"

[capabilities.imap]
allow_plain_auth_without_tls = true
"#,
        mapping_block(&m.path().display().to_string())
    );
    assert!(Config::parse_and_validate(&toml).is_ok());
}

fn submission_config_with_sasl(mapping: &str, sasl: &str) -> String {
    format!(
        r#"
{}
[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.submission]
port = 587
tls = "plain"

[listener.submission]
protocol = "submission"
bind = ["127.0.0.1:587"]
tls = "plain"

[capabilities.submission]
allow_plain_auth_without_tls = true
sasl = {sasl}
"#,
        mapping_block(mapping)
    )
}

#[test]
fn default_sasl_set_includes_login() {
    let m = mapping_file("");
    let toml = format!(
        r#"
{}
[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.submission]
port = 587
tls = "plain"

[listener.submission]
protocol = "submission"
bind = ["127.0.0.1:587"]
tls = "plain"
"#,
        mapping_block(&m.path().display().to_string())
    );
    let config = Config::parse_and_validate(&toml).unwrap();
    for sasl in [
        &config.capabilities.submission.sasl,
        &config.capabilities.imap.sasl,
        &config.capabilities.pop3.sasl,
        &config.capabilities.managesieve.sasl,
    ] {
        assert!(
            sasl.iter().any(|m| m == "LOGIN"),
            "LOGIN missing from default sasl set {sasl:?}"
        );
    }
}

#[test]
fn accepts_login_in_sasl_and_canonicalizes_case() {
    let m = mapping_file("");
    let toml = submission_config_with_sasl(
        &m.path().display().to_string(),
        r#"["plain", "Login", "oauthbearer"]"#,
    );
    let config = Config::parse_and_validate(&toml).unwrap();
    assert_eq!(
        config.capabilities.submission.sasl,
        vec!["PLAIN", "LOGIN", "OAUTHBEARER"]
    );
}

#[test]
fn rejects_unsupported_sasl_mechanism() {
    let m = mapping_file("");
    let toml =
        submission_config_with_sasl(&m.path().display().to_string(), r#"["PLAIN", "CRAM-MD5"]"#);
    let err = Config::parse_and_validate(&toml).unwrap_err().to_string();
    assert!(
        err.contains("CRAM-MD5") && err.contains("capabilities.submission.sasl"),
        "unexpected error: {err}"
    );
}

#[test]
fn rejects_duplicate_sasl_mechanism() {
    let m = mapping_file("");
    let toml =
        submission_config_with_sasl(&m.path().display().to_string(), r#"["PLAIN", "plain"]"#);
    let err = Config::parse_and_validate(&toml).unwrap_err().to_string();
    assert!(err.contains("more than once"), "unexpected error: {err}");
}

#[test]
fn rejects_unsupported_sasl_mechanism_in_every_section() {
    let m = mapping_file("");
    for section in ["imap", "pop3", "managesieve"] {
        let toml = format!(
            r#"
{}
[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.imap]
port = 143
tls = "plain"

[listener.imap]
protocol = "imap"
bind = ["127.0.0.1:143"]
tls = "plain"

[capabilities.{section}]
sasl = ["NTLM"]
"#,
            mapping_block(&m.path().display().to_string())
        );
        let err = Config::parse_and_validate(&toml).unwrap_err().to_string();
        assert!(
            err.contains(&format!("capabilities.{section}.sasl")),
            "unexpected error for {section}: {err}"
        );
    }
}

fn http_fallback_config(mapping_path: &str, fallback: &str) -> String {
    format!(
        r#"
{}
[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.legacy.protocol.http]
port = 80
tls = "plain"

[destination.imaponly]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.imaponly.protocol.imap]
port = 143
tls = "plain"

[[http.route]]
match = "/**"
extract = {{ from = "authorization" }}
fallback = "{fallback}"
"#,
        mapping_block(mapping_path)
    )
}

#[test]
fn http_route_fallback_must_name_known_http_destination() {
    let m = mapping_file("");
    let path = m.path().display().to_string();
    assert!(Config::parse_and_validate(&http_fallback_config(&path, "legacy")).is_ok());
    assert!(Config::parse_and_validate(&http_fallback_config(&path, "ghost")).is_err());
    assert!(Config::parse_and_validate(&http_fallback_config(&path, "imaponly")).is_err());
}

fn install_script_config() -> &'static str {
    let script = include_str!("../../install.sh");
    let (_, rest) = script
        .split_once("write_config_file() {\n    cat > \"$1\" <<'EOF'\n")
        .expect("install.sh config heredoc start");
    let (config, _) = rest
        .split_once("\nEOF\n")
        .expect("install.sh config heredoc end");
    config
}

#[test]
fn shipped_configs_validate() {
    // every configuration shipped with the proxy passes boot validation
    for (name, raw) in [
        (
            "config.sample.toml",
            include_str!("../../resources/config.sample.toml"),
        ),
        (
            "config.stalwart-upgrade.toml",
            include_str!("../../resources/config.stalwart-upgrade.toml"),
        ),
        (
            "config.dovecot-postfix.toml",
            include_str!("../../resources/config.dovecot-postfix.toml"),
        ),
        ("install.sh", install_script_config()),
    ] {
        if let Err(e) = Config::parse_and_validate(raw) {
            panic!("{name} fails validation: {e}");
        }
    }
}
