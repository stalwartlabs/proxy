/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub const SCHEMA: &str = r##"{"sections": [
{"id": "server", "kind": "table", "label": "Server", "fields": [
  {"key": "threads", "type": "usize", "label": "Worker threads", "default": 0, "restart": true, "help": "0 uses one thread per CPU core"},
  {"key": "shutdown_grace", "type": "duration", "label": "Shutdown grace", "default": "30s", "help": "How long open connections may drain after a shutdown signal"},
  {"key": "bridge_idle", "type": "duration", "label": "Bridge idle timeout", "default": "30m"},
  {"key": "backend_timeout", "type": "duration", "label": "Backend timeout", "default": "10s", "help": "Connect, TLS and greeting deadline for the backend leg"},
  {"key": "backend_connect_retries", "type": "u32", "label": "Backend connect retries", "default": 1},
  {"key": "host_down_threshold", "type": "u32", "label": "Host down threshold", "default": 5, "help": "Consecutive failures before a destination is marked down"},
  {"key": "host_down_min_clients", "type": "u32", "label": "Host down minimum clients", "default": 2, "help": "Distinct clients a session-stage failure streak must span"},
  {"key": "host_down_cooldown", "type": "duration", "label": "Host down cooldown", "default": "30s"},
  {"key": "proxy_ttl", "type": "u32", "label": "Proxy TTL", "default": 7, "help": "Hop limit for XCLIENT loop protection"},
  {"key": "log_level", "type": "string", "label": "Log level", "default": "info", "restart": true},
  {"key": "hostname", "type": "string", "label": "Hostname", "help": "Name announced in greetings; defaults to the local address"}]},
{"id": "tls", "kind": "table", "label": "TLS", "fields": [
  {"key": "certificate", "type": "map", "label": "Certificates", "fields": [
    {"key": "cert", "type": "string", "required": true, "label": "Certificate file", "help": "PEM certificate chain"},
    {"key": "key", "type": "string", "required": true, "label": "Private key file", "help": "PEM private key"},
    {"key": "subjects", "type": "list", "item": "string", "label": "Subjects", "help": "SNI names served by this certificate; defaults to the names in the certificate"},
    {"key": "default", "type": "bool", "label": "Default certificate", "default": false}]},
  {"key": "protocols", "type": "table", "label": "Protocols", "fields": [
    {"key": "min_version", "type": "enum", "values": ["1.2", "1.3"], "label": "Minimum version", "default": "1.2"},
    {"key": "ignore_client_order", "type": "bool", "label": "Prefer server cipher order", "default": false},
    {"key": "disable_cipher_suites", "type": "list", "item": "string", "label": "Disabled cipher suites"}]},
  {"key": "allow_self_signed", "type": "bool", "label": "Allow self-signed fallback", "default": false, "help": "Serve a generated self-signed certificate when no configured certificate applies"}]},
{"id": "listener", "kind": "map", "label": "Listeners", "fields": [
  {"key": "protocol", "type": "enum", "values": ["smtp", "submission", "lmtp", "imap", "pop3", "managesieve", "http"], "required": true, "label": "Protocol"},
  {"key": "bind", "type": "list", "item": "socket_addr", "required": true, "label": "Bind addresses"},
  {"key": "tls", "type": "enum", "values": ["implicit", "starttls", "plain"], "required": true, "label": "TLS mode"},
  {"key": "proxy_protocol", "type": "enum", "values": ["off", "optional", "required"], "label": "Inbound PROXY protocol", "default": "off"},
  {"key": "proxy_trusted", "type": "list", "item": "cidr", "label": "Trusted PROXY sources"},
  {"key": "max_connections", "type": "usize", "label": "Maximum connections", "default": 8192},
  {"key": "preauth_timeout", "type": "duration", "label": "Pre-auth timeout", "default": "30s"},
  {"key": "max_auth_attempts", "type": "u32", "label": "Maximum auth attempts", "default": 3},
  {"key": "forwarded", "type": "enum", "values": ["off", "trust"], "label": "Forwarded headers", "default": "off", "help": "HTTP only: trust Forwarded and X-Forwarded-For from the client"}]},
{"id": "destination", "kind": "map", "label": "Destinations", "fields": [
  {"key": "host", "type": "string", "required": true, "label": "Host", "help": "Hostname or IP of the backend"},
  {"key": "tls_server_name", "type": "string", "label": "TLS server name", "help": "Required when host is an IP and any endpoint uses TLS"},
  {"key": "proxy_protocol", "type": "bool", "label": "PROXY protocol", "default": true},
  {"key": "forwarding", "type": "enum", "values": ["proxy", "xclient", "none"], "label": "Client forwarding", "help": "Inferred from proxy_protocol when unset"},
  {"key": "forwarded", "type": "bool", "label": "Forwarded header", "default": false, "help": "HTTP only: append Forwarded and X-Forwarded-For"},
  {"key": "tls_allow_invalid_certs", "type": "bool", "label": "Allow invalid certificates", "default": false},
  {"key": "tls_pinned_cert_sha256", "type": "string", "label": "Pinned certificate SHA-256"},
  {"key": "tls_client_cert", "type": "string", "label": "Client certificate file"},
  {"key": "tls_client_key", "type": "string", "label": "Client key file"},
  {"key": "source_ips", "type": "list", "item": "ip", "label": "Source addresses"},
  {"key": "dns_cache_ttl", "type": "duration", "label": "DNS cache TTL"},
  {"key": "hide_auth_errors", "type": "bool", "label": "Hide auth errors", "default": false},
  {"key": "allow_plaintext_auth", "type": "bool", "label": "Allow plaintext auth", "default": false, "help": "Allow credentials over an unencrypted backend leg"},
  {"key": "protocol", "type": "map", "label": "Endpoints", "key_enum": ["smtp", "submission", "lmtp", "imap", "pop3", "managesieve", "http"], "fields": [
    {"key": "port", "type": "u16", "required": true, "label": "Port"},
    {"key": "tls", "type": "enum", "values": ["implicit", "starttls", "plain"], "required": true, "label": "TLS mode"},
    {"key": "forwarding", "type": "enum", "values": ["proxy", "xclient", "none"], "label": "Client forwarding"}]}]},
{"id": "routing", "kind": "table", "label": "Routing", "fields": [
  {"key": "default_destination", "type": "string", "required": true, "label": "Default destination"},
  {"key": "smtp_passthrough_destination", "type": "string", "label": "SMTP/LMTP pass-through destination"},
  {"key": "master_user_separators", "type": "list", "item": "string", "label": "Master user separators", "default": ["%"]}]},
{"id": "mapping", "kind": "table", "label": "Mapping", "fields": [
  {"key": "source", "type": "enum", "values": ["file", "redis", "sql"], "required": true, "label": "Source"},
  {"key": "normalize", "type": "enum", "values": ["none", "lowercase"], "label": "Normalize", "default": "none"},
  {"key": "negative_ttl", "type": "duration", "label": "Negative TTL", "default": "30s"},
  {"key": "positive_ttl", "type": "duration", "label": "Positive TTL", "default": "10m"},
  {"key": "cache_max_entries", "type": "u64", "label": "Cache entries", "default": 1000000},
  {"key": "cache_max_bytes", "type": "u64", "label": "Cache byte budget", "help": "When set, bounds the cache by approximate bytes instead of entries"},
  {"key": "lookup_timeout", "type": "duration", "label": "Lookup timeout", "default": "5s"},
  {"key": "file", "type": "table", "label": "File", "fields": [
    {"key": "path", "type": "string", "required": true, "label": "Path"}]},
  {"key": "redis", "type": "table", "label": "Redis", "fields": [
    {"key": "url", "type": "secret", "required": true, "label": "URL", "secret": true},
    {"key": "key_prefix", "type": "string", "label": "Key prefix", "default": "route:"},
    {"key": "pool_size", "type": "usize", "label": "Pool size", "default": 16}]},
  {"key": "sql", "type": "table", "label": "SQL", "fields": [
    {"key": "url", "type": "secret", "required": true, "label": "URL", "secret": true},
    {"key": "query", "type": "string", "required": true, "label": "Lookup query"},
    {"key": "pool_size", "type": "usize", "label": "Pool size", "default": 16},
    {"key": "upsert_query", "type": "string", "label": "Upsert query"},
    {"key": "delete_query", "type": "string", "label": "Delete query"},
    {"key": "list_query", "type": "string", "label": "List query"},
    {"key": "count_query", "type": "string", "label": "Count query"}]}]},
{"id": "capabilities", "kind": "table", "label": "Capabilities", "fields": [
  {"key": "imap", "type": "table", "label": "IMAP", "fields": [
    {"key": "advertise", "type": "list", "item": "string", "label": "Advertised capabilities"},
    {"key": "sasl", "type": "list", "item": "enum", "values": ["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"], "label": "SASL mechanisms", "default": ["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"]},
    {"key": "allow_plain_auth_without_tls", "type": "bool", "label": "Allow plain auth without TLS", "default": false},
    {"key": "banner", "type": "string", "label": "Banner", "default": "Stalwart IMAP4rev2 at your service."}]},
  {"key": "managesieve", "type": "table", "label": "ManageSieve", "fields": [
    {"key": "sieve", "type": "list", "item": "string", "label": "Sieve extensions"},
    {"key": "sasl", "type": "list", "item": "enum", "values": ["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"], "label": "SASL mechanisms", "default": ["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"]},
    {"key": "allow_plain_auth_without_tls", "type": "bool", "label": "Allow plain auth without TLS", "default": false},
    {"key": "implementation", "type": "string", "label": "Implementation", "default": "Stalwart ManageSieve"}]},
  {"key": "submission", "type": "table", "label": "Submission", "fields": [
    {"key": "ehlo", "type": "list", "item": "string", "label": "EHLO extensions"},
    {"key": "sasl", "type": "list", "item": "enum", "values": ["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"], "label": "SASL mechanisms", "default": ["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"]},
    {"key": "allow_plain_auth_without_tls", "type": "bool", "label": "Allow plain auth without TLS", "default": false},
    {"key": "banner", "type": "string", "label": "Banner", "default": "at your service."}]},
  {"key": "pop3", "type": "table", "label": "POP3", "fields": [
    {"key": "sasl", "type": "list", "item": "enum", "values": ["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"], "label": "SASL mechanisms", "default": ["PLAIN", "LOGIN", "OAUTHBEARER", "XOAUTH2"]},
    {"key": "allow_plain_auth_without_tls", "type": "bool", "label": "Allow plain auth without TLS", "default": false},
    {"key": "banner", "type": "string", "label": "Banner", "default": "Stalwart POP3 at your service."}]}]},
{"id": "oauth", "kind": "table", "label": "OAuth", "fields": [
  {"key": "jwt_username_claim", "type": "string", "label": "JWT username claim", "default": "email"}]},
{"id": "http", "kind": "table", "label": "HTTP", "fields": [
  {"key": "route", "type": "list", "item": "table", "label": "Routes", "fields": [
    {"key": "match", "type": "string", "required": true, "label": "Path glob"},
    {"key": "destination", "type": "string", "label": "Destination"},
    {"key": "extract", "type": "table", "label": "Extract identifier", "fields": [
      {"key": "from", "type": "enum", "values": ["authorization", "query", "body", "header"], "required": true, "label": "From"},
      {"key": "regex", "type": "string", "label": "Regex"},
      {"key": "param", "type": "string", "label": "Parameter"},
      {"key": "header", "type": "string", "label": "Header"}]},
    {"key": "fallback", "type": "string", "label": "Fallback destination"}]},
  {"key": "body_extract_cap", "type": "usize", "label": "Body extract cap", "default": 65536},
  {"key": "max_head_size", "type": "usize", "label": "Maximum head size", "default": 65536},
  {"key": "relay_idle", "type": "duration", "label": "Relay idle timeout", "default": "1m"},
  {"key": "keepalive_timeout", "type": "duration", "label": "Keep-alive timeout", "default": "75s"},
  {"key": "max_keepalive_requests", "type": "u32", "label": "Keep-alive requests", "default": 1000}]},
{"id": "admin", "kind": "table", "label": "Admin", "readonly": true, "fields": [
  {"key": "bind", "type": "socket_addr", "required": true, "label": "Bind address", "restart": true},
  {"key": "tls", "type": "enum", "values": ["implicit"], "label": "TLS mode", "default": "implicit"},
  {"key": "bearer_token_file", "type": "string", "label": "Bearer token file"},
  {"key": "bearer_token", "type": "secret", "label": "Bearer token", "secret": true},
  {"key": "min_token_len", "type": "usize", "label": "Minimum token length", "default": 32},
  {"key": "lockout_threshold", "type": "u32", "label": "Lockout threshold", "default": 5},
  {"key": "lockout_duration", "type": "duration", "label": "Lockout duration", "default": "5m"},
  {"key": "config_write", "type": "bool", "label": "Allow config writes", "default": false},
  {"key": "max_body_size", "type": "usize", "label": "Maximum body size", "default": 1048576},
  {"key": "session_idle_timeout", "type": "duration", "label": "Session idle timeout", "default": "30m"},
  {"key": "session_lifetime", "type": "duration", "label": "Session lifetime", "default": "12h"},
  {"key": "allow", "type": "table", "label": "Operator allowlist", "help": "Limits what configuration edits may bind and reach; an empty list allows anything", "fields": [
    {"key": "listener_addresses", "type": "list", "item": "cidr", "label": "Listener addresses", "help": "Networks that listener bind addresses must fall in"},
    {"key": "listener_ports", "type": "list", "item": "port_range", "label": "Listener ports"},
    {"key": "destination_hosts", "type": "list", "item": "string", "label": "Destination hosts", "help": "CIDR networks, host names or *.suffix patterns; host names outside them are checked by address at connect time"},
    {"key": "destination_ports", "type": "list", "item": "port_range", "label": "Destination ports"}]}]}
]}"##;

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/config/schema/tests.rs"]
mod tests;
