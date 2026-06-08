/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use globset::{Glob, GlobSet, GlobSetBuilder};
use regex::Regex;

use crate::config::{ExtractFrom, HttpConfig, HttpExtract, HttpRoute};
use crate::error::{ProxyError, Result};
use crate::http::head::Head;
use crate::token::bearer_identifier;

pub enum RouteOutcome {
    Pin {
        dest_id: String,
    },
    Identifier {
        identifier: Option<String>,
        fallback: Option<String>,
    },
}

struct CompiledExtract {
    from: ExtractFrom,
    regex: Option<Regex>,
    param: Option<String>,
    header: Option<String>,
}

struct CompiledRoute {
    destination: Option<String>,
    extract: Option<CompiledExtract>,
    fallback: Option<String>,
    needs_body: bool,
}

pub struct HttpRouter {
    set: GlobSet,
    routes: Vec<CompiledRoute>,
    jwt_username_claim: String,
    pub body_extract_cap: usize,
    pub max_head_size: usize,
    pub relay_idle: Duration,
    pub keepalive_timeout: Duration,
    pub max_keepalive_requests: u32,
}

impl HttpRouter {
    pub fn build(http: &HttpConfig, jwt_username_claim: String) -> Result<Self> {
        let mut builder = GlobSetBuilder::new();
        let mut routes = Vec::with_capacity(http.route.len());
        for route in &http.route {
            builder.add(
                Glob::new(&route.match_glob)
                    .map_err(|e| ProxyError::config(format!("invalid http route glob: {e}")))?,
            );
            routes.push(compile_route(route)?);
        }
        let set = builder
            .build()
            .map_err(|e| ProxyError::config(format!("invalid http route set: {e}")))?;
        Ok(HttpRouter {
            set,
            routes,
            jwt_username_claim,
            body_extract_cap: http.body_extract_cap,
            max_head_size: http.max_head_size,
            relay_idle: http.relay_idle,
            keepalive_timeout: http.keepalive_timeout,
            max_keepalive_requests: http.max_keepalive_requests,
        })
    }

    pub fn match_index(&self, head: &Head) -> Option<usize> {
        let path = head.path();
        let raw = self.set.matches(path).into_iter().min();
        let trimmed = path.trim_end_matches('/');
        let normalized = if trimmed.len() != path.len() && !trimmed.is_empty() {
            self.set.matches(trimmed).into_iter().min()
        } else {
            None
        };
        match (raw, normalized) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn needs_body_at(&self, idx: usize) -> bool {
        self.routes[idx].needs_body
    }

    pub fn route_at(&self, idx: usize, head: &Head, body: Option<&[u8]>) -> RouteOutcome {
        let route = &self.routes[idx];
        if let Some(dest) = &route.destination {
            return RouteOutcome::Pin {
                dest_id: dest.clone(),
            };
        }
        let identifier = match &route.extract {
            Some(extract) => self.extract(extract, head, body),
            None => None,
        };
        RouteOutcome::Identifier {
            identifier,
            fallback: route.fallback.clone(),
        }
    }

    fn extract(
        &self,
        extract: &CompiledExtract,
        head: &Head,
        body: Option<&[u8]>,
    ) -> Option<String> {
        match extract.from {
            ExtractFrom::Authorization => self.extract_authorization(head),
            ExtractFrom::Query => {
                let param = extract.param.as_deref()?;
                let query = head.query()?;
                query_param(query, param)
            }
            ExtractFrom::Body => {
                let re = extract.regex.as_ref()?;
                let body = body?;
                let text = std::str::from_utf8(body).ok()?;
                let caps = re.captures(text)?;
                let raw = caps.get(1)?.as_str();
                Some(form_decode(raw))
            }
            ExtractFrom::Header => {
                let name = extract.header.as_deref()?;
                head.header(name).map(|v| v.to_string())
            }
        }
    }

    fn extract_authorization(&self, head: &Head) -> Option<String> {
        let value = head.header("authorization")?;
        let value = value.trim();
        if let Some(rest) = strip_scheme(value, "basic") {
            let decoded = BASE64.decode(rest.trim()).ok()?;
            let text = String::from_utf8(decoded).ok()?;
            let login = match text.split_once(':') {
                Some((login, _)) => login,
                None => text.as_str(),
            };
            return Some(login.trim().to_lowercase());
        }
        if let Some(rest) = strip_scheme(value, "bearer") {
            return bearer_identifier(rest.trim(), &self.jwt_username_claim);
        }
        None
    }
}

fn strip_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    if value.len() < scheme.len() + 1 {
        return None;
    }
    let (head, rest) = value.split_at(scheme.len());
    if head.eq_ignore_ascii_case(scheme) && rest.starts_with(' ') {
        Some(&rest[1..])
    } else {
        None
    }
}

fn compile_route(route: &HttpRoute) -> Result<CompiledRoute> {
    let extract = match &route.extract {
        Some(e) => Some(compile_extract(e)?),
        None => None,
    };
    let needs_body = matches!(
        &route.extract,
        Some(HttpExtract {
            from: ExtractFrom::Body,
            ..
        })
    );
    Ok(CompiledRoute {
        destination: route.destination.clone(),
        extract,
        fallback: route.fallback.clone(),
        needs_body,
    })
}

fn compile_extract(extract: &HttpExtract) -> Result<CompiledExtract> {
    let regex = match &extract.regex {
        Some(re) => Some(
            Regex::new(re)
                .map_err(|e| ProxyError::config(format!("invalid http extract regex: {e}")))?,
        ),
        None => None,
    };
    Ok(CompiledExtract {
        from: extract.from,
        regex,
        param: extract.param.clone(),
        header: extract.header.clone(),
    })
}

fn query_param(query: &str, param: &str) -> Option<String> {
    for pair in query.split('&') {
        let (key, value) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if form_decode(key) == param {
            return Some(form_decode(value));
        }
    }
    None
}

fn form_decode(input: &str) -> String {
    let replaced = input.replace('+', " ");
    percent_encoding::percent_decode_str(&replaced)
        .decode_utf8_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HttpConfig;
    use crate::http::head::{Head, ParseOutcome};

    fn parse(buf: &[u8]) -> Head {
        match Head::parse(buf, 64 * 1024).unwrap() {
            ParseOutcome::Done { head, .. } => head,
            _ => panic!("need more"),
        }
    }

    fn route(router: &HttpRouter, head: &Head, body: Option<&[u8]>) -> RouteOutcome {
        let idx = router.match_index(head).expect("route should match");
        router.route_at(idx, head, body)
    }

    fn router_from_toml(toml: &str) -> HttpRouter {
        let http: HttpConfig = toml::from_str(toml).unwrap();
        HttpRouter::build(&http, "email".to_string()).unwrap()
    }

    #[test]
    fn glob_first_match_wins() {
        let router = router_from_toml(
            r#"
[[route]]
match = "/.well-known/**"
destination = "legacy"
[[route]]
match = "/**"
destination = "other"
"#,
        );
        let head = parse(b"GET /.well-known/jmap HTTP/1.1\r\nHost: x\r\n\r\n");
        match route(&router, &head, None) {
            RouteOutcome::Pin { dest_id } => assert_eq!(dest_id, "legacy"),
            _ => panic!("expected pin"),
        }
        let head = parse(b"GET /other/path HTTP/1.1\r\nHost: x\r\n\r\n");
        match route(&router, &head, None) {
            RouteOutcome::Pin { dest_id } => assert_eq!(dest_id, "other"),
            _ => panic!("expected pin"),
        }
    }

    #[test]
    fn trailing_slash_matches_specific_route_over_catchall() {
        let router = router_from_toml(
            r#"
[[route]]
match = "/api"
destination = "legacy"
[[route]]
match = "/**"
destination = "other"
"#,
        );
        let head = parse(b"GET /api/ HTTP/1.1\r\nHost: x\r\n\r\n");
        match route(&router, &head, None) {
            RouteOutcome::Pin { dest_id } => assert_eq!(dest_id, "legacy"),
            _ => panic!("expected pin"),
        }
        assert_eq!(head.path(), "/api/");
    }

    #[test]
    fn root_path_not_emptied_by_trim() {
        let router = router_from_toml(
            r#"
[[route]]
match = "/"
destination = "legacy"
"#,
        );
        let head = parse(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        match route(&router, &head, None) {
            RouteOutcome::Pin { dest_id } => assert_eq!(dest_id, "legacy"),
            _ => panic!("expected pin"),
        }
    }

    #[test]
    fn static_pin_vs_identifier() {
        let router = router_from_toml(
            r#"
[[route]]
match = "/static"
destination = "legacy"
[[route]]
match = "/**"
extract = { from = "authorization" }
fallback = "default"
"#,
        );
        let head = parse(b"GET /static HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(matches!(
            route(&router, &head, None),
            RouteOutcome::Pin { .. }
        ));
        let head = parse(b"GET /dyn HTTP/1.1\r\nHost: x\r\n\r\n");
        match route(&router, &head, None) {
            RouteOutcome::Identifier { fallback, .. } => {
                assert_eq!(fallback.as_deref(), Some("default"));
            }
            _ => panic!("expected identifier"),
        }
    }

    #[test]
    fn basic_auth_lowercased() {
        let router = router_from_toml(
            r#"
[[route]]
match = "/**"
extract = { from = "authorization" }
"#,
        );
        let creds = BASE64.encode("Alice@Example.COM:secret");
        let req = format!("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {creds}\r\n\r\n");
        let head = parse(req.as_bytes());
        match route(&router, &head, None) {
            RouteOutcome::Identifier { identifier, .. } => {
                assert_eq!(identifier.as_deref(), Some("alice@example.com"));
            }
            _ => panic!("expected identifier"),
        }
    }

    #[test]
    fn bearer_uses_bearer_identifier() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let router = router_from_toml(
            r#"
[[route]]
match = "/**"
extract = { from = "authorization" }
"#,
        );
        let claims = URL_SAFE_NO_PAD.encode(r#"{"email":"bob@example.com"}"#);
        let token = format!("hdr.{claims}.sig");
        let req = format!("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\r\n");
        let head = parse(req.as_bytes());
        match route(&router, &head, None) {
            RouteOutcome::Identifier { identifier, .. } => {
                assert_eq!(identifier.as_deref(), Some("bob@example.com"));
            }
            _ => panic!("expected identifier"),
        }
    }

    #[test]
    fn query_param_url_decoded() {
        let router = router_from_toml(
            r#"
[[route]]
match = "/oauth/**"
extract = { from = "query", param = "login_hint" }
"#,
        );
        let head = parse(
            b"GET /oauth/authorize?login_hint=user%40example.com&x=1 HTTP/1.1\r\nHost: x\r\n\r\n",
        );
        match route(&router, &head, None) {
            RouteOutcome::Identifier { identifier, .. } => {
                assert_eq!(identifier.as_deref(), Some("user@example.com"));
            }
            _ => panic!("expected identifier"),
        }
    }

    #[test]
    fn body_regex_capture() {
        let router = router_from_toml(
            r#"
[[route]]
match = "/auth/token"
extract = { from = "body", regex = "username=([^&]+)" }
"#,
        );
        let head = parse(b"POST /auth/token HTTP/1.1\r\nHost: x\r\nContent-Length: 30\r\n\r\n");
        assert!(router.needs_body_at(router.match_index(&head).unwrap()));
        let body = b"grant=x&username=joe%40corp.com";
        match route(&router, &head, Some(body)) {
            RouteOutcome::Identifier { identifier, .. } => {
                assert_eq!(identifier.as_deref(), Some("joe@corp.com"));
            }
            _ => panic!("expected identifier"),
        }
    }

    #[test]
    fn header_extraction() {
        let router = router_from_toml(
            r#"
[[route]]
match = "/**"
extract = { from = "header", header = "X-User" }
"#,
        );
        let head = parse(b"GET / HTTP/1.1\r\nHost: x\r\nX-User: someone\r\n\r\n");
        match route(&router, &head, None) {
            RouteOutcome::Identifier { identifier, .. } => {
                assert_eq!(identifier.as_deref(), Some("someone"));
            }
            _ => panic!("expected identifier"),
        }
    }
}
