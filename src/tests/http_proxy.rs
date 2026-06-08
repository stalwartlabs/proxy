/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use super::harness::*;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn split_host_port(hp: &str) -> (String, u16) {
    let (host, port) = hp.rsplit_once(':').unwrap();
    (host.to_string(), port.parse().unwrap())
}

fn static_http_config(host: &str, port: u16, mapping_path: &str) -> String {
    format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{mapping_path}"

[routing]
default_destination = "web"

[destination.web]
host = "{host}"
proxy_protocol = false
allow_plaintext_auth = true
[destination.web.protocol.http]
port = {port}
tls = "plain"

[[http.route]]
match = "/**"
destination = "web"

[listener.http]
protocol = "http"
bind = ["127.0.0.1:0"]
tls = "plain"
"#
    )
}

async fn read_req_head(sock: &mut tokio::net::TcpStream) {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];
    loop {
        if find(&buf, b"\r\n\r\n").is_some() {
            return;
        }
        let n = sock.read(&mut scratch).await.unwrap();
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

#[tokio::test]
async fn http_static_route_proxies_to_backend() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/inbox")
        .with_status(200)
        .with_body("hello")
        .create_async()
        .await;
    let (host, port) = split_host_port(&server.host_with_port());

    let mapping = mapping_file("");
    let toml = format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[routing]
default_destination = "web"

[destination.web]
host = "{host}"
proxy_protocol = false
allow_plaintext_auth = true
[destination.web.protocol.http]
port = {port}
tls = "plain"

[[http.route]]
match = "/**"
destination = "web"

[listener.http]
protocol = "http"
bind = ["127.0.0.1:0"]
tls = "plain"
"#,
        mapping.path().display()
    );
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40030".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(
        &mut client,
        b"GET /inbox HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"200").is_some(),
        "expected 200, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        find(&resp, b"hello").is_some(),
        "expected body hello, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    mock.assert_async().await;
    handler.abort();
}

#[tokio::test]
async fn http_client_connection_close_closes_after_response() {
    let (port, backend) = dummy_backend(|mut sock| async move {
        read_req_head(&mut sock).await;
        sock.write_all(
            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: /x\r\nContent-Length: 0\r\n\r\n",
        )
        .await
        .unwrap();
        let mut scratch = [0u8; 256];
        let _ = sock.read(&mut scratch).await;
    })
    .await;

    let mapping = mapping_file("");
    let toml = format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[routing]
default_destination = "web"

[destination.web]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.web.protocol.http]
port = {port}
tls = "plain"

[[http.route]]
match = "/**"
destination = "web"

[listener.http]
protocol = "http"
bind = ["127.0.0.1:0"]
tls = "plain"
"#,
        mapping.path().display()
    );
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40031".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(
        &mut client,
        b"GET /a HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), read_to_eof(&mut client))
        .await
        .expect("proxy must close the client leg on Connection: close, not hang");
    assert!(
        find(&resp, b"307").is_some(),
        "expected 307, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    backend.abort();
    handler.abort();
}

#[tokio::test]
async fn http_authorization_extract_routes_to_backend() {
    let mut server = mockito::Server::new_async().await;
    let mock = server
        .mock("GET", "/")
        .with_status(200)
        .with_body("ok")
        .create_async()
        .await;
    let (host, port) = split_host_port(&server.host_with_port());

    let mapping = mapping_file("user@example.com\tweb\n");
    let toml = format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[routing]
default_destination = "web"

[destination.web]
host = "{host}"
proxy_protocol = false
allow_plaintext_auth = true
[destination.web.protocol.http]
port = {port}
tls = "plain"

[[http.route]]
match = "/**"
extract = {{ from = "authorization" }}

[listener.http]
protocol = "http"
bind = ["127.0.0.1:0"]
tls = "plain"
"#,
        mapping.path().display()
    );
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40031".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    let creds = BASE64.encode("user@example.com:pw");
    let req = format!(
        "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {creds}\r\nConnection: close\r\n\r\n"
    );
    send(&mut client, req.as_bytes()).await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"200").is_some(),
        "expected 200, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    mock.assert_async().await;
    handler.abort();
}

#[tokio::test]
async fn http_rejects_cl_te_smuggling() {
    let mapping = mapping_file("");
    let toml = static_http_config("127.0.0.1", 1, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40040".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(
        &mut client,
        b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
    )
    .await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"400").is_some(),
        "CL+TE must be rejected with 400, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    handler.abort();
}

#[tokio::test]
async fn http_rejects_http_1_0() {
    let mapping = mapping_file("");
    let toml = static_http_config("127.0.0.1", 1, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40041".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(&mut client, b"GET / HTTP/1.0\r\nHost: x\r\n\r\n").await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"505").is_some(),
        "HTTP/1.0 must be rejected with 505, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    handler.abort();
}

#[tokio::test]
async fn http_no_body_304_with_content_length_keeps_connection_alive() {
    async fn backend(mut sock: tokio::net::TcpStream) {
        read_req_head(&mut sock).await;
        sock.write_all(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 100\r\nETag: \"x\"\r\n\r\n")
            .await
            .unwrap();
        read_req_head(&mut sock).await;
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    }

    let (port, backend) = dummy_backend(backend).await;
    let mapping = mapping_file("");
    let toml = static_http_config("127.0.0.1", port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40042".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(&mut client, b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let first = read_until(&mut client, b"\r\n\r\n").await;
    assert!(
        find(&first, b"304").is_some(),
        "expected 304, got {:?}",
        String::from_utf8_lossy(&first)
    );

    send(
        &mut client,
        b"GET /b HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
    )
    .await;
    let second = read_to_eof(&mut client).await;
    assert!(
        find(&second, b"200").is_some() && find(&second, b"ok").is_some(),
        "a 304 with a Content-Length must not consume a phantom body; second request hung. got {:?}",
        String::from_utf8_lossy(&second)
    );
    backend.abort();
    handler.abort();
}

#[tokio::test]
async fn http_misdirected_request_returns_421() {
    async fn backend_a(mut sock: tokio::net::TcpStream) {
        read_req_head(&mut sock).await;
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na")
            .await
            .unwrap();
        let mut scratch = [0u8; 64];
        let _ = sock.read(&mut scratch).await;
    }
    let (port_a, backend_a) = dummy_backend(backend_a).await;
    let host_a = "127.0.0.1".to_string();

    let server_b = mockito::Server::new_async().await;
    let (host_b, port_b) = split_host_port(&server_b.host_with_port());

    let mapping = mapping_file("alice@x\tweb_a\nbob@x\tweb_b\n");
    let toml = format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[routing]
default_destination = "web_a"

[destination.web_a]
host = "{host_a}"
proxy_protocol = false
allow_plaintext_auth = true
[destination.web_a.protocol.http]
port = {port_a}
tls = "plain"

[destination.web_b]
host = "{host_b}"
proxy_protocol = false
allow_plaintext_auth = true
[destination.web_b.protocol.http]
port = {port_b}
tls = "plain"

[[http.route]]
match = "/**"
extract = {{ from = "authorization" }}

[listener.http]
protocol = "http"
bind = ["127.0.0.1:0"]
tls = "plain"
"#,
        mapping.path().display()
    );
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40043".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    let creds_a = BASE64.encode("alice@x:pw");
    send(
        &mut client,
        format!("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {creds_a}\r\n\r\n").as_bytes(),
    )
    .await;
    let first = read_until(&mut client, b"\r\n\r\n").await;
    assert!(
        find(&first, b"200").is_some(),
        "first request should reach web_a, got {:?}",
        String::from_utf8_lossy(&first)
    );

    let creds_b = BASE64.encode("bob@x:pw");
    send(
        &mut client,
        format!("GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {creds_b}\r\n\r\n").as_bytes(),
    )
    .await;
    let second = read_to_eof(&mut client).await;
    assert!(
        find(&second, b"421").is_some(),
        "a request routing to a different backend must get 421, got {:?}",
        String::from_utf8_lossy(&second)
    );

    backend_a.abort();
    handler.abort();
}

async fn read_until_backend(sock: &mut tokio::net::TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];
    loop {
        if find(&buf, needle).is_some() {
            return buf;
        }
        let n = sock.read(&mut scratch).await.unwrap();
        if n == 0 {
            return buf;
        }
        buf.extend_from_slice(&scratch[..n]);
    }
}

#[tokio::test]
async fn http_websocket_upgrade_is_relayed_and_bridged() {
    async fn backend(mut sock: tokio::net::TcpStream) {
        read_req_head(&mut sock).await;
        sock.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
        )
        .await
        .unwrap();
        let mut scratch = [0u8; 64];
        let n = sock.read(&mut scratch).await.unwrap();
        assert_eq!(&scratch[..n], b"PING");
        sock.write_all(b"PONG").await.unwrap();
    }

    let (port, backend) = dummy_backend(backend).await;
    let mapping = mapping_file("");
    let toml = static_http_config("127.0.0.1", port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40060".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(
        &mut client,
        b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    )
    .await;

    let upgrade = read_until(&mut client, b"\r\n\r\n").await;
    assert!(
        find(&upgrade, b"101").is_some()
            && find(&upgrade, b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo=").is_some(),
        "expected verbatim 101 with the backend's accept, got {:?}",
        String::from_utf8_lossy(&upgrade)
    );

    send(&mut client, b"PING").await;
    let echo = read_until(&mut client, b"PONG").await;
    assert!(
        find(&echo, b"PONG").is_some(),
        "post-upgrade bytes must bridge raw, got {:?}",
        String::from_utf8_lossy(&echo)
    );

    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn http_websocket_declined_relayed_as_framed_response_not_bridged() {
    async fn backend(mut sock: tokio::net::TcpStream) {
        read_req_head(&mut sock).await;
        sock.write_all(
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\nConnection: close\r\n\r\ndenied!LEAK",
        )
        .await
        .unwrap();
    }

    let (port, backend) = dummy_backend(backend).await;
    let mapping = mapping_file("");
    let toml = static_http_config("127.0.0.1", port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40062".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(
        &mut client,
        b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    )
    .await;

    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), read_to_eof(&mut client))
        .await
        .expect("a declined upgrade must be relayed and the client leg closed, not bridged");
    assert!(
        find(&resp, b"403").is_some() && find(&resp, b"denied!").is_some(),
        "expected the 403 body relayed, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        find(&resp, b"LEAK").is_none(),
        "framed relay must stop at Content-Length; raw bridge leaked trailing bytes: {:?}",
        String::from_utf8_lossy(&resp)
    );

    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn http_backend_connection_close_closes_client_leg() {
    async fn backend(mut sock: tokio::net::TcpStream) {
        read_req_head(&mut sock).await;
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
            .await
            .unwrap();
    }

    let (port, backend) = dummy_backend(backend).await;
    let mapping = mapping_file("");
    let toml = static_http_config("127.0.0.1", port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40063".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(&mut client, b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let resp = tokio::time::timeout(std::time::Duration::from_secs(5), read_to_eof(&mut client))
        .await
        .expect("proxy must close the client leg when the backend signals Connection: close");
    assert!(
        find(&resp, b"200").is_some() && find(&resp, b"hi").is_some(),
        "expected the 200 body, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        find(&resp, b"Connection: close").is_some(),
        "the backend's Connection: close must be propagated to the client, got {:?}",
        String::from_utf8_lossy(&resp)
    );

    backend.abort();
    handler.abort();
}

#[tokio::test]
async fn http_sse_streams_until_close() {
    async fn backend(mut sock: tokio::net::TcpStream) {
        read_req_head(&mut sock).await;
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\r\n")
            .await
            .unwrap();
        sock.write_all(b"data: hello\n\n").await.unwrap();
        sock.write_all(b"data: world\n\n").await.unwrap();
    }

    let (port, backend) = dummy_backend(backend).await;
    let mapping = mapping_file("");
    let toml = static_http_config("127.0.0.1", port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40061".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(&mut client, b"GET /events HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"text/event-stream").is_some()
            && find(&resp, b"data: hello").is_some()
            && find(&resp, b"data: world").is_some(),
        "SSE events must stream through until close, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn http_100_continue_with_early_hints() {
    async fn backend(mut sock: tokio::net::TcpStream) {
        read_req_head(&mut sock).await;
        sock.write_all(b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>; rel=preload\r\n\r\n")
            .await
            .unwrap();
        sock.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();
        let body = read_until_backend(&mut sock, b"hello").await;
        assert!(find(&body, b"hello").is_some());
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    }

    let (port, backend) = dummy_backend(backend).await;
    let mapping = mapping_file("");
    let toml = static_http_config("127.0.0.1", port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40062".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(
        &mut client,
        b"POST /upload HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 5\r\nConnection: close\r\n\r\n",
    )
    .await;
    let interim = read_until(&mut client, b"100 Continue").await;
    assert!(
        find(&interim, b"103").is_some(),
        "the 103 Early Hints interim must be relayed, got {:?}",
        String::from_utf8_lossy(&interim)
    );

    send(&mut client, b"hello").await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"200").is_some() && find(&resp, b"ok").is_some(),
        "after 100 Continue the body must flow and the final response return, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn http_100_continue_final_response_forces_close_no_smuggling() {
    async fn backend(mut sock: tokio::net::TcpStream) {
        read_req_head(&mut sock).await;
        sock.write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut scratch = [0u8; 256];
        let extra = sock.read(&mut scratch).await.unwrap_or(0);
        assert_eq!(
            extra, 0,
            "proxy must not forward a second request on the same backend leg"
        );
    }

    let (port, backend) = dummy_backend(backend).await;
    let mapping = mapping_file("");
    let toml = static_http_config("127.0.0.1", port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40064".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(
        &mut client,
        b"POST /upload HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 40\r\n\r\nGET /evil HTTP/1.1\r\nHost: x\r\n\r\n",
    )
    .await;

    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"413").is_some(),
        "expected the backend's 413 final response, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    assert!(
        find(&resp, b"Connection: close").is_some(),
        "the proxy must force Connection: close on an unhonored 100-continue, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn http_100_continue_body_route_proxy_answers_continue() {
    async fn backend(mut sock: tokio::net::TcpStream) {
        let req = read_until_backend(&mut sock, b"corp.com").await;
        assert!(
            find(&req, b"Expect").is_none() && find(&req, b"100-continue").is_none(),
            "proxy must strip Expect when it answers 100-continue itself, got {:?}",
            String::from_utf8_lossy(&req)
        );
        assert!(
            find(&req, b"username=joe").is_some(),
            "the routing body must reach the backend, got {:?}",
            String::from_utf8_lossy(&req)
        );
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
    }

    let (port, backend) = dummy_backend(backend).await;
    let mapping = mapping_file("");
    let toml = format!(
        r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[routing]
default_destination = "web"

[destination.web]
host = "127.0.0.1"
proxy_protocol = false
allow_plaintext_auth = true
[destination.web.protocol.http]
port = {port}
tls = "plain"

[[http.route]]
match = "/auth/**"
extract = {{ from = "body", regex = "username=([^&]+)" }}

[listener.http]
protocol = "http"
bind = ["127.0.0.1:0"]
tls = "plain"
"#,
        mapping.path().display()
    );
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40066".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    let body = b"username=joe@corp.com";
    let req = format!(
        "POST /auth/token HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    send(&mut client, req.as_bytes()).await;

    let interim = read_until(&mut client, b"100 Continue").await;
    assert!(
        find(&interim, b"100").is_some(),
        "the proxy must answer 100 Continue itself before the body is sent, got {:?}",
        String::from_utf8_lossy(&interim)
    );

    send(&mut client, body).await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"200").is_some() && find(&resp, b"ok").is_some(),
        "expected 200 ok after body-based routing, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
    handler.abort();
}

#[tokio::test]
async fn http_chunked_request_and_response_round_trip() {
    async fn backend(mut sock: tokio::net::TcpStream) {
        let _ = read_until_backend(&mut sock, b"0\r\n\r\n").await;
        sock.write_all(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
    }

    let (port, backend) = dummy_backend(backend).await;
    let mapping = mapping_file("");
    let toml = static_http_config("127.0.0.1", port, &mapping.path().display().to_string());
    let ctx = make_ctx(&toml).await;
    let listener = ctx.config.listener["http"].clone();

    let (mut client, srv) = tcp_pair().await;
    let ctx2 = ctx.clone();
    let handler = tokio::spawn(async move {
        let _ = crate::http::proxy::handle(
            &ctx2,
            &listener,
            Box::new(srv),
            "127.0.0.1:40063".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        )
        .await;
    });

    send(
        &mut client,
        b"POST /up HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    )
    .await;
    let resp = read_to_eof(&mut client).await;
    assert!(
        find(&resp, b"200").is_some() && find(&resp, b"abc").is_some(),
        "chunked request and response must round-trip, got {:?}",
        String::from_utf8_lossy(&resp)
    );
    let _ = backend.await;
    handler.abort();
}
