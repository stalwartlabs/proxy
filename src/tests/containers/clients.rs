/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::tests::harness::tls_connect_client;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tls {
    Implicit,
    Starttls,
}

fn plain_ir(login: &str, password: &str) -> String {
    B64.encode(format!("\0{login}\0{password}"))
}

async fn read_reply<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).into_owned()
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

pub async fn imap_auth(host: &str, port: u16, tls: Tls, login: &str, password: &str) -> String {
    let cmd = format!("a1 AUTHENTICATE PLAIN {}\r\n", plain_ir(login, password));
    match tls {
        Tls::Implicit => {
            let tcp = TcpStream::connect((host, port)).await.unwrap();
            let mut s = tls_connect_client(tcp).await;
            let _ = read_reply(&mut s).await;
            s.write_all(cmd.as_bytes()).await.unwrap();
            read_until(&mut s, "a1 ").await
        }
        Tls::Starttls => {
            let mut tcp = TcpStream::connect((host, port)).await.unwrap();
            let _ = read_reply(&mut tcp).await;
            tcp.write_all(b"a0 STARTTLS\r\n").await.unwrap();
            let _ = read_until(&mut tcp, "a0 ").await;
            let mut s = tls_connect_client(tcp).await;
            s.write_all(cmd.as_bytes()).await.unwrap();
            read_until(&mut s, "a1 ").await
        }
    }
}

pub async fn pop3_auth(host: &str, port: u16, tls: Tls, login: &str, password: &str) -> String {
    let cmd = format!("AUTH PLAIN {}\r\n", plain_ir(login, password));
    match tls {
        Tls::Implicit => {
            let tcp = TcpStream::connect((host, port)).await.unwrap();
            let mut s = tls_connect_client(tcp).await;
            let _ = read_reply(&mut s).await;
            s.write_all(cmd.as_bytes()).await.unwrap();
            read_reply(&mut s).await
        }
        Tls::Starttls => {
            let mut tcp = TcpStream::connect((host, port)).await.unwrap();
            let _ = read_reply(&mut tcp).await;
            tcp.write_all(b"STLS\r\n").await.unwrap();
            let _ = read_reply(&mut tcp).await;
            let mut s = tls_connect_client(tcp).await;
            s.write_all(cmd.as_bytes()).await.unwrap();
            read_reply(&mut s).await
        }
    }
}

pub async fn managesieve_auth(
    host: &str,
    port: u16,
    tls: Tls,
    login: &str,
    password: &str,
) -> String {
    let cmd = format!(
        "AUTHENTICATE \"PLAIN\" \"{}\"\r\n",
        plain_ir(login, password)
    );
    match tls {
        Tls::Implicit => {
            let tcp = TcpStream::connect((host, port)).await.unwrap();
            let mut s = tls_connect_client(tcp).await;
            let _ = read_until(&mut s, "OK").await;
            s.write_all(cmd.as_bytes()).await.unwrap();
            read_reply(&mut s).await
        }
        Tls::Starttls => {
            let mut tcp = TcpStream::connect((host, port)).await.unwrap();
            let _ = read_until(&mut tcp, "OK").await;
            tcp.write_all(b"STARTTLS\r\n").await.unwrap();
            let _ = read_reply(&mut tcp).await;
            let mut s = tls_connect_client(tcp).await;
            let _ = read_until(&mut s, "OK").await;
            s.write_all(cmd.as_bytes()).await.unwrap();
            read_reply(&mut s).await
        }
    }
}

async fn submission_auth<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    login: &str,
    password: &str,
) -> String {
    stream.write_all(b"EHLO proxy.test\r\n").await.unwrap();
    let _ = read_until(stream, "250 ").await;
    let ir = B64.encode(format!("\0{login}\0{password}"));
    stream
        .write_all(format!("AUTH PLAIN {ir}\r\n").as_bytes())
        .await
        .unwrap();
    read_reply(stream).await
}

pub async fn submission_send(
    host: &str,
    port: u16,
    tls: Tls,
    login: &str,
    password: &str,
) -> String {
    match tls {
        Tls::Implicit => {
            let tcp = TcpStream::connect((host, port)).await.unwrap();
            let mut s = tls_connect_client(tcp).await;
            let _ = read_reply(&mut s).await;
            submission_auth(&mut s, login, password).await
        }
        Tls::Starttls => {
            let mut tcp = TcpStream::connect((host, port)).await.unwrap();
            let _ = read_reply(&mut tcp).await;
            tcp.write_all(b"EHLO proxy.test\r\n").await.unwrap();
            let _ = read_until(&mut tcp, "250 ").await;
            tcp.write_all(b"STARTTLS\r\n").await.unwrap();
            let _ = read_reply(&mut tcp).await;
            let mut s = tls_connect_client(tcp).await;
            submission_auth(&mut s, login, password).await
        }
    }
}

pub async fn smtp_passthrough_send(host: &str, port: u16, from: &str, to: &str) -> String {
    let mut s = TcpStream::connect((host, port)).await.unwrap();
    let _ = read_reply(&mut s).await;
    s.write_all(b"EHLO proxy.test\r\n").await.unwrap();
    let _ = read_until(&mut s, "250 ").await;
    s.write_all(format!("MAIL FROM:<{from}>\r\n").as_bytes())
        .await
        .unwrap();
    let _ = read_reply(&mut s).await;
    s.write_all(format!("RCPT TO:<{to}>\r\n").as_bytes())
        .await
        .unwrap();
    let rcpt = read_reply(&mut s).await;
    s.write_all(b"QUIT\r\n").await.unwrap();
    rcpt
}
