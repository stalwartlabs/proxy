/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::ProxyProtocolMode;
use crate::net::cidr::Cidr;
use crate::net::proxy_protocol::resolve_inbound;

use super::harness::*;

async fn read_payload(stream: &mut crate::net::BoxedStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];
    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut scratch))
            .await
        {
            Ok(Ok(0)) => return buf,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&scratch[..n]);
                if !buf.is_empty() {
                    return buf;
                }
            }
            Ok(Err(_)) | Err(_) => return buf,
        }
    }
}

#[tokio::test]
async fn v1_header_from_trusted_peer_rewrites_peer_and_preserves_payload() {
    let (mut client, server) = tcp_pair().await;
    let tcp_peer = client.local_addr().unwrap();
    let tcp_local = server.local_addr().unwrap();

    client
        .write_all(b"PROXY TCP4 1.2.3.4 5.6.7.8 1111 2222\r\nPAYLOAD")
        .await
        .unwrap();
    client.flush().await.unwrap();

    let any: Cidr = "0.0.0.0/0".parse().unwrap();
    let mut res = resolve_inbound(
        server,
        tcp_peer,
        tcp_local,
        ProxyProtocolMode::Optional,
        &[any],
    )
    .await
    .unwrap();

    assert_eq!(res.peer, "1.2.3.4:1111".parse().unwrap());

    let payload = read_payload(&mut res.stream).await;
    assert_eq!(&payload, b"PAYLOAD");
}

#[tokio::test]
async fn optional_untrusted_peer_leaves_peer_unchanged() {
    let (mut client, server) = tcp_pair().await;
    let tcp_peer = client.local_addr().unwrap();
    let tcp_local = server.local_addr().unwrap();

    client.write_all(b"PAYLOAD").await.unwrap();
    client.flush().await.unwrap();

    let mut res = resolve_inbound(
        server,
        tcp_peer,
        tcp_local,
        ProxyProtocolMode::Optional,
        &[],
    )
    .await
    .unwrap();

    assert_eq!(res.peer, tcp_peer);

    let payload = read_payload(&mut res.stream).await;
    assert_eq!(&payload, b"PAYLOAD");
}

#[tokio::test]
async fn required_trusted_peer_without_header_errors() {
    let (mut client, server) = tcp_pair().await;
    let tcp_peer = client.local_addr().unwrap();
    let tcp_local = server.local_addr().unwrap();

    client.write_all(b"PAYLOAD").await.unwrap();
    client.flush().await.unwrap();

    let any: Cidr = "0.0.0.0/0".parse().unwrap();
    let res = resolve_inbound(
        server,
        tcp_peer,
        tcp_local,
        ProxyProtocolMode::Required,
        &[any],
    )
    .await;

    assert!(res.is_err());
}
