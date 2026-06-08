/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::SocketAddr;

use proxy_header::{ProxiedAddress, ProxyHeader};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::config::ProxyProtocolMode;
use crate::error::{ProxyError, Result};
use crate::net::cidr::{Cidr, any_contains};
use crate::net::stream::{BoxedStream, PrefacedStream};

const V2_MAGIC: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
const V1_PREFIX: &[u8] = b"PROXY ";
const MAX_HEADER_PROBE: usize = 1024;

fn could_be_proxy(buf: &[u8]) -> bool {
    let n = buf.len();
    let v1 = &V1_PREFIX[..n.min(V1_PREFIX.len())];
    let v2 = &V2_MAGIC[..n.min(V2_MAGIC.len())];
    buf.starts_with(v1) || buf.starts_with(v2)
}

fn normalize(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        _ => addr,
    }
}

pub struct InboundResolution {
    pub stream: BoxedStream,
    pub peer: SocketAddr,
    pub local: SocketAddr,
}

pub async fn resolve_inbound(
    stream: TcpStream,
    tcp_peer: SocketAddr,
    tcp_local: SocketAddr,
    mode: ProxyProtocolMode,
    trusted: &[Cidr],
) -> Result<InboundResolution> {
    if mode == ProxyProtocolMode::Off {
        return Ok(InboundResolution {
            stream: Box::new(stream),
            peer: tcp_peer,
            local: tcp_local,
        });
    }

    let is_trusted = any_contains(trusted, tcp_peer.ip());
    if !is_trusted {
        if mode == ProxyProtocolMode::Required {
            return Err(ProxyError::protocol(
                "PROXY header required but peer is not trusted",
            ));
        }
        return Ok(InboundResolution {
            stream: Box::new(stream),
            peer: tcp_peer,
            local: tcp_local,
        });
    }

    parse_inbound_header(stream, tcp_peer, tcp_local, mode).await
}

async fn parse_inbound_header(
    mut stream: TcpStream,
    tcp_peer: SocketAddr,
    tcp_local: SocketAddr,
    mode: ProxyProtocolMode,
) -> Result<InboundResolution> {
    let required = mode == ProxyProtocolMode::Required;
    let mut buf: Vec<u8> = Vec::with_capacity(256);

    loop {
        let n = stream
            .read_buf(&mut buf)
            .await
            .map_err(|e| ProxyError::protocol(format!("reading PROXY header: {e}")))?;
        if n == 0 {
            if required {
                return Err(ProxyError::protocol(
                    "PROXY header required but connection closed before one arrived",
                ));
            }
            return Ok(InboundResolution {
                stream: Box::new(PrefacedStream::new(buf, stream)),
                peer: tcp_peer,
                local: tcp_local,
            });
        }

        if !could_be_proxy(&buf) {
            if required {
                return Err(ProxyError::protocol(
                    "PROXY header required from trusted peer but none present",
                ));
            }
            return Ok(InboundResolution {
                stream: Box::new(PrefacedStream::new(buf, stream)),
                peer: tcp_peer,
                local: tcp_local,
            });
        }

        match ProxyHeader::parse(&buf, Default::default()) {
            Ok((header, consumed)) => {
                let (peer, local) = match header.proxied_address() {
                    Some(addr) => (normalize(addr.source), normalize(addr.destination)),
                    None => (tcp_peer, tcp_local),
                };
                let leftover = buf.split_off(consumed);
                return Ok(InboundResolution {
                    stream: Box::new(PrefacedStream::new(leftover, stream)),
                    peer,
                    local,
                });
            }
            Err(proxy_header::Error::BufferTooShort) if buf.len() < MAX_HEADER_PROBE => {
                continue;
            }
            Err(_) => {
                if required {
                    return Err(ProxyError::protocol(
                        "invalid PROXY header from trusted peer",
                    ));
                }
                return Ok(InboundResolution {
                    stream: Box::new(PrefacedStream::new(buf, stream)),
                    peer: tcp_peer,
                    local: tcp_local,
                });
            }
        }
    }
}

pub fn build_outbound_header(peer: SocketAddr, local: SocketAddr) -> Result<Vec<u8>> {
    let src = normalize(peer);
    let dst = normalize(local);
    let mut buf = Vec::with_capacity(64);
    if src.is_ipv4() != dst.is_ipv4() {
        buf.extend_from_slice(b"PROXY UNKNOWN\r\n");
        return Ok(buf);
    }
    let header = ProxyHeader::with_address(ProxiedAddress::stream(src, dst));
    header
        .encode_v2(&mut buf)
        .map_err(|e| ProxyError::backend(format!("PROXY header encode failed: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_mapped_v4() {
        let mapped: SocketAddr = "[::ffff:10.0.0.1]:25".parse().unwrap();
        assert_eq!(normalize(mapped), "10.0.0.1:25".parse().unwrap());
    }

    #[test]
    fn outbound_v2_for_matching_families() {
        let h = build_outbound_header(
            "10.0.0.1:12345".parse().unwrap(),
            "10.0.0.2:993".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(&h[..12], &V2_MAGIC);
    }

    #[test]
    fn outbound_unknown_for_family_mismatch() {
        let h = build_outbound_header(
            "10.0.0.1:12345".parse().unwrap(),
            "[2001:db8::1]:993".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(&h, b"PROXY UNKNOWN\r\n");
    }
}
