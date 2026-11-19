/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::{SocketAddr, SocketAddrV6};
use std::ops::Deref;

use proxy_header::ProxyHeader;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::config::ProxyProtocolMode;
use crate::error::{ProxyError, Result};
use crate::net::cidr::Cidr;
use crate::net::stream::{ClientStream, Prefaced};

const V2_MAGIC: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
const V1_PREFIX: &[u8] = b"PROXY ";
const MAX_HEADER_PROBE: usize = 1024;

fn could_be_proxy(buf: &[u8]) -> bool {
    let is_prefix_of = |magic: &[u8]| buf.iter().zip(magic).all(|(a, b)| a == b);
    is_prefix_of(V1_PREFIX) || is_prefix_of(&V2_MAGIC)
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

fn as_v6(addr: SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V4(v4) => SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0),
        SocketAddr::V6(v6) => v6,
    }
}

pub struct InboundResolution {
    pub stream: ClientStream,
    pub peer: SocketAddr,
    pub local: SocketAddr,
}

impl InboundResolution {
    pub async fn resolve(
        stream: TcpStream,
        tcp_peer: SocketAddr,
        tcp_local: SocketAddr,
        mode: ProxyProtocolMode,
        trusted: &[Cidr],
    ) -> Result<InboundResolution> {
        if mode == ProxyProtocolMode::Off {
            return Ok(InboundResolution {
                stream: stream.into(),
                peer: tcp_peer,
                local: tcp_local,
            });
        }

        let is_trusted = Cidr::any_contains(trusted, tcp_peer.ip());
        if !is_trusted {
            if mode == ProxyProtocolMode::Required {
                return Err(ProxyError::protocol(
                    "PROXY header required but peer is not trusted",
                ));
            }
            return Ok(InboundResolution {
                stream: stream.into(),
                peer: tcp_peer,
                local: tcp_local,
            });
        }

        Self::parse(stream, tcp_peer, tcp_local, mode).await
    }

    async fn parse(
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
                    stream: Prefaced::with_prefix(buf, stream).into(),
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
                    stream: Prefaced::with_prefix(buf, stream).into(),
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
                        stream: Prefaced::with_prefix(leftover, stream).into(),
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
                        stream: Prefaced::with_prefix(buf, stream).into(),
                        peer: tcp_peer,
                        local: tcp_local,
                    });
                }
            }
        }
    }
}

const V2_VERSION_PROXY: u8 = 0x21;
const V2_TCP_V4: u8 = 0x11;
const V2_TCP_V6: u8 = 0x21;
const V2_FIXED_LEN: usize = 16;
const V2_V4_ADDRS_LEN: u16 = 12;
const V2_V6_ADDRS_LEN: u16 = 36;
const V2_MAX_LEN: usize = V2_FIXED_LEN + V2_V6_ADDRS_LEN as usize;

pub struct OutboundHeader {
    buf: [u8; V2_MAX_LEN],
    len: usize,
}

impl OutboundHeader {
    pub fn new(peer: SocketAddr, local: SocketAddr) -> Self {
        let mut header = OutboundHeader {
            buf: [0; V2_MAX_LEN],
            len: 0,
        };
        match (normalize(peer), normalize(local)) {
            (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
                header.push_prefix(V2_TCP_V4, V2_V4_ADDRS_LEN);
                header.push(&src.ip().octets());
                header.push(&dst.ip().octets());
                header.push(&src.port().to_be_bytes());
                header.push(&dst.port().to_be_bytes());
            }
            (src, dst) => {
                let (src, dst) = (as_v6(src), as_v6(dst));
                header.push_prefix(V2_TCP_V6, V2_V6_ADDRS_LEN);
                header.push(&src.ip().octets());
                header.push(&dst.ip().octets());
                header.push(&src.port().to_be_bytes());
                header.push(&dst.port().to_be_bytes());
            }
        }
        header
    }

    fn push_prefix(&mut self, family: u8, addrs_len: u16) {
        self.push(&V2_MAGIC);
        self.push(&[V2_VERSION_PROXY, family]);
        self.push(&addrs_len.to_be_bytes());
    }

    fn push(&mut self, bytes: &[u8]) {
        if let Some(slot) = self.buf.get_mut(self.len..self.len + bytes.len()) {
            slot.copy_from_slice(bytes);
            self.len += bytes.len();
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.buf.get(..self.len).unwrap_or_default()
    }
}

impl Deref for OutboundHeader {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/net/proxy_protocol/tests.rs"]
mod tests;
