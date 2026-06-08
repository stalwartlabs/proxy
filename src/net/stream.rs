/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub trait SessionStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn is_tls(&self) -> bool;
    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>);
}

pub type BoxedStream = Box<dyn SessionStream>;

impl SessionStream for TcpStream {
    fn is_tls(&self) -> bool {
        false
    }

    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>) {
        (Cow::Borrowed(""), Cow::Borrowed(""))
    }
}

impl SessionStream for BoxedStream {
    fn is_tls(&self) -> bool {
        (**self).is_tls()
    }

    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>) {
        (**self).tls_version_and_cipher()
    }
}

fn protocol_version_str(v: Option<rustls::ProtocolVersion>) -> Cow<'static, str> {
    Cow::Borrowed(match v {
        Some(rustls::ProtocolVersion::SSLv2) => "SSLv2",
        Some(rustls::ProtocolVersion::SSLv3) => "SSLv3",
        Some(rustls::ProtocolVersion::TLSv1_0) => "TLSv1.0",
        Some(rustls::ProtocolVersion::TLSv1_1) => "TLSv1.1",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        _ => "unknown",
    })
}

fn cipher_str(cs: Option<rustls::SupportedCipherSuite>) -> Cow<'static, str> {
    Cow::Borrowed(cs.and_then(|c| c.suite().as_str()).unwrap_or("unknown"))
}

macro_rules! impl_tls_stream {
    ($side:path) => {
        impl<T: SessionStream> SessionStream for $side {
            fn is_tls(&self) -> bool {
                true
            }

            fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>) {
                let (_, conn) = self.get_ref();
                (
                    protocol_version_str(conn.protocol_version()),
                    cipher_str(conn.negotiated_cipher_suite()),
                )
            }
        }
    };
}

impl_tls_stream!(tokio_rustls::server::TlsStream<T>);
impl_tls_stream!(tokio_rustls::client::TlsStream<T>);

pub struct PrefacedStream<IO> {
    prefix: Vec<u8>,
    pos: usize,
    io: IO,
}

impl<IO> PrefacedStream<IO> {
    pub fn new(prefix: Vec<u8>, io: IO) -> Self {
        PrefacedStream { prefix, pos: 0, io }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for PrefacedStream<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = self.get_mut();
        if me.pos < me.prefix.len() {
            let remaining = &me.prefix[me.pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            me.pos += n;
            if me.pos == me.prefix.len() {
                me.prefix = Vec::new();
                me.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.io).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for PrefacedStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

impl<IO: SessionStream> SessionStream for PrefacedStream<IO> {
    fn is_tls(&self) -> bool {
        false
    }

    fn tls_version_and_cipher(&self) -> (Cow<'static, str>, Cow<'static, str>) {
        (Cow::Borrowed(""), Cow::Borrowed(""))
    }
}
