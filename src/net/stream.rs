/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::pki_types::ServerName;
use rustls::{CipherSuite, ClientConfig, ProtocolVersion};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};

use crate::error::{ErrorKind, ProxyError, Result, Side, Stage};
use crate::net::linebuf::LineBuf;

pub struct Prefaced<IO> {
    prefix: Option<Box<Prefix>>,
    io: IO,
}

struct Prefix {
    data: Box<[u8]>,
    pos: usize,
}

impl<IO> Prefaced<IO> {
    pub fn new(io: IO) -> Self {
        Prefaced { prefix: None, io }
    }

    pub fn with_prefix(prefix: Vec<u8>, io: IO) -> Self {
        let prefix = (!prefix.is_empty()).then(|| {
            Box::new(Prefix {
                data: prefix.into_boxed_slice(),
                pos: 0,
            })
        });
        Prefaced { prefix, io }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for Prefaced<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        if let Some(prefix) = &mut me.prefix {
            let remaining = prefix.data.get(prefix.pos..).unwrap_or_default();
            let n = remaining.len().min(buf.remaining());
            let (head, rest) = remaining.split_at(n);
            buf.put_slice(head);
            if rest.is_empty() {
                me.prefix = None;
            } else {
                prefix.pos += n;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.io).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Prefaced<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsInfo {
    pub version: ProtocolVersion,
    pub cipher: CipherSuite,
}

impl TlsInfo {
    fn from_conn(conn: &rustls::CommonState) -> Option<Self> {
        Some(TlsInfo {
            version: conn.protocol_version()?,
            cipher: conn.negotiated_cipher_suite()?.suite(),
        })
    }

    pub fn version_str(&self) -> &'static str {
        match self.version {
            ProtocolVersion::TLSv1_2 => "TLSv1.2",
            ProtocolVersion::TLSv1_3 => "TLSv1.3",
            ProtocolVersion::TLSv1_1 => "TLSv1.1",
            ProtocolVersion::TLSv1_0 => "TLSv1.0",
            _ => "unknown",
        }
    }

    pub fn cipher_str(&self) -> &'static str {
        self.cipher.as_str().unwrap_or("unknown")
    }
}

pub enum ClientStream {
    Plain(Prefaced<TcpStream>),
    Tls(Box<server::TlsStream<Prefaced<TcpStream>>>),
}

const _: () = assert!(size_of::<ClientStream>() <= 48);

impl From<TcpStream> for ClientStream {
    fn from(tcp: TcpStream) -> Self {
        ClientStream::Plain(Prefaced::new(tcp))
    }
}

impl From<Prefaced<TcpStream>> for ClientStream {
    fn from(io: Prefaced<TcpStream>) -> Self {
        ClientStream::Plain(io)
    }
}

impl ClientStream {
    pub fn is_tls(&self) -> bool {
        matches!(self, ClientStream::Tls(_))
    }

    pub fn tls_info(&self) -> Option<TlsInfo> {
        match self {
            ClientStream::Plain(_) => None,
            ClientStream::Tls(tls) => TlsInfo::from_conn(tls.get_ref().1),
        }
    }

    pub async fn accept_tls(self, acceptor: &TlsAcceptor) -> Result<Self> {
        let ClientStream::Plain(io) = self else {
            return Err(ProxyError::already_tls());
        };
        acceptor
            .accept(io)
            .await
            .map(|tls| ClientStream::Tls(Box::new(tls)))
            .map_err(|e| ProxyError::io(Stage::InboundTls, Side::Client, e))
    }

    pub async fn upgrade(self, acceptor: &TlsAcceptor, buf: &mut LineBuf) -> Result<Self> {
        buf.clear();
        self.accept_tls(acceptor).await
    }

    pub async fn send(&mut self, bytes: &[u8]) -> Result<()> {
        send_all(self, bytes, Stage::Preauth, Side::Client).await
    }
}

pub enum BackendStream {
    Plain(TcpStream),
    Tls(Box<client::TlsStream<TcpStream>>),
}

const _: () = assert!(size_of::<BackendStream>() <= 40);

impl From<TcpStream> for BackendStream {
    fn from(tcp: TcpStream) -> Self {
        BackendStream::Plain(tcp)
    }
}

impl BackendStream {
    pub fn is_tls(&self) -> bool {
        matches!(self, BackendStream::Tls(_))
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        match self {
            BackendStream::Plain(tcp) => tcp.peer_addr(),
            BackendStream::Tls(tls) => tls.get_ref().0.peer_addr(),
        }
    }

    pub fn tls_info(&self) -> Option<TlsInfo> {
        match self {
            BackendStream::Plain(_) => None,
            BackendStream::Tls(tls) => TlsInfo::from_conn(tls.get_ref().1),
        }
    }

    pub async fn connect_tls(
        self,
        config: &Arc<ClientConfig>,
        name: Option<&ServerName<'static>>,
    ) -> Result<Self> {
        let name = name.ok_or_else(ProxyError::no_server_name)?;
        self.handshake(config, name).await
    }

    async fn handshake(
        self,
        config: &Arc<ClientConfig>,
        name: &ServerName<'static>,
    ) -> Result<Self> {
        let BackendStream::Plain(tcp) = self else {
            return Err(ProxyError::already_tls());
        };
        TlsConnector::from(config.clone())
            .connect(name.clone(), tcp)
            .await
            .map(|tls| BackendStream::Tls(Box::new(tls)))
            .map_err(|e| ProxyError::io(Stage::BackendTls, Side::Backend, e))
    }

    pub async fn upgrade(
        self,
        config: &Arc<ClientConfig>,
        name: Option<&ServerName<'static>>,
        buf: &LineBuf,
    ) -> Result<Self> {
        let name = name.ok_or_else(ProxyError::no_server_name)?;
        if !buf.data().is_empty() {
            return Err(ProxyError::plaintext_after_starttls());
        }
        self.handshake(config, name).await
    }

    pub async fn send(&mut self, bytes: &[u8], stage: Stage) -> Result<()> {
        send_all(self, bytes, stage, Side::Backend).await
    }
}

async fn send_all<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    stage: Stage,
    side: Side,
) -> Result<()> {
    stream
        .write_all(bytes)
        .await
        .map_err(|e| ProxyError::io(stage, side, e))?;
    stream
        .flush()
        .await
        .map_err(|e| ProxyError::io(stage, side, e))
}

macro_rules! dispatch_io {
    ($ty:ident) => {
        impl AsyncRead for $ty {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $ty::Plain(s) => Pin::new(s).poll_read(cx, buf),
                    $ty::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
                }
            }
        }

        impl AsyncWrite for $ty {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                match self.get_mut() {
                    $ty::Plain(s) => Pin::new(s).poll_write(cx, buf),
                    $ty::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
                }
            }

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                match self.get_mut() {
                    $ty::Plain(s) => Pin::new(s).poll_write_vectored(cx, bufs),
                    $ty::Tls(s) => Pin::new(s.as_mut()).poll_write_vectored(cx, bufs),
                }
            }

            fn is_write_vectored(&self) -> bool {
                match self {
                    $ty::Plain(s) => s.is_write_vectored(),
                    $ty::Tls(s) => s.is_write_vectored(),
                }
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $ty::Plain(s) => Pin::new(s).poll_flush(cx),
                    $ty::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
                }
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                match self.get_mut() {
                    $ty::Plain(s) => Pin::new(s).poll_shutdown(cx),
                    $ty::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
                }
            }
        }
    };
}

dispatch_io!(ClientStream);
dispatch_io!(BackendStream);
impl ProxyError {
    #[cold]
    #[inline(never)]
    fn already_tls() -> ProxyError {
        ProxyError::new(
            Stage::Starttls,
            Side::Client,
            ErrorKind::Protocol("stream is already TLS".into()),
        )
    }

    #[cold]
    #[inline(never)]
    fn no_server_name() -> ProxyError {
        ProxyError::unavailable(
            Stage::BackendTls,
            "destination has no valid TLS server name (set tls_server_name)",
        )
    }

    #[cold]
    #[inline(never)]
    fn plaintext_after_starttls() -> ProxyError {
        ProxyError::unavailable(
            Stage::Starttls,
            "backend sent data after its STARTTLS reply",
        )
    }
}
