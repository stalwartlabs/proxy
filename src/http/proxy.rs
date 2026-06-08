/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::config::{ForwardedMode, ListenerConfig, Protocol, TlsMode};
use crate::error::{ProxyError, Result};
use crate::net::BoxedStream;
use crate::proto::common::Ctx;

use super::head::{BodyFraming, Head, ParseError, ParseOutcome, error_response};
use super::router::{HttpRouter, RouteOutcome};

const READ_CHUNK: usize = 16 * 1024;

#[derive(Clone, Copy)]
struct Idle {
    body: Duration,
    stream: Duration,
}

struct Reader {
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl Reader {
    fn new() -> Self {
        Reader {
            buf: Vec::with_capacity(READ_CHUNK),
            pos: 0,
            eof: false,
        }
    }

    fn data(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn consume(&mut self, n: usize) {
        self.pos += n;
        if self.pos >= self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos >= READ_CHUNK {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }

    fn take_data(&mut self) -> Vec<u8> {
        let out = self.buf[self.pos..].to_vec();
        self.buf.clear();
        self.pos = 0;
        out
    }

    async fn fill(&mut self, stream: &mut BoxedStream, idle: Duration) -> Result<usize> {
        let start = self.buf.len();
        self.buf.resize(start + READ_CHUNK, 0);
        let n = match timeout(idle, stream.read(&mut self.buf[start..])).await {
            Ok(r) => r.map_err(|e| ProxyError::protocol(format!("reading stream: {e}")))?,
            Err(_) => {
                self.buf.truncate(start);
                return Err(ProxyError::protocol("read idle timeout"));
            }
        };
        self.buf.truncate(start + n);
        if n == 0 {
            self.eof = true;
        }
        Ok(n)
    }
}

async fn read_client_head(
    stream: &mut BoxedStream,
    reader: &mut Reader,
    max_head: usize,
    idle: Duration,
) -> std::result::Result<Option<Head>, ParseError> {
    loop {
        match Head::parse(reader.data(), max_head)? {
            ParseOutcome::Done { head, consumed } => {
                reader.consume(consumed);
                return Ok(Some(head));
            }
            ParseOutcome::NeedMore => {}
        }
        if reader.eof {
            if reader.is_empty() {
                return Ok(None);
            }
            return Err(ParseError::BadRequest);
        }
        let n = reader
            .fill(stream, idle)
            .await
            .map_err(|_| ParseError::BadRequest)?;
        if n == 0 && reader.is_empty() {
            return Ok(None);
        }
    }
}

async fn read_backend_head(
    stream: &mut BoxedStream,
    reader: &mut Reader,
    max_head: usize,
    idle: Duration,
) -> Result<Head> {
    loop {
        match Head::parse_response(reader.data(), max_head)
            .map_err(|_| ProxyError::backend("malformed backend response head"))?
        {
            ParseOutcome::Done { head, consumed } => {
                reader.consume(consumed);
                return Ok(head);
            }
            ParseOutcome::NeedMore => {}
        }
        let n = reader
            .fill(stream, idle)
            .await
            .map_err(|_| ProxyError::backend("reading backend"))?;
        if n == 0 {
            return Err(ProxyError::backend("backend closed before response head"));
        }
    }
}

async fn push_client(stream: &mut BoxedStream, bytes: &[u8]) -> Result<()> {
    stream
        .write_all(bytes)
        .await
        .map_err(|e| ProxyError::protocol(format!("writing client: {e}")))
}

async fn flush_client(stream: &mut BoxedStream) -> Result<()> {
    stream
        .flush()
        .await
        .map_err(|e| ProxyError::protocol(format!("flushing client: {e}")))
}

async fn push_backend(stream: &mut BoxedStream, bytes: &[u8]) -> Result<()> {
    stream
        .write_all(bytes)
        .await
        .map_err(|e| ProxyError::backend(format!("writing backend: {e}")))
}

async fn flush_backend(stream: &mut BoxedStream) -> Result<()> {
    stream
        .flush()
        .await
        .map_err(|e| ProxyError::backend(format!("flushing backend: {e}")))
}

async fn write_client(stream: &mut BoxedStream, bytes: &[u8]) -> Result<()> {
    push_client(stream, bytes).await?;
    flush_client(stream).await
}

async fn transfer_length(
    src: &mut BoxedStream,
    reader: &mut Reader,
    dst: &mut BoxedStream,
    to_backend: bool,
    mut remaining: u64,
    idle: Duration,
) -> Result<()> {
    while remaining > 0 {
        if reader.is_empty() {
            let n = reader.fill(src, idle).await?;
            if n == 0 {
                return Err(if to_backend {
                    ProxyError::protocol("client closed mid body")
                } else {
                    ProxyError::backend("backend closed mid body")
                });
            }
        }
        let take = {
            let avail = reader.data();
            let take = (remaining as usize).min(avail.len());
            forward(dst, &avail[..take], to_backend).await?;
            take
        };
        reader.consume(take);
        remaining -= take as u64;
    }
    Ok(())
}

async fn transfer_chunked(
    src: &mut BoxedStream,
    reader: &mut Reader,
    dst: &mut BoxedStream,
    to_backend: bool,
    idle: Duration,
) -> Result<()> {
    loop {
        let line = read_chunk_line(src, reader, idle).await?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_str, 16)
            .map_err(|_| ProxyError::protocol("invalid chunk size"))?;

        if size == 0 {
            let mut frame = format!("{size:x}\r\n").into_bytes();
            loop {
                let trailer = read_chunk_line(src, reader, idle).await?;
                frame.extend_from_slice(trailer.as_bytes());
                frame.extend_from_slice(b"\r\n");
                if trailer.is_empty() {
                    break;
                }
            }
            forward(dst, &frame, to_backend).await?;
            return Ok(());
        }

        let header = format!("{size:x}\r\n");
        let mut remaining = size;
        let mut header_pending = true;
        while remaining > 0 {
            if reader.is_empty() {
                let n = reader.fill(src, idle).await?;
                if n == 0 {
                    return Err(ProxyError::protocol("closed mid chunk"));
                }
            }
            let take = (remaining as usize).min(reader.data().len());
            let last = remaining - take as u64 == 0;
            {
                let avail = reader.data();
                if header_pending || last {
                    let mut frame =
                        Vec::with_capacity(header.len() * header_pending as usize + take + 2);
                    if header_pending {
                        frame.extend_from_slice(header.as_bytes());
                    }
                    frame.extend_from_slice(&avail[..take]);
                    if last {
                        frame.extend_from_slice(b"\r\n");
                    }
                    forward(dst, &frame, to_backend).await?;
                } else {
                    forward(dst, &avail[..take], to_backend).await?;
                }
            }
            header_pending = false;
            reader.consume(take);
            remaining -= take as u64;
        }

        let crlf = read_chunk_line(src, reader, idle).await?;
        if !crlf.is_empty() {
            return Err(ProxyError::protocol("malformed chunk terminator"));
        }
    }
}

async fn forward(dst: &mut BoxedStream, bytes: &[u8], to_backend: bool) -> Result<()> {
    if to_backend {
        push_backend(dst, bytes).await
    } else {
        push_client(dst, bytes).await
    }
}

async fn flush_side(dst: &mut BoxedStream, to_backend: bool) -> Result<()> {
    if to_backend {
        flush_backend(dst).await
    } else {
        flush_client(dst).await
    }
}

async fn read_chunk_line(
    src: &mut BoxedStream,
    reader: &mut Reader,
    idle: Duration,
) -> Result<String> {
    loop {
        let found = {
            let data = reader.data();
            if let Some(pos) = data.iter().position(|&b| b == b'\n') {
                let mut end = pos;
                if end > 0 && data[end - 1] == b'\r' {
                    end -= 1;
                }
                let line = String::from_utf8(data[..end].to_vec())
                    .map_err(|_| ProxyError::protocol("invalid chunk line"))?;
                Some((line, pos + 1))
            } else {
                None
            }
        };
        if let Some((line, consumed)) = found {
            reader.consume(consumed);
            return Ok(line);
        }
        if reader.data().len() > 16 * 1024 {
            return Err(ProxyError::protocol("chunk line too long"));
        }
        let n = reader.fill(src, idle).await?;
        if n == 0 {
            return Err(ProxyError::protocol("closed reading chunk line"));
        }
    }
}

async fn stream_until_close(
    src: &mut BoxedStream,
    reader: &mut Reader,
    dst: &mut BoxedStream,
    to_backend: bool,
    idle: Duration,
) -> Result<()> {
    if !reader.is_empty() {
        let chunk = reader.take_data();
        forward(dst, &chunk, to_backend).await?;
        flush_side(dst, to_backend).await?;
    }
    loop {
        let n = reader.fill(src, idle).await?;
        if n == 0 {
            return Ok(());
        }
        let chunk = reader.take_data();
        forward(dst, &chunk, to_backend).await?;
        flush_side(dst, to_backend).await?;
    }
}

fn sanitize_inbound_forwarded(head: &mut Head, listener: &ListenerConfig) {
    if listener.forwarded != ForwardedMode::Trust {
        head.remove_header("forwarded");
        head.remove_header("x-forwarded-for");
    }
}

fn apply_outbound_forwarded(head: &mut Head, dest_forwarded: bool, peer: IpAddr) {
    if !dest_forwarded {
        return;
    }
    let for_node = match peer {
        IpAddr::V4(v4) => format!("for={v4}"),
        IpAddr::V6(v6) => format!("for=\"[{v6}]\""),
    };
    match head.header("forwarded").map(|v| v.to_string()) {
        Some(existing) => head.set_header("forwarded", &format!("{existing}, {for_node}")),
        None => head.set_header("forwarded", &for_node),
    }
    let xff = match head.header("x-forwarded-for").map(|v| v.to_string()) {
        Some(existing) => format!("{existing}, {}", peer),
        None => peer.to_string(),
    };
    head.set_header("x-forwarded-for", &xff);
}

fn response_no_body(req_method: &str, head: &Head) -> bool {
    if req_method.eq_ignore_ascii_case("HEAD") {
        return true;
    }
    matches!(head.framing, BodyFraming::None)
}

enum Disposition {
    Close,
    Hijack {
        backend: BoxedStream,
        to_backend: Vec<u8>,
        to_client: Vec<u8>,
    },
}

async fn shutdown_client(stream: &mut BoxedStream) {
    let _ = timeout(Duration::from_secs(3), stream.shutdown()).await;
}

pub async fn handle(
    ctx: &Ctx,
    listener: &ListenerConfig,
    mut stream: BoxedStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let bridge_idle = ctx.config.server.bridge_idle;
    match serve(ctx, listener, &mut stream, peer, local).await {
        Ok(Disposition::Close) => {
            shutdown_client(&mut stream).await;
            Ok(())
        }
        Ok(Disposition::Hijack {
            backend,
            to_backend,
            to_client,
        }) => {
            crate::outbound::bridge(stream, backend, &to_backend, &to_client, bridge_idle, None)
                .await?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn serve(
    ctx: &Ctx,
    listener: &ListenerConfig,
    stream: &mut BoxedStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<Disposition> {
    let router = ctx.http_router.as_ref();
    let max_head = router.max_head_size;
    let body_cap = router.body_extract_cap;
    let bridge_idle = ctx.config.server.bridge_idle;
    let idle = Idle {
        body: router.relay_idle,
        stream: bridge_idle,
    };
    let keepalive_timeout = router.keepalive_timeout;
    let max_requests = router.max_keepalive_requests;

    let mut reader = Reader::new();

    let first_head = match timeout(
        listener.preauth_timeout,
        read_client_head(stream, &mut reader, max_head, listener.preauth_timeout),
    )
    .await
    {
        Ok(Ok(Some(h))) => h,
        Ok(Ok(None)) => return Ok(Disposition::Close),
        Ok(Err(e)) => {
            let _ = write_client(stream, &error_response(e.status(), reason(e.status()))).await;
            return Ok(Disposition::Close);
        }
        Err(_) => {
            let _ = write_client(stream, &error_response(408, "Request Timeout")).await;
            return Ok(Disposition::Close);
        }
    };

    let mut first_head = first_head;
    sanitize_inbound_forwarded(&mut first_head, listener);

    let (buffered_body, dest_id) = match prepare(
        ctx,
        router,
        stream,
        &mut reader,
        &mut first_head,
        body_cap,
        idle.body,
    )
    .await?
    {
        Some(t) => t,
        None => {
            let _ = write_client(stream, &error_response(404, "Not Found")).await;
            return Ok(Disposition::Close);
        }
    };

    let (dest, ep, tls_cfg) = match ctx.endpoint(&dest_id, Protocol::Http) {
        Ok(t) => t,
        Err(_) => {
            let _ = write_client(stream, &error_response(502, "Bad Gateway")).await;
            return Ok(Disposition::Close);
        }
    };

    if ep.tls == TlsMode::Starttls {
        let _ = write_client(stream, &error_response(502, "Bad Gateway")).await;
        return Ok(Disposition::Close);
    }

    let fwd = dest.forwarding_for(Protocol::Http);
    if let Err(e) = crate::proto::forward::guard_loop(
        &ctx.self_binds,
        dest,
        ep,
        fwd,
        ctx.config.server.proxy_ttl,
    ) {
        tracing::warn!(error = %e, destination = %dest_id, "http loop guard");
        let _ = write_client(stream, &error_response(502, "Bad Gateway")).await;
        return Ok(Disposition::Close);
    }
    let mut backend = match crate::proto::common::establish(ctx, &dest_id, || {
        crate::outbound::dial(dest, ep, fwd, &tls_cfg, peer, local)
    })
    .await
    {
        Ok(b) => b,
        Err(_) => {
            let _ = write_client(stream, &error_response(502, "Bad Gateway")).await;
            return Ok(Disposition::Close);
        }
    };

    let mut opts = ExchangeOpts {
        dest_forwarded: dest.forwarded,
        peer,
        max_head,
        idle,
        force_close: false,
    };
    let mut backend_reader = Reader::new();

    let mut current_head = first_head;
    let mut current_body = buffered_body;
    let mut served: u32 = 0;

    loop {
        served += 1;
        opts.force_close = max_requests != 0 && served >= max_requests;

        let outcome = exchange(
            stream,
            &mut reader,
            &mut backend,
            &mut backend_reader,
            &mut current_head,
            current_body.take(),
            &opts,
        )
        .await;

        match outcome {
            Ok(ExchangeResult::KeepAlive) => {}
            Ok(ExchangeResult::Hijack {
                to_backend,
                to_client,
            }) => {
                return Ok(Disposition::Hijack {
                    backend,
                    to_backend,
                    to_client,
                });
            }
            Ok(ExchangeResult::Close) => return Ok(Disposition::Close),
            Err(e) => return Err(e),
        }

        let next = match timeout(
            keepalive_timeout,
            read_client_head(stream, &mut reader, max_head, idle.body),
        )
        .await
        {
            Ok(Ok(Some(h))) => h,
            Ok(Ok(None)) => return Ok(Disposition::Close),
            Ok(Err(e)) => {
                let _ = write_client(stream, &error_response(e.status(), reason(e.status()))).await;
                return Ok(Disposition::Close);
            }
            Err(_) => return Ok(Disposition::Close),
        };

        let mut next = next;
        sanitize_inbound_forwarded(&mut next, listener);

        let (next_body, next_dest) = match prepare(
            ctx,
            router,
            stream,
            &mut reader,
            &mut next,
            body_cap,
            idle.body,
        )
        .await?
        {
            Some(t) => t,
            None => {
                let _ = write_client(stream, &error_response(404, "Not Found")).await;
                return Ok(Disposition::Close);
            }
        };

        if next_dest != dest_id {
            if let Some(body) = &next_body {
                drain_buffered(stream, &mut reader, &next, body.len(), idle.body)
                    .await
                    .ok();
            }
            let _ = write_client(stream, &error_response(421, "Misdirected Request")).await;
            return Ok(Disposition::Close);
        }

        current_head = next;
        current_body = next_body;
    }
}

enum ExchangeResult {
    KeepAlive,
    Hijack {
        to_backend: Vec<u8>,
        to_client: Vec<u8>,
    },
    Close,
}

#[derive(Clone, Copy)]
struct ExchangeOpts {
    dest_forwarded: bool,
    peer: SocketAddr,
    max_head: usize,
    idle: Idle,
    force_close: bool,
}

async fn exchange(
    client: &mut BoxedStream,
    client_reader: &mut Reader,
    backend: &mut BoxedStream,
    backend_reader: &mut Reader,
    head: &mut Head,
    buffered_body: Option<Vec<u8>>,
    opts: &ExchangeOpts,
) -> Result<ExchangeResult> {
    let max_head = opts.max_head;
    let idle = opts.idle;

    let flags = head.conn_flags();
    let is_ws = flags.is_websocket_upgrade;
    let client_close = opts.force_close || flags.close;

    let expects_continue = head.expects_continue();
    let req_method = head.method.clone();

    apply_outbound_forwarded(head, opts.dest_forwarded, opts.peer.ip());

    let serialized = head.serialize(false, is_ws);
    push_backend(backend, &serialized).await?;

    let buffered_len = buffered_body.as_ref().map(|b| b.len());
    if let Some(body) = &buffered_body {
        push_backend(backend, body).await?;
    }

    if is_ws {
        flush_backend(backend).await?;
        let resp = read_backend_head(backend, backend_reader, max_head, idle.body).await?;
        if resp.status == 101 {
            let resp_bytes = resp.serialize(false, true);
            write_client(client, &resp_bytes).await?;
            let to_backend = client_reader.take_data();
            let to_client = backend_reader.take_data();
            return Ok(ExchangeResult::Hijack {
                to_backend,
                to_client,
            });
        }
        return finish_response(
            client,
            backend,
            backend_reader,
            &req_method,
            resp,
            client_close,
            idle,
        )
        .await;
    }

    if expects_continue {
        flush_backend(backend).await?;
        loop {
            let interim = read_backend_head(backend, backend_reader, max_head, idle.body).await?;
            if interim.status == 100 {
                write_client(client, &interim.serialize(false, false)).await?;
                stream_request_remainder(client, client_reader, backend, head, buffered_len, idle)
                    .await?;
                flush_backend(backend).await?;
                return relay_response(
                    client,
                    backend,
                    backend_reader,
                    &req_method,
                    max_head,
                    client_close,
                    idle,
                )
                .await;
            }
            if (100..200).contains(&interim.status) {
                write_client(client, &interim.serialize(false, false)).await?;
                continue;
            }
            return finish_response(
                client,
                backend,
                backend_reader,
                &req_method,
                interim,
                true,
                idle,
            )
            .await;
        }
    }

    stream_request_remainder(client, client_reader, backend, head, buffered_len, idle).await?;
    flush_backend(backend).await?;

    relay_response(
        client,
        backend,
        backend_reader,
        &req_method,
        max_head,
        client_close,
        idle,
    )
    .await
}

async fn stream_request_remainder(
    client: &mut BoxedStream,
    client_reader: &mut Reader,
    backend: &mut BoxedStream,
    head: &Head,
    already_forwarded: Option<usize>,
    idle: Idle,
) -> Result<()> {
    match head.framing {
        BodyFraming::None | BodyFraming::UntilClose => Ok(()),
        BodyFraming::Length(n) => {
            let remaining = n.saturating_sub(already_forwarded.unwrap_or(0) as u64);
            transfer_length(client, client_reader, backend, true, remaining, idle.body).await
        }
        BodyFraming::Chunked => {
            transfer_chunked(client, client_reader, backend, true, idle.body).await
        }
    }
}

async fn relay_response(
    client: &mut BoxedStream,
    backend: &mut BoxedStream,
    backend_reader: &mut Reader,
    req_method: &str,
    max_head: usize,
    client_close: bool,
    idle: Idle,
) -> Result<ExchangeResult> {
    loop {
        let resp = read_backend_head(backend, backend_reader, max_head, idle.body).await?;
        if (100..200).contains(&resp.status) {
            write_client(client, &resp.serialize(false, false)).await?;
            continue;
        }
        return finish_response(
            client,
            backend,
            backend_reader,
            req_method,
            resp,
            client_close,
            idle,
        )
        .await;
    }
}

async fn finish_response(
    client: &mut BoxedStream,
    backend: &mut BoxedStream,
    backend_reader: &mut Reader,
    req_method: &str,
    resp: Head,
    force_close: bool,
    idle: Idle,
) -> Result<ExchangeResult> {
    let force_close = force_close || resp.conn_flags().close;
    let is_sse = resp.is_sse();
    let no_body = response_no_body(req_method, &resp);
    let bytes = resp.serialize(force_close, false);
    push_client(client, &bytes).await?;

    let done = || {
        if force_close {
            ExchangeResult::Close
        } else {
            ExchangeResult::KeepAlive
        }
    };

    if no_body {
        flush_client(client).await?;
        return Ok(done());
    }

    if is_sse {
        flush_client(client).await?;
        stream_until_close(backend, backend_reader, client, false, idle.stream).await?;
        return Ok(ExchangeResult::Close);
    }

    match resp.framing {
        BodyFraming::None => {
            flush_client(client).await?;
            Ok(done())
        }
        BodyFraming::Length(n) => {
            transfer_length(backend, backend_reader, client, false, n, idle.body).await?;
            flush_client(client).await?;
            Ok(done())
        }
        BodyFraming::Chunked => {
            transfer_chunked(backend, backend_reader, client, false, idle.body).await?;
            flush_client(client).await?;
            Ok(done())
        }
        BodyFraming::UntilClose => {
            flush_client(client).await?;
            stream_until_close(backend, backend_reader, client, false, idle.stream).await?;
            Ok(ExchangeResult::Close)
        }
    }
}

async fn buffer_body(
    client: &mut BoxedStream,
    reader: &mut Reader,
    head: &Head,
    cap: usize,
    idle: Duration,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    if let BodyFraming::Length(n) = head.framing {
        let want = (n as usize).min(cap);
        while body.len() < want {
            if reader.is_empty() {
                let got = reader.fill(client, idle).await?;
                if got == 0 {
                    break;
                }
            }
            let take = {
                let avail = reader.data();
                let take = (want - body.len()).min(avail.len());
                body.extend_from_slice(&avail[..take]);
                take
            };
            reader.consume(take);
        }
    }
    Ok(body)
}

async fn drain_buffered(
    client: &mut BoxedStream,
    reader: &mut Reader,
    head: &Head,
    already: usize,
    idle: Duration,
) -> Result<()> {
    if let BodyFraming::Length(n) = head.framing {
        let mut remaining = (n as usize).saturating_sub(already) as u64;
        while remaining > 0 {
            if reader.is_empty() {
                let got = reader.fill(client, idle).await?;
                if got == 0 {
                    break;
                }
            }
            let take = (remaining as usize).min(reader.data().len());
            reader.consume(take);
            remaining -= take as u64;
        }
    }
    Ok(())
}

async fn prepare(
    ctx: &Ctx,
    router: &HttpRouter,
    client: &mut BoxedStream,
    reader: &mut Reader,
    head: &mut Head,
    body_cap: usize,
    body_idle: Duration,
) -> Result<Option<(Option<Vec<u8>>, String)>> {
    let idx = match router.match_index(head) {
        Some(i) => i,
        None => return Ok(None),
    };

    let body = if router.needs_body_at(idx) {
        if head.expects_continue() {
            write_client(client, b"HTTP/1.1 100 Continue\r\n\r\n").await?;
            head.remove_header("expect");
        }
        Some(buffer_body(client, reader, head, body_cap, body_idle).await?)
    } else {
        None
    };

    let dest_id = match router.route_at(idx, head, body.as_deref()) {
        RouteOutcome::Pin { dest_id } => dest_id,
        RouteOutcome::Identifier {
            identifier,
            fallback,
        } => {
            if identifier.is_none() && fallback.is_none() {
                ctx.resolve(None).await.to_string()
            } else {
                ctx.resolve(identifier.as_deref()).await.to_string()
            }
        }
    };

    Ok(Some((body, dest_id)))
}

fn reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        502 => "Bad Gateway",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}
