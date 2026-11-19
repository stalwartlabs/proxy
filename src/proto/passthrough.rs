/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::net::SocketAddr;
use std::sync::Arc;

use crate::error::{ProxyError, Result, Side, Stage};
use crate::net::bridge::BridgeArgs;
use crate::net::dial::Peers;
use crate::net::stream::ClientStream;
use crate::runtime::metrics::ListenerCounters;
use crate::runtime::registry::NewConn;
use crate::runtime::{ListenerId, Runtime};

pub async fn handle(
    rt: Arc<Runtime>,
    id: ListenerId,
    stream: ClientStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    let listener = rt
        .listener(id)
        .ok_or_else(|| ProxyError::config("listener is not part of the running configuration"))?;
    let dest_id = rt
        .passthrough_dest
        .ok_or_else(|| ProxyError::config("smtp_passthrough_destination not configured"))?;
    let dest = rt
        .destination(dest_id)
        .ok_or_else(|| ProxyError::config("smtp_passthrough_destination was removed"))?;
    let ep = dest.endpoint(listener.protocol)?;
    let peers = Peers { peer, local };
    let backend = rt
        .establish(dest, peer, || dest.dial(ep, peers, &rt.loop_guard))
        .await
        .inspect_err(|_| {
            ListenerCounters::bump(&rt.shared.metrics.listener(id).backend_failures)
        })?;
    let backend_addr = backend
        .peer_addr()
        .map_err(|err| ProxyError::io(Stage::Connect, Side::Backend, err))?;
    let guard = rt.shared.registry.register(NewConn {
        key: None,
        protocol: listener.protocol,
        listener: id,
        client: peer,
        dest: dest_id,
        backend: backend_addr,
        client_tls: stream.tls_info(),
        backend_tls: backend.tls_info(),
    });
    let args = BridgeArgs {
        kick: Some(guard.cancel()),
        info: Some(guard.info().clone()),
        ..BridgeArgs::new(stream, backend, rt.server.bridge_idle)
    };
    drop(rt);
    args.run().await?;
    Ok(())
}
