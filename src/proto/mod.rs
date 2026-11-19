/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod backend;
pub mod forward;
pub mod imap;
pub mod managesieve;
pub mod passthrough;
pub mod pop3;
pub mod sasl_exchange;
pub mod session;
pub mod submission;

use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::Protocol;
use crate::error::Result;
use crate::http;
use crate::net::stream::ClientStream;
use crate::runtime::{ListenerId, Runtime};

pub async fn dispatch(
    rt: Arc<Runtime>,
    protocol: Protocol,
    id: ListenerId,
    stream: ClientStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    match protocol {
        Protocol::Imap => imap::handle(rt, id, stream, peer, local).await,
        Protocol::Pop3 => pop3::handle(rt, id, stream, peer, local).await,
        Protocol::ManageSieve => managesieve::handle(rt, id, stream, peer, local).await,
        Protocol::Submission => submission::handle(rt, id, stream, peer, local).await,
        Protocol::Smtp | Protocol::Lmtp => passthrough::handle(rt, id, stream, peer, local).await,
        Protocol::Http => http::proxy::handle(rt, id, stream, peer, local).await,
    }
}
