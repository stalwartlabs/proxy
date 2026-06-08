/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod common;
pub mod forward;
pub mod imap;
pub mod managesieve;
pub mod pop3;
pub mod smtp;

use std::net::SocketAddr;

use crate::config::{ListenerConfig, Protocol};
use crate::error::Result;
use crate::net::BoxedStream;
use common::Ctx;

pub async fn dispatch(
    ctx: &Ctx,
    listener: &ListenerConfig,
    stream: BoxedStream,
    peer: SocketAddr,
    local: SocketAddr,
) -> Result<()> {
    match listener.protocol {
        Protocol::Imap => imap::handle(ctx, listener, stream, peer, local).await,
        Protocol::Pop3 => pop3::handle(ctx, listener, stream, peer, local).await,
        Protocol::ManageSieve => managesieve::handle(ctx, listener, stream, peer, local).await,
        Protocol::Submission => smtp::handle_submission(ctx, listener, stream, peer, local).await,
        Protocol::Smtp | Protocol::Lmtp => {
            smtp::handle_passthrough(ctx, listener, stream, peer, local).await
        }
        Protocol::Http => crate::http::proxy::handle(ctx, listener, stream, peer, local).await,
    }
}
