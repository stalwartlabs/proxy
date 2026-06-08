/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::borrow::Cow;

pub type Result<T> = std::result::Result<T, ProxyError>;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("configuration error: {0}")]
    Config(Cow<'static, str>),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("tls error: {0}")]
    Tls(Cow<'static, str>),

    #[error("backend unavailable: {0}")]
    BackendUnavailable(Cow<'static, str>),

    #[error("backend connection failed: {0}")]
    BackendConnect(Cow<'static, str>),

    #[error("protocol error: {0}")]
    Protocol(Cow<'static, str>),

    #[error("the pre-auth dialogue exceeded its limits: {0}")]
    PreAuth(Cow<'static, str>),

    #[error("connection closed")]
    Closed,
}

impl ProxyError {
    pub fn config(msg: impl Into<Cow<'static, str>>) -> Self {
        ProxyError::Config(msg.into())
    }

    pub fn tls(msg: impl Into<Cow<'static, str>>) -> Self {
        ProxyError::Tls(msg.into())
    }

    pub fn backend(msg: impl Into<Cow<'static, str>>) -> Self {
        ProxyError::BackendUnavailable(msg.into())
    }

    pub fn backend_connect(msg: impl Into<Cow<'static, str>>) -> Self {
        ProxyError::BackendConnect(msg.into())
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, ProxyError::BackendConnect(_) | ProxyError::Io(_))
    }

    pub fn protocol(msg: impl Into<Cow<'static, str>>) -> Self {
        ProxyError::Protocol(msg.into())
    }

    pub fn preauth(msg: impl Into<Cow<'static, str>>) -> Self {
        ProxyError::PreAuth(msg.into())
    }
}
