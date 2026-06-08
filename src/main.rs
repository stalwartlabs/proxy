/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod admin;
mod config;
mod error;
mod http;
mod imap_receiver;
mod net;
mod observe;
mod outbound;
mod proto;
mod route;
mod sasl;
mod server;
mod token;

#[cfg(test)]
mod tests;

pub use error::{ProxyError, Result};

use std::sync::Arc;

fn main() -> std::process::ExitCode {
    let config_path = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("PROXY_CONFIG").ok());
    let config_path = match config_path {
        Some(p) => p,
        None => {
            eprintln!("usage: proxy <config.toml>  (or set PROXY_CONFIG)");
            return std::process::ExitCode::from(2);
        }
    };

    let raw = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to read config {config_path}: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let config = match config::Config::parse_and_validate(&raw) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("invalid configuration: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    observe::init(&config.server.log_level);

    let threads = if config.server.threads == 0 {
        num_cpus::get()
    } else {
        config.server.threads
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("failed to build tokio runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    match runtime.block_on(server::run(config, Arc::from(config_path))) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "fatal error");
            std::process::ExitCode::FAILURE
        }
    }
}
