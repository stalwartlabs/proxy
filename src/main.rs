/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

mod admin;
mod config;
mod error;
mod http;
mod init;
mod net;
mod observe;
mod proto;
mod route;
mod runtime;
mod sasl;
mod server;
mod token;

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../proxy-tests/unit/src/tests/mod.rs"]
mod tests;

pub use error::{ProxyError, Result};

use std::process::ExitCode;
use std::sync::Arc;

use init::Init;
use server::Server;

const INIT_COMMAND: &str = "init";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let config_path = match args.next() {
        Some(command) if command == INIT_COMMAND => {
            return match Init::parse(args).and_then(|init| init.run()) {
                Ok(initialized) => {
                    initialized.print();
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("proxy init: {err}");
                    err.exit_code()
                }
            };
        }
        Some(path) => path,
        None => match std::env::var("PROXY_CONFIG") {
            Ok(path) => path,
            Err(_) => {
                eprintln!(
                    "usage: proxy <config.toml>  (or set PROXY_CONFIG)\n{}",
                    init::USAGE
                );
                return ExitCode::from(2);
            }
        },
    };

    let raw = match std::fs::read_to_string(&config_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to read config {config_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let config = match config::Config::parse_and_validate(&raw) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("invalid configuration: {e}");
            return ExitCode::FAILURE;
        }
    };

    let revision = config::Revision::of(raw.as_bytes());
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
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(Server::run(config, revision, Arc::from(config_path))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "fatal error");
            ExitCode::FAILURE
        }
    }
}
