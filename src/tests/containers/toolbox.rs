/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::time::Duration;

use testcontainers::core::{ExecCommand, Host, WaitFor};
use testcontainers::runners::{AsyncBuilder, AsyncRunner};
use testcontainers::{ContainerAsync, GenericBuildableImage, GenericImage, ImageExt};
use tokio::io::AsyncReadExt;

use super::HOST_GATEWAY;

const DOCKERFILE: &str = r#"FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl openssl swaks msmtp isync getmail6 fetchmail \
      sieve-connect dovecot-core cyrus-clients neomutt vdirsyncer \
      python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir jmapc sievelib
RUN set -eu; arch="$(uname -m)"; case "$arch" in \
      aarch64|arm64) asset="websocat.aarch64-unknown-linux-musl";; \
      x86_64|amd64)  asset="websocat.x86_64-unknown-linux-musl";; \
      *) echo "unsupported arch $arch" >&2; exit 1;; esac; \
    curl -fsSL -o /usr/local/bin/websocat \
      "https://github.com/vi/websocat/releases/latest/download/$asset"; \
    chmod +x /usr/local/bin/websocat
ENV PATH=/opt/venv/bin:/usr/lib/cyrus/bin:$PATH
CMD ["sleep", "infinity"]
"#;

pub struct Toolbox {
    container: ContainerAsync<GenericImage>,
}

pub struct Exec {
    pub code: i64,
    pub stdout: String,
    pub stderr: String,
}

impl Exec {
    pub fn ok(&self) -> bool {
        self.code == 0
    }

    pub fn combined(&self) -> String {
        format!("{}{}", self.stdout, self.stderr)
    }
}

impl Toolbox {
    pub async fn start() -> Toolbox {
        let image: GenericImage = GenericBuildableImage::new("proxy-toolbox", "test")
            .with_dockerfile_string(DOCKERFILE.to_string())
            .build_image()
            .await
            .expect("build toolbox image");

        let container = image
            .with_wait_for(WaitFor::seconds(1))
            .with_startup_timeout(Duration::from_secs(300))
            .with_host(HOST_GATEWAY, Host::HostGateway)
            .start()
            .await
            .expect("start toolbox container");

        Toolbox { container }
    }

    pub async fn run(&self, argv: &[&str]) -> Exec {
        let mut result = self
            .container
            .exec(ExecCommand::new(argv.iter().map(|s| s.to_string())))
            .await
            .expect("toolbox exec");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let _ = result.stdout().read_to_end(&mut stdout).await;
        let _ = result.stderr().read_to_end(&mut stderr).await;
        let code = result.exit_code().await.ok().flatten().unwrap_or(-1);
        Exec {
            code,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        }
    }

    pub async fn sh(&self, script: &str) -> Exec {
        self.run(&["sh", "-c", script]).await
    }
}
