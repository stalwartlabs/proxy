/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::process::{Command, Stdio};
use std::sync::{Arc, Once, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use testcontainers::runners::AsyncBuilder;
use testcontainers::{GenericBuildableImage, GenericImage};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

use crate::net::acceptor::Listener;
use crate::proto::common::Ctx;

use super::harness::make_ctx;

pub mod clients;
pub mod http;
pub mod jmap;
pub mod legacy;
pub mod limits;
pub mod master_user_and_load;
pub mod oauth;
pub mod scenario1;
pub mod scenario2;
pub mod stalwart;
pub mod toolbox;
pub mod toolbox_http;
pub mod toolbox_matrix;

pub const HOST_GATEWAY: &str = "host.docker.internal";

pub const OWNER_LABEL: &str = "art.stalw.proxy.test";

pub fn pick_free_port() -> u16 {
    let l = StdTcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn run_id() -> &'static str {
    static RUN_ID: OnceLock<String> = OnceLock::new();
    RUN_ID.get_or_init(|| {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!("{}-{nanos}", std::process::id())
    })
}

pub fn owner_labels() -> [(&'static str, &'static str); 1] {
    sweep_abandoned_containers();
    [(OWNER_LABEL, run_id())]
}

fn docker_ids(filter: &str) -> Vec<String> {
    Command::new("docker")
        .args(["ps", "-aq", "--filter", filter])
        .output()
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn sweep_abandoned_containers() {
    static SWEPT: Once = Once::new();
    SWEPT.call_once(|| {
        let mine = docker_ids(&format!("label={OWNER_LABEL}={}", run_id()));
        let stale: Vec<String> = docker_ids(&format!("label={OWNER_LABEL}"))
            .into_iter()
            .filter(|id| !mine.contains(id))
            .collect();
        if stale.is_empty() {
            return;
        }
        eprintln!("removing {} abandoned test container(s)", stale.len());
        let _ = Command::new("docker")
            .args(["rm", "-f", "-v"])
            .args(&stale)
            .output();
    });
}

fn content_tag(dockerfile: &str, data: &[(&str, &[u8])]) -> String {
    let mut hasher = ahash::RandomState::with_seeds(0x5354, 0x414c, 0x5741, 0x5254).build_hasher();
    dockerfile.hash(&mut hasher);
    for (target, bytes) in data {
        target.hash(&mut hasher);
        bytes.hash(&mut hasher);
    }
    format!("{:016x}", hasher.finish())
}

async fn image_present(reference: &str) -> bool {
    tokio::process::Command::new("docker")
        .args(["image", "inspect", reference])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|status| status.success())
        .unwrap_or(false)
}

pub async fn ensure_image(name: &str, dockerfile: &str, data: &[(&str, &[u8])]) -> GenericImage {
    static BUILD_LOCK: Mutex<()> = Mutex::const_new(());
    let tag = content_tag(dockerfile, data);
    let _guard = BUILD_LOCK.lock().await;
    if image_present(&format!("{name}:{tag}")).await {
        return GenericImage::new(name.to_owned(), tag);
    }
    let mut builder =
        GenericBuildableImage::new(name, &tag).with_dockerfile_string(dockerfile.to_string());
    for (target, bytes) in data {
        builder = builder.with_data(bytes.to_vec(), *target);
    }
    builder
        .build_image()
        .await
        .unwrap_or_else(|e| panic!("build image {name}:{tag}: {e}"))
}

pub struct Proxy {
    shutdown: watch::Sender<bool>,
    handles: Vec<JoinHandle<()>>,
    listeners: HashMap<String, SocketAddr>,
    admin: Option<SocketAddr>,
    _ctx: Arc<Ctx>,
}

impl Proxy {
    pub async fn launch(toml: &str) -> Proxy {
        let ctx = make_ctx(toml).await;
        let config = ctx.config.clone();
        let shared = Arc::new(arc_swap::ArcSwap::new(ctx.clone()));
        let (shutdown, rx) = watch::channel(false);
        let mut handles = Vec::new();
        let mut listeners = HashMap::new();

        for (id, listener_cfg) in &config.listener {
            let bind = *listener_cfg
                .bind
                .first()
                .expect("listener has at least one bind address");
            listeners.insert(id.clone(), bind);
            let listener = Arc::new(Listener::new(
                id.as_str().into(),
                Arc::new(listener_cfg.clone()),
            ));
            let shared = shared.clone();
            let rx = rx.clone();
            handles.push(tokio::spawn(async move {
                listener.run(shared, rx).await;
            }));
        }

        let mut admin = None;
        if let Some(admin_cfg) = &config.admin {
            admin = Some(admin_cfg.bind);
            let shared = shared.clone();
            let config = config.clone();
            handles.push(tokio::spawn(async move {
                let _ = crate::admin::run(shared, config, None).await;
            }));
        }

        let proxy = Proxy {
            shutdown,
            handles,
            listeners,
            admin,
            _ctx: ctx,
        };
        for addr in proxy.listeners.values() {
            wait_listening(*addr).await;
        }
        if let Some(addr) = proxy.admin {
            wait_listening(addr).await;
        }
        proxy
    }

    pub fn port(&self, listener_id: &str) -> u16 {
        self.listeners
            .get(listener_id)
            .unwrap_or_else(|| panic!("unknown listener {listener_id:?}"))
            .port()
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        for handle in &self.handles {
            handle.abort();
        }
    }
}

async fn wait_listening(addr: SocketAddr) {
    let target = if addr.ip().is_unspecified() {
        SocketAddr::new("127.0.0.1".parse().unwrap(), addr.port())
    } else {
        addr
    };
    for _ in 0..200 {
        if TcpStream::connect(target).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("proxy listener {addr} never came up");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::harness::{dummy_backend, mapping_file};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn launcher_binds_and_bridges_pop3() {
        let (backend_port, backend) = dummy_backend(|mut sock| async move {
            sock.write_all(b"+OK dummy ready\r\n").await.unwrap();
            let mut buf = [0u8; 256];
            let _ = sock.read(&mut buf).await;
        })
        .await;

        let map = mapping_file("user@example.com\tlegacy\n");
        let listen_port = pick_free_port();
        let toml = format!(
            r#"
[mapping]
source = "file"
normalize = "lowercase"
[mapping.file]
path = "{}"

[routing]
default_destination = "legacy"

[destination.legacy]
host = "127.0.0.1"
forwarding = "none"
allow_plaintext_auth = true
[destination.legacy.protocol.pop3]
port = {backend_port}
tls = "plain"

[capabilities.pop3]
allow_plain_auth_without_tls = true

[listener.pop3]
protocol = "pop3"
bind = ["0.0.0.0:{listen_port}"]
tls = "plain"
"#,
            map.path().display()
        );

        let proxy = Proxy::launch(&toml).await;
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port("pop3")))
            .await
            .unwrap();
        let mut greeting = [0u8; 64];
        let n = client.read(&mut greeting).await.unwrap();
        assert!(
            greeting[..n].starts_with(b"+OK"),
            "expected POP3 greeting, got {:?}",
            String::from_utf8_lossy(&greeting[..n])
        );
        drop(proxy);
        backend.abort();
    }
}
