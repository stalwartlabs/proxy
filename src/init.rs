/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::ffi::OsString;
use std::fmt::Write as _;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::config::Config;
use crate::config::confine::{CERTS_DIR, MAPPINGS_DIR};
use crate::config::tls::ADMIN_CERTIFICATE_ID;

const CONFIG_FILE: &str = "config.toml";
const TOKEN_FILE: &str = "admin-token";
const CERT_FILE: &str = "admin.crt";
const KEY_FILE: &str = "admin.key";
const STAGING_SUFFIX: &str = ".init-tmp";
const FIRST_UNPRIVILEGED_PORT: u16 = 1024;
const LISTENER_PORTS: [u16; 10] = [24, 25, 80, 110, 143, 443, 465, 587, 993, 995];
const DESTINATION_PORTS: [u16; 12] = [24, 25, 110, 143, 443, 465, 587, 993, 995, 4190, 8080, 8443];
#[cfg(unix)]
const WORLD_WRITABLE: u32 = 0o002;
#[cfg(unix)]
const GROUP_WRITABLE: u32 = 0o020;
const ADMIN_BIND_FLAG: &str = "--admin-bind";
const DEFAULT_ADMIN_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9443);
const TOKEN_BYTES: usize = 32;
const CERT_NAMES: [&str; 3] = ["localhost", "127.0.0.1", "::1"];
const EXIT_USAGE: u8 = 2;
const EXIT_EXISTS: u8 = 3;
pub const USAGE: &str = "usage: proxy init <dir> [--admin-bind <ip:port>]";

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("{0}\n{USAGE}")]
    Usage(String),
    #[error("{} already exists; nothing was written", .0.display())]
    Initialized(PathBuf),
    #[error("{}: {reason}; nothing was written", path.display())]
    Unsafe { path: PathBuf, reason: &'static str },
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
    #[error("{0}")]
    Generate(String),
}

impl InitError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            InitError::Usage(_) => ExitCode::from(EXIT_USAGE),
            InitError::Initialized(_) => ExitCode::from(EXIT_EXISTS),
            InitError::Unsafe { .. } | InitError::Io { .. } | InitError::Generate(_) => {
                ExitCode::FAILURE
            }
        }
    }

    fn io(path: &Path) -> impl FnOnce(io::Error) -> InitError + '_ {
        move |source| InitError::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    fn unsafe_path(path: &Path, reason: &'static str) -> InitError {
        InitError::Unsafe {
            path: path.to_path_buf(),
            reason,
        }
    }
}

pub struct Init {
    dir: PathBuf,
    admin_bind: SocketAddr,
}

pub struct Initialized {
    pub config: PathBuf,
    pub token: PathBuf,
    pub url: String,
    pub fingerprint: String,
}

struct Layout {
    dir: PathBuf,
    config: PathBuf,
    token: PathBuf,
    certs: PathBuf,
    mappings: PathBuf,
    cert: PathBuf,
    key: PathBuf,
}

struct Staged {
    files: Vec<(PathBuf, PathBuf)>,
}

impl Init {
    pub fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, InitError> {
        let mut dir = None;
        let mut admin_bind = DEFAULT_ADMIN_BIND;
        while let Some(arg) = args.next() {
            let bind = match arg.strip_prefix(ADMIN_BIND_FLAG) {
                Some("") => args
                    .next()
                    .ok_or_else(|| InitError::Usage(format!("{ADMIN_BIND_FLAG} needs a value")))?,
                Some(inline) => match inline.strip_prefix('=') {
                    Some(value) => value.to_string(),
                    None => return Err(InitError::Usage(format!("unknown option {arg:?}"))),
                },
                None if arg.starts_with('-') => {
                    return Err(InitError::Usage(format!("unknown option {arg:?}")));
                }
                None if dir.is_none() => {
                    dir = Some(PathBuf::from(arg));
                    continue;
                }
                None => return Err(InitError::Usage(format!("unexpected argument {arg:?}"))),
            };
            admin_bind = bind.parse().map_err(|_| {
                InitError::Usage(format!(
                    "{ADMIN_BIND_FLAG}: {bind:?} is not an ip:port address"
                ))
            })?;
        }
        let dir = dir.ok_or_else(|| InitError::Usage("missing <dir>".to_string()))?;
        Ok(Init { dir, admin_bind })
    }

    pub fn run(&self) -> Result<Initialized, InitError> {
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder
            .create(&self.dir)
            .map_err(InitError::io(&self.dir))?;
        let dir = fs::canonicalize(&self.dir).map_err(InitError::io(&self.dir))?;
        let layout = Layout::in_dir(dir);
        let dir_meta = Layout::private_dir_meta(&layout.dir)?;
        if fs::symlink_metadata(&layout.config).is_ok() {
            return Err(InitError::Initialized(layout.config));
        }
        let token = Self::token()?;
        let cert = self.certificate()?;
        let fingerprint = Self::fingerprint(cert.cert.der());
        let config = self.config_text(&layout)?;
        Config::parse(&config).map_err(|err| InitError::Generate(err.to_string()))?;

        let certs_meta = Layout::create_private_dir(&layout.certs)?;
        Layout::create_private_dir(&layout.mappings)?;
        let mut staged = Staged {
            files: Vec::with_capacity(4),
        };
        let probe = staged.write(&layout.key, cert.signing_key.serialize_pem().as_bytes())?;
        Layout::check_owner(
            &probe,
            &layout.key,
            [(&layout.dir, &dir_meta), (&layout.certs, &certs_meta)],
        )?;
        staged.write(&layout.cert, cert.cert.pem().as_bytes())?;
        staged.write(&layout.token, token.as_bytes())?;
        staged.write(&layout.config, config.as_bytes())?;
        staged.commit(&layout)?;
        Ok(Initialized {
            config: layout.config,
            token: layout.token,
            url: format!("https://{}/ui/", self.reachable_bind()),
            fingerprint,
        })
    }

    fn token() -> Result<String, InitError> {
        let mut bytes = [0u8; TOKEN_BYTES];
        aws_lc_rs::rand::fill(&mut bytes)
            .map_err(|_| InitError::Generate("system random source unavailable".to_string()))?;
        let mut token = String::with_capacity(TOKEN_BYTES * 2 + 1);
        for byte in bytes {
            let _ = write!(token, "{byte:02x}");
        }
        token.push('\n');
        Ok(token)
    }

    fn certificate(&self) -> Result<rcgen::CertifiedKey<rcgen::KeyPair>, InitError> {
        let ip = self.admin_bind.ip();
        let mut names: Vec<String> = CERT_NAMES.iter().map(|name| name.to_string()).collect();
        if !ip.is_unspecified()
            && ip != IpAddr::V4(Ipv4Addr::LOCALHOST)
            && ip != IpAddr::V6(Ipv6Addr::LOCALHOST)
        {
            names.push(ip.to_string());
        }
        rcgen::generate_simple_self_signed(names)
            .map_err(|err| InitError::Generate(format!("self-signed certificate: {err}")))
    }

    fn fingerprint(der: &[u8]) -> String {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, der);
        let mut out = String::with_capacity(digest.as_ref().len() * 3);
        for byte in digest.as_ref() {
            if !out.is_empty() {
                out.push(':');
            }
            let _ = write!(out, "{byte:02X}");
        }
        out
    }

    fn config_text(&self, layout: &Layout) -> Result<String, InitError> {
        let quoted = |path: &Path| {
            path.to_str()
                .map(|text| toml::Value::String(text.to_string()).to_string())
                .ok_or_else(|| {
                    InitError::Generate(format!("{} is not valid UTF-8", path.display()))
                })
        };
        let mut text = format!(
            "[admin]\nbind = \"{}\"\nbearer_token_file = {}\nconfig_write = true\n\n[admin.allow]\nlistener_ports = [",
            self.admin_bind,
            quoted(&layout.token)?,
        );
        self.write_listener_ports(&mut text);
        text.push_str("]\ndestination_ports = [");
        Self::write_ports(&mut text, DESTINATION_PORTS.iter().copied());
        let _ = write!(
            text,
            "]\n\n[tls.certificate.{ADMIN_CERTIFICATE_ID}]\ncert = {}\nkey = {}\ndefault = true\n",
            quoted(&layout.cert)?,
            quoted(&layout.key)?,
        );
        Ok(text)
    }

    fn write_listener_ports(&self, text: &mut String) {
        let admin = self.admin_bind.port();
        Self::write_ports(
            text,
            LISTENER_PORTS.iter().copied().filter(|port| *port != admin),
        );
        let ranges = match (FIRST_UNPRIVILEGED_PORT..=u16::MAX).contains(&admin) {
            true => [
                (admin > FIRST_UNPRIVILEGED_PORT).then(|| (FIRST_UNPRIVILEGED_PORT, admin - 1)),
                (admin < u16::MAX).then(|| (admin + 1, u16::MAX)),
            ],
            false => [Some((FIRST_UNPRIVILEGED_PORT, u16::MAX)), None],
        };
        for (first, last) in ranges.into_iter().flatten() {
            let _ = match first == last {
                true => write!(text, ", {first}"),
                false => write!(text, ", \"{first}-{last}\""),
            };
        }
    }

    fn write_ports(text: &mut String, ports: impl Iterator<Item = u16>) {
        for (index, port) in ports.enumerate() {
            if index > 0 {
                text.push_str(", ");
            }
            let _ = write!(text, "{port}");
        }
    }

    fn reachable_bind(&self) -> SocketAddr {
        let ip = match self.admin_bind.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip => ip,
        };
        SocketAddr::new(ip, self.admin_bind.port())
    }
}

impl Layout {
    fn in_dir(dir: PathBuf) -> Self {
        let certs = dir.join(CERTS_DIR);
        Layout {
            config: dir.join(CONFIG_FILE),
            token: dir.join(TOKEN_FILE),
            mappings: dir.join(MAPPINGS_DIR),
            cert: certs.join(CERT_FILE),
            key: certs.join(KEY_FILE),
            certs,
            dir,
        }
    }

    fn create_private_dir(path: &Path) -> Result<Metadata, InitError> {
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        match builder.create(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(InitError::io(path)(err)),
        }
        Self::private_dir_meta(path)
    }

    fn private_dir_meta(path: &Path) -> Result<Metadata, InitError> {
        let meta = fs::symlink_metadata(path).map_err(InitError::io(path))?;
        if meta.file_type().is_symlink() {
            return Err(InitError::unsafe_path(path, "is a symbolic link"));
        }
        if !meta.is_dir() {
            return Err(InitError::unsafe_path(path, "is not a directory"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if mode & WORLD_WRITABLE != 0 {
                return Err(InitError::unsafe_path(path, "is world-writable"));
            }
            if mode & GROUP_WRITABLE != 0 {
                eprintln!(
                    "warning: {} is group-writable; members of its group can replace the admin configuration",
                    path.display()
                );
            }
        }
        Ok(meta)
    }

    #[cfg(unix)]
    fn check_owner<'a>(
        probe: &File,
        probe_path: &Path,
        dirs: impl IntoIterator<Item = (&'a PathBuf, &'a Metadata)>,
    ) -> Result<(), InitError> {
        use std::os::unix::fs::MetadataExt;
        let uid = probe.metadata().map_err(InitError::io(probe_path))?.uid();
        match dirs.into_iter().find(|(_, meta)| meta.uid() != uid) {
            Some((path, _)) => Err(InitError::unsafe_path(
                path,
                "is owned by another user than the one running init",
            )),
            None => Ok(()),
        }
    }

    #[cfg(not(unix))]
    fn check_owner<'a>(
        _probe: &File,
        _probe_path: &Path,
        _dirs: impl IntoIterator<Item = (&'a PathBuf, &'a Metadata)>,
    ) -> Result<(), InitError> {
        Ok(())
    }

    #[cfg(unix)]
    fn sync_dir(path: &Path) -> Result<(), InitError> {
        File::open(path)
            .and_then(|dir| dir.sync_all())
            .map_err(InitError::io(path))
    }

    #[cfg(not(unix))]
    fn sync_dir(_path: &Path) -> Result<(), InitError> {
        Ok(())
    }
}

impl Staged {
    fn write(&mut self, path: &Path, bytes: &[u8]) -> Result<File, InitError> {
        let mut staging = OsString::from(path.as_os_str());
        staging.push(STAGING_SUFFIX);
        let staging = PathBuf::from(staging);
        match fs::remove_file(&staging) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(InitError::io(&staging)(err)),
        }
        let mut file = Self::create(&staging).map_err(InitError::io(&staging))?;
        self.files.push((staging.clone(), path.to_path_buf()));
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(InitError::io(&staging))?;
        Ok(file)
    }

    fn commit(mut self, layout: &Layout) -> Result<(), InitError> {
        for (staging, path) in &self.files {
            fs::rename(staging, path).map_err(InitError::io(path))?;
        }
        self.files.clear();
        Layout::sync_dir(&layout.certs)?;
        Layout::sync_dir(&layout.dir)
    }

    #[cfg(unix)]
    fn create(path: &Path) -> io::Result<File> {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    }

    #[cfg(not(unix))]
    fn create(path: &Path) -> io::Result<File> {
        OpenOptions::new().write(true).create_new(true).open(path)
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        for (staging, _) in &self.files {
            let _ = fs::remove_file(staging);
        }
    }
}

impl Initialized {
    pub fn print(&self) {
        println!("config: {}", self.config.display());
        println!("token file: {}", self.token.display());
        println!("admin UI: {}", self.url);
        println!("certificate sha256: {}", self.fingerprint);
    }
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../proxy-tests/unit/src/init/tests.rs"]
mod tests;
