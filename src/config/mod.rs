/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

pub mod admin;
pub mod allow;
pub mod capabilities;
pub mod confine;
pub mod destination;
pub mod duration;
pub mod edit;
pub mod http;
pub mod listener;
pub mod mapping;
pub mod routing;
pub mod schema;
pub mod secret;
pub mod server;
pub mod tls;

use std::str::FromStr;
use std::time::Duration;

use ahash::AHashMap;
use serde::{Deserialize, Serialize};

use crate::error::{ConfigError, ConfigErrors, ProxyError, Result};

pub use admin::AdminConfig;
pub use capabilities::{
    CapabilitiesConfig, ImapCapabilities, ManageSieveCapabilities, Pop3Capabilities,
    SubmissionCapabilities,
};
pub use destination::{DestProtocol, DestinationConfig, Forwarding};
pub use http::{ExtractFrom, HttpConfig, HttpExtract, HttpRoute};
pub use listener::{ForwardedMode, ListenerConfig, ProxyProtocolMode};
pub use mapping::{MappingConfig, MappingSource, Normalize, RedisMappingConfig, SqlMappingConfig};
pub use routing::{DEFAULT_JWT_CLAIM, OAuthConfig, RoutingConfig};
pub use server::ServerConfig;
pub use tls::TlsConfig;

macro_rules! protocols {
    ($($variant:ident => $name:tt),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
        pub enum Protocol {
            $(#[serde(rename = $name)] $variant,)+
        }

        impl Protocol {
            pub const ALL: [Protocol; [$($name),+].len()] = [$(Protocol::$variant),+];

            pub fn parse(name: &[u8]) -> Option<Protocol> {
                hashify::map!(name, Protocol, $($name => Protocol::$variant),+).copied()
            }

            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Protocol::$variant => $name),+
                }
            }
        }
    };
}

protocols! {
    Smtp => "smtp",
    Submission => "submission",
    Lmtp => "lmtp",
    Imap => "imap",
    Pop3 => "pop3",
    ManageSieve => "managesieve",
    Http => "http",
}

impl Protocol {
    pub const COUNT: usize = Self::ALL.len();

    pub const fn index(self) -> usize {
        self as usize
    }

    pub fn is_credential_bearing(&self) -> bool {
        matches!(
            self,
            Protocol::Imap
                | Protocol::Pop3
                | Protocol::ManageSieve
                | Protocol::Submission
                | Protocol::Http
        )
    }

    pub fn is_passthrough(&self) -> bool {
        matches!(self, Protocol::Smtp | Protocol::Lmtp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsMode {
    Implicit,
    Starttls,
    Plain,
}

impl TlsMode {
    fn implicit() -> Self {
        TlsMode::Implicit
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TlsMode::Implicit => "implicit",
            TlsMode::Starttls => "starttls",
            TlsMode::Plain => "plain",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Revision([u8; Revision::LEN]);

impl Revision {
    const LEN: usize = 6;

    fn hex_digit(digit: u8) -> std::result::Result<u8, InvalidRevision> {
        match digit {
            b'0'..=b'9' => Ok(digit - b'0'),
            b'a'..=b'f' => Ok(digit - b'a' + 10),
            b'A'..=b'F' => Ok(digit - b'A' + 10),
            _ => Err(InvalidRevision),
        }
    }

    pub fn of(source: &[u8]) -> Self {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, source);
        let mut out = [0u8; Self::LEN];
        if let Some(prefix) = digest.as_ref().first_chunk::<{ Self::LEN }>() {
            out = *prefix;
        }
        Revision(out)
    }
}

impl std::fmt::Display for Revision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl FromStr for Revision {
    type Err = InvalidRevision;

    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        let mut out = [0u8; Self::LEN];
        let (pairs, []) = text.as_bytes().as_chunks::<2>() else {
            return Err(InvalidRevision);
        };
        if pairs.len() != Self::LEN {
            return Err(InvalidRevision);
        }
        for (byte, [high, low]) in out.iter_mut().zip(pairs) {
            *byte = (Self::hex_digit(*high)? << 4) | Self::hex_digit(*low)?;
        }
        Ok(Revision(out))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid config revision")]
pub struct InvalidRevision;

impl Serialize for Revision {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub listener: AHashMap<String, ListenerConfig>,
    #[serde(default)]
    pub destination: AHashMap<String, DestinationConfig>,
    #[serde(default)]
    pub routing: Option<RoutingConfig>,
    #[serde(default)]
    pub mapping: Option<MappingConfig>,
    #[serde(default)]
    pub capabilities: CapabilitiesConfig,
    #[serde(default)]
    pub oauth: OAuthConfig,
    #[serde(default)]
    pub http: HttpConfig,
    pub admin: Option<AdminConfig>,
}

pub(crate) fn line_of(raw: &str, offset: usize) -> Option<u32> {
    let before = raw.as_bytes().get(..offset)?;
    u32::try_from(memchr::memchr_iter(b'\n', before).count() + 1).ok()
}

fn secs<const N: u64>() -> Duration {
    Duration::from_secs(N)
}

fn int<const N: u32>() -> u32 {
    N
}

fn size<const N: usize>() -> usize {
    N
}

fn count<const N: u64>() -> u64 {
    N
}

fn yes() -> bool {
    true
}

impl Config {
    pub fn parse(raw: &str) -> std::result::Result<Self, ConfigErrors> {
        let config: Config = toml::from_str(raw).map_err(|err| {
            let line = err.span().and_then(|span| line_of(raw, span.start));
            ConfigErrors(vec![ConfigError {
                path: Box::default(),
                message: format!("TOML parse: {}", err.message()).into(),
                line,
            }])
        })?;
        config.validate().map(|()| config)
    }

    pub fn parse_and_validate(raw: &str) -> Result<Self> {
        Config::parse(raw).map_err(ProxyError::from)
    }

    pub fn default_destination(&self) -> Option<&str> {
        self.routing
            .as_ref()
            .map(|routing| routing.default_destination.as_str())
    }
}
