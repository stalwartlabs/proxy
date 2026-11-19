/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize};

use crate::sasl::SaslMech;

const DEFAULT_SASL: [SaslMech; 4] = [
    SaslMech::Plain,
    SaslMech::Login,
    SaslMech::OAuthBearer,
    SaslMech::XOAuth2,
];

const DEFAULT_IMAP_ADVERTISE: &[&str] = &[
    "IMAP4rev2",
    "IMAP4rev1",
    "ENABLE",
    "SASL-IR",
    "LITERAL+",
    "ID",
    "UTF8=ACCEPT",
    "JMAPACCESS",
];

const DEFAULT_SIEVE_EXT: &[&str] = &[
    "body",
    "comparator-elbonia",
    "comparator-i;ascii-casemap",
    "comparator-i;ascii-numeric",
    "comparator-i;octet",
    "convert",
    "copy",
    "date",
    "duplicate",
    "editheader",
    "enclose",
    "encoded-character",
    "enotify",
    "envelope",
    "envelope-deliverby",
    "envelope-dsn",
    "environment",
    "ereject",
    "extlists",
    "extracttext",
    "fcc",
    "fileinto",
    "foreverypart",
    "ihave",
    "imap4flags",
    "imapsieve",
    "include",
    "index",
    "mailbox",
    "mailboxid",
    "mboxmetadata",
    "mime",
    "redirect-deliverby",
    "redirect-dsn",
    "regex",
    "reject",
    "relational",
    "replace",
    "servermetadata",
    "spamtest",
    "spamtestplus",
    "special-use",
    "subaddress",
    "vacation",
    "vacation-seconds",
    "variables",
    "virustest",
];

const DEFAULT_EHLO: &[&str] = &[
    "ENHANCEDSTATUSCODES",
    "8BITMIME",
    "BINARYMIME",
    "SMTPUTF8",
    "PIPELINING",
    "CHUNKING",
    "REQUIRETLS",
    "SIZE",
];

fn owned(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct CapabilitiesConfig {
    pub imap: ImapCapabilities,
    pub managesieve: ManageSieveCapabilities,
    pub submission: SubmissionCapabilities,
    pub pop3: Pop3Capabilities,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ImapCapabilities {
    pub advertise: Vec<String>,
    #[serde(deserialize_with = "ImapCapabilities::deserialize_sasl")]
    pub sasl: Vec<SaslMech>,
    pub allow_plain_auth_without_tls: bool,
    pub banner: String,
}

impl Default for ImapCapabilities {
    fn default() -> Self {
        ImapCapabilities {
            advertise: owned(DEFAULT_IMAP_ADVERTISE),
            sasl: DEFAULT_SASL.to_vec(),
            allow_plain_auth_without_tls: false,
            banner: "Stalwart IMAP4rev2 at your service.".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ManageSieveCapabilities {
    pub sieve: Vec<String>,
    #[serde(deserialize_with = "ManageSieveCapabilities::deserialize_sasl")]
    pub sasl: Vec<SaslMech>,
    pub allow_plain_auth_without_tls: bool,
    pub implementation: String,
}

impl Default for ManageSieveCapabilities {
    fn default() -> Self {
        ManageSieveCapabilities {
            sieve: owned(DEFAULT_SIEVE_EXT),
            sasl: DEFAULT_SASL.to_vec(),
            allow_plain_auth_without_tls: false,
            implementation: "Stalwart ManageSieve".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubmissionCapabilities {
    pub ehlo: Vec<String>,
    #[serde(deserialize_with = "SubmissionCapabilities::deserialize_sasl")]
    pub sasl: Vec<SaslMech>,
    pub allow_plain_auth_without_tls: bool,
    pub banner: String,
}

impl Default for SubmissionCapabilities {
    fn default() -> Self {
        SubmissionCapabilities {
            ehlo: owned(DEFAULT_EHLO),
            sasl: DEFAULT_SASL.to_vec(),
            allow_plain_auth_without_tls: false,
            banner: "at your service.".to_string(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Pop3Capabilities {
    #[serde(deserialize_with = "Pop3Capabilities::deserialize_sasl")]
    pub sasl: Vec<SaslMech>,
    pub allow_plain_auth_without_tls: bool,
    pub banner: String,
}

impl Default for Pop3Capabilities {
    fn default() -> Self {
        Pop3Capabilities {
            sasl: DEFAULT_SASL.to_vec(),
            allow_plain_auth_without_tls: false,
            banner: "Stalwart POP3 at your service.".to_string(),
        }
    }
}

impl CapabilitiesConfig {
    fn sasl_list<'de, D: Deserializer<'de>>(
        deserializer: D,
        section: &str,
    ) -> Result<Vec<SaslMech>, D::Error> {
        let names = Vec::<String>::deserialize(deserializer)?;
        let mut mechs = Vec::with_capacity(names.len().min(DEFAULT_SASL.len()));
        for (index, name) in names.iter().enumerate() {
            let mech = SaslMech::parse(name.as_bytes()).ok_or_else(|| {
                D::Error::custom(format!(
                    "capabilities.{section}.sasl[{index}]: unsupported mechanism {name:?}; supported mechanisms are PLAIN, LOGIN, OAUTHBEARER, XOAUTH2"
                ))
            })?;
            mechs.push(mech);
        }
        Ok(mechs)
    }
}

impl ImapCapabilities {
    fn deserialize_sasl<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<SaslMech>, D::Error> {
        CapabilitiesConfig::sasl_list(deserializer, "imap")
    }
}

impl ManageSieveCapabilities {
    fn deserialize_sasl<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<SaslMech>, D::Error> {
        CapabilitiesConfig::sasl_list(deserializer, "managesieve")
    }
}

impl SubmissionCapabilities {
    fn deserialize_sasl<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<SaslMech>, D::Error> {
        CapabilitiesConfig::sasl_list(deserializer, "submission")
    }
}

impl Pop3Capabilities {
    fn deserialize_sasl<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<SaslMech>, D::Error> {
        CapabilitiesConfig::sasl_list(deserializer, "pop3")
    }
}
