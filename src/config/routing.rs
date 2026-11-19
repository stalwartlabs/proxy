/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    pub default_destination: String,
    #[serde(default)]
    pub smtp_passthrough_destination: Option<String>,
    #[serde(default = "master_user_separators")]
    pub master_user_separators: Vec<String>,
}

fn master_user_separators() -> Vec<String> {
    vec!["%".to_string()]
}

pub const DEFAULT_JWT_CLAIM: &str = "email";

#[derive(Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuthConfig {
    pub jwt_username_claim: String,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        OAuthConfig {
            jwt_username_claim: DEFAULT_JWT_CLAIM.to_string(),
        }
    }
}
