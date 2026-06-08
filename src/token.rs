/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::sasl::Credential;

pub fn bearer_identifier(token: &str, jwt_username_claim: &str) -> Option<String> {
    if let Some(rest) = token.strip_prefix("sw1.") {
        return match rest.split_once('.') {
            Some((_body, footer)) => {
                let decoded = URL_SAFE_NO_PAD.decode(footer).ok()?;
                String::from_utf8(decoded).ok()
            }
            None => None,
        };
    }

    let claims_seg = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(claims_seg).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;

    for name in [
        jwt_username_claim,
        "email",
        "preferred_username",
        "upn",
        "unique_name",
        "sub",
    ] {
        if let Some(v) = claims.get(name).and_then(|v| v.as_str())
            && v.contains('@')
        {
            return Some(v.to_string());
        }
    }
    None
}

pub fn valid_routing_identifier(id: &str) -> bool {
    !id.bytes()
        .any(|b| b < 0x20 || b == 0x7f || b == b' ' || b == b'"')
}

pub fn identifier_from_credential(cred: &Credential, jwt_username_claim: &str) -> Option<String> {
    match cred {
        Credential::Plain { authcid, .. } => Some(authcid.clone()),
        Credential::OAuth {
            username: Some(u), ..
        } => Some(u.clone()),
        Credential::OAuth {
            username: None,
            token,
        } => bearer_identifier(token, jwt_username_claim),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn sw1_footer() {
        let footer = URL_SAFE_NO_PAD.encode("user@example.com");
        let token = format!("sw1.bodyblob.{footer}");
        assert_eq!(
            bearer_identifier(&token, "email"),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn sw1_no_footer() {
        assert_eq!(bearer_identifier("sw1.bodyonly", "email"), None);
    }

    #[test]
    fn jwt_email_claim() {
        let claims = URL_SAFE_NO_PAD.encode(r#"{"email":"alice@example.com","sub":"x"}"#);
        let token = format!("hdr.{claims}.sig");
        assert_eq!(
            bearer_identifier(&token, "email"),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn jwt_configured_claim_first() {
        let claims = URL_SAFE_NO_PAD.encode(r#"{"login_email":"bob@corp.com","sub":"nope"}"#);
        let token = format!("hdr.{claims}.sig");
        assert_eq!(
            bearer_identifier(&token, "login_email"),
            Some("bob@corp.com".to_string())
        );
    }

    #[test]
    fn jwt_requires_at_sign() {
        let claims = URL_SAFE_NO_PAD.encode(r#"{"sub":"not-an-email"}"#);
        let token = format!("hdr.{claims}.sig");
        assert_eq!(bearer_identifier(&token, "email"), None);
    }

    #[test]
    fn garbage_token_is_none() {
        assert_eq!(bearer_identifier("not-a-jwt", "email"), None);
    }

    #[test]
    fn jwt_precedence_falls_through_to_later_claims() {
        let claims = URL_SAFE_NO_PAD.encode(r#"{"upn":"carol@corp.com","sub":"x"}"#);
        let token = format!("hdr.{claims}.sig");
        assert_eq!(
            bearer_identifier(&token, "email"),
            Some("carol@corp.com".to_string())
        );
    }

    #[test]
    fn jwt_configured_claim_without_at_falls_through() {
        let claims = URL_SAFE_NO_PAD.encode(r#"{"login":"noat","email":"dan@corp.com"}"#);
        let token = format!("hdr.{claims}.sig");
        assert_eq!(
            bearer_identifier(&token, "login"),
            Some("dan@corp.com".to_string())
        );
    }

    #[test]
    fn sw1_invalid_footer_is_none() {
        assert_eq!(bearer_identifier("sw1.body.!!!notbase64!!!", "email"), None);
    }

    #[test]
    fn identifier_from_credential_all_arms() {
        let plain = Credential::Plain {
            authcid: "alice".into(),
            passwd: "p".into(),
        };
        assert_eq!(
            identifier_from_credential(&plain, "email"),
            Some("alice".to_string())
        );

        let oauth_named = Credential::OAuth {
            username: Some("u@x".into()),
            token: "tok".into(),
        };
        assert_eq!(
            identifier_from_credential(&oauth_named, "email"),
            Some("u@x".to_string())
        );

        let footer = URL_SAFE_NO_PAD.encode("eve@example.com");
        let oauth_tok = Credential::OAuth {
            username: None,
            token: format!("sw1.body.{footer}"),
        };
        assert_eq!(
            identifier_from_credential(&oauth_tok, "email"),
            Some("eve@example.com".to_string())
        );
    }
}
