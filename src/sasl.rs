/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    Plain {
        authcid: String,
        passwd: String,
    },
    OAuth {
        username: Option<String>,
        token: String,
    },
}

impl Credential {
    pub fn decode_sasl_challenge_plain(challenge: &[u8]) -> Option<Self> {
        let mut username = Vec::new();
        let mut secret = Vec::new();
        let mut arg_num = 0;
        for &ch in challenge {
            if ch != 0 {
                if arg_num == 1 {
                    username.push(ch);
                } else if arg_num == 2 {
                    secret.push(ch);
                }
            } else {
                arg_num += 1;
            }
        }

        match (String::from_utf8(username), String::from_utf8(secret)) {
            (Ok(username), Ok(secret)) if !username.is_empty() && !secret.is_empty() => {
                Some(Credential::Plain {
                    authcid: username,
                    passwd: secret,
                })
            }
            _ => None,
        }
    }

    pub fn decode_sasl_challenge_oauth(challenge: &[u8]) -> Option<Self> {
        extract_oauth_bearer(challenge)
            .map(|(token, username)| Credential::OAuth { username, token })
    }
}

pub fn extract_oauth_bearer(bytes: &[u8]) -> Option<(String, Option<String>)> {
    let mut start_pos = 0;
    let eof = bytes.len().saturating_sub(1);
    let mut iter = bytes.iter().enumerate();
    let mut a = None;

    while let Some((pos, ch)) = iter.next() {
        if *ch == b','
            && bytes
                .get(pos + 1..pos + 3)
                .is_some_and(|s| s.eq_ignore_ascii_case(b"a="))
        {
            let from_pos = pos + 3;
            let mut to_pos = from_pos;
            for (pos, ch) in iter.by_ref() {
                if *ch == b',' || *ch == 1 {
                    to_pos = pos;
                    break;
                }
            }

            if to_pos > from_pos {
                a = bytes
                    .get(from_pos..to_pos)
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .filter(|v| v.contains('@'));
            }
        } else {
            let is_separator = *ch == 1;
            if is_separator || pos == eof {
                if bytes
                    .get(start_pos..start_pos + 12)
                    .is_some_and(|s| s.eq_ignore_ascii_case(b"auth=Bearer "))
                {
                    return bytes
                        .get(start_pos + 12..if is_separator { pos } else { bytes.len() })
                        .and_then(|s| std::str::from_utf8(s).ok())
                        .map(|token| (token.to_string(), a.map(|s| s.to_string())));
                }

                start_pos = pos + 1;
            }
        }
    }

    None
}

pub fn decode_sasl_ir(b64: &[u8]) -> Option<Vec<u8>> {
    mail_parser::decoders::base64::base64_decode(b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_extracts_authcid() {
        let challenge = b"\0test\0secret";
        let cred = Credential::decode_sasl_challenge_plain(challenge).unwrap();
        assert_eq!(
            cred,
            Credential::Plain {
                authcid: "test".into(),
                passwd: "secret".into()
            }
        );
    }

    #[test]
    fn plain_rejects_empty() {
        assert!(Credential::decode_sasl_challenge_plain(b"\0\0").is_none());
        assert!(Credential::decode_sasl_challenge_plain(b"\0user\0").is_none());
    }

    #[test]
    fn test_extract_oauth_bearer() {
        assert_eq!(
            extract_oauth_bearer(b"auth=Bearer validtoken"),
            Some(("validtoken".to_string(), None))
        );
        assert_eq!(extract_oauth_bearer(b"auth=Invalid validtoken"), None);
        assert_eq!(extract_oauth_bearer(b"auth=Bearer"), None);
        assert_eq!(extract_oauth_bearer(b""), None);
        assert_eq!(
            extract_oauth_bearer(b"auth=Bearer token1\x01auth=Bearer token2"),
            Some(("token1".to_string(), None))
        );
        assert_eq!(
            extract_oauth_bearer(b"auth=Bearer token with spaces"),
            Some(("token with spaces".to_string(), None))
        );
        let input = "n,a=user@example.com,\x01host=server.example.com\x01port=143\x01auth=Bearer vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==\x01\x01";
        assert_eq!(
            extract_oauth_bearer(input.as_bytes()),
            Some((
                "vF9dft4qmTc2Nvb3RlckBhbHRhdmlzdGEuY29tCg==".to_string(),
                Some("user@example.com".to_string())
            ))
        );
    }

    #[test]
    fn lenient_ir_decode() {
        let out = decode_sasl_ir(b"dGVzdAB0ZXN0AHRlc3Q=").unwrap();
        assert_eq!(out, b"test\0test\0test");
    }

    #[test]
    fn plain_with_authzid_takes_authcid() {
        let challenge = b"admin\0alice\0secret";
        let cred = Credential::decode_sasl_challenge_plain(challenge).unwrap();
        assert_eq!(
            cred,
            Credential::Plain {
                authcid: "alice".into(),
                passwd: "secret".into()
            }
        );
    }

    #[test]
    fn oauth_wrapper_returns_credential() {
        let input = "n,a=u@x,\x01auth=Bearer tok\x01\x01";
        let cred = Credential::decode_sasl_challenge_oauth(input.as_bytes()).unwrap();
        assert_eq!(
            cred,
            Credential::OAuth {
                username: Some("u@x".into()),
                token: "tok".into()
            }
        );
    }

    #[test]
    fn xoauth2_frame_extracts_token() {
        let input = "user=u@x\x01auth=Bearer xtok\x01\x01";
        assert_eq!(
            extract_oauth_bearer(input.as_bytes()),
            Some(("xtok".to_string(), None))
        );
    }

    #[test]
    fn oauth_a_field_requires_at_sign() {
        let input = "n,a=plainuser,\x01auth=Bearer tok\x01\x01";
        assert_eq!(
            extract_oauth_bearer(input.as_bytes()),
            Some(("tok".to_string(), None))
        );
    }

    #[test]
    fn lenient_ir_tolerates_whitespace() {
        let with_ws = decode_sasl_ir(b"dGVz dAB0\nZXN0AHRlc3Q=").unwrap();
        assert_eq!(with_ws, b"test\0test\0test");
    }

    #[test]
    fn lenient_ir_decodes_full_quads_without_padding() {
        let out = decode_sasl_ir(b"AHRlc3QAc2VjcmV0").unwrap();
        assert_eq!(out, b"\0test\0secret");
    }
}
