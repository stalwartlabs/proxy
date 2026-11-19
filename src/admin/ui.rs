/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use super::http::{NOT_MODIFIED, Reply, Request, StaticBody};
use crate::http::head::Method;

const UI_ROOT: &str = "/ui/";
const UI_INDEX: &str = "/ui";
const ASSETS_PREFIX: &str = "/ui/assets/";

pub struct Asset {
    pub content_type: &'static str,
    pub etag: &'static str,
    pub etag_br: &'static str,
    pub raw: &'static [u8],
    pub br: Option<&'static [u8]>,
    pub immutable: bool,
}

include!(concat!(env!("OUT_DIR"), "/ui_assets.rs"));

impl Request {
    pub fn serve_ui(&self, body: &mut Vec<u8>) -> Option<Reply> {
        let target = self.path();
        let asset = match target {
            "/" => return Some(self.only_get(body, Reply::redirect(UI_ROOT))),
            UI_INDEX => &INDEX,
            _ => {
                let found = target
                    .strip_prefix(ASSETS_PREFIX)
                    .and_then(|name| asset(name.as_bytes()));
                match found {
                    Some(asset) => asset,
                    None if target.starts_with(UI_ROOT) => {
                        return Some(Reply::error(body, 404, "not_found", "not found"));
                    }
                    None => return None,
                }
            }
        };
        Some(self.only_get(body, asset.respond(self)))
    }

    fn only_get(&self, body: &mut Vec<u8>, reply: Reply) -> Reply {
        match self.method() {
            Method::Get => reply,
            _ => Reply::error(body, 405, "method_not_allowed", "method not allowed"),
        }
    }
}

impl Asset {
    fn respond(&'static self, request: &Request) -> Reply {
        let (bytes, br, etag) = match self.br {
            Some(compressed) if request.accepts_br() => (compressed, true, self.etag_br),
            _ => (self.raw, false, self.etag),
        };
        let status = match request.matches_etag(etag) {
            true => NOT_MODIFIED,
            false => 200,
        };
        Reply::asset(
            status,
            StaticBody {
                content_type: self.content_type,
                etag,
                bytes: if status == NOT_MODIFIED { &[] } else { bytes },
                br,
                immutable: self.immutable,
            },
        )
    }
}
