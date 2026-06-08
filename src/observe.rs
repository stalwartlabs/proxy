/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::atomic::{AtomicBool, Ordering};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init(level: &str) {
    if INITIALIZED.swap(true, Ordering::SeqCst) {
        return;
    }
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = fmt().with_env_filter(filter).with_target(false).try_init();
}

pub fn redact(value: &str) -> String {
    if value.is_empty() {
        return "<empty>".to_string();
    }
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    let tag = hasher.finish() & 0xffff;
    let visible: String = value.chars().take(2).collect();
    format!("{visible}***#{tag:04x}")
}
