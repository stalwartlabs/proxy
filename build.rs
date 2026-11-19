/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const UI_DIR: &str = "ui";
const HASH_LEN: usize = 10;
const BROTLI_QUALITY: u32 = 11;
const BROTLI_WINDOW: u32 = 22;
const BROTLI_BUFFER: usize = 4096;
const JS_PROLOGUE: &str = "(() => {\n'use strict';\n";
const JS_EPILOGUE: &str = "\n})();\n";

struct Output {
    name: String,
    content_type: &'static str,
    hash: String,
    compress: bool,
    immutable: bool,
}

struct Builder {
    out_dir: PathBuf,
    outputs: Vec<Output>,
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if env::var_os("CARGO_FEATURE_UI").is_none() {
        return;
    }
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    let ui = Path::new(UI_DIR);
    println!("cargo:rerun-if-changed={UI_DIR}");
    let mut builder = Builder {
        out_dir: out_dir.join("ui"),
        outputs: Vec::new(),
    };
    fs::create_dir_all(&builder.out_dir).expect("create OUT_DIR/ui");

    let mut css = concat_dir(&ui.join("css"), "css");
    for font in sorted_files(&ui.join("fonts"), "woff2") {
        let bytes = read(&font);
        let file = file_name(&font);
        let hashed = builder.emit(file, "font/woff2", bytes, false, true);
        css = css.replace(&format!("url('fonts/{file}')"), &format!("url('{hashed}')"));
    }
    let app_css = builder.emit(
        "app.css",
        "text/css; charset=utf-8",
        css.into_bytes(),
        true,
        true,
    );

    let mut js = String::from(JS_PROLOGUE);
    js.push_str(&concat_dir(&ui.join("js"), "js"));
    js.push_str(JS_EPILOGUE);
    let app_js = builder.emit(
        "app.js",
        "text/javascript; charset=utf-8",
        js.into_bytes(),
        true,
        true,
    );
    let boot_js = builder.emit(
        "boot.js",
        "text/javascript; charset=utf-8",
        read(&ui.join("boot.js")),
        true,
        true,
    );
    let logo = builder.emit(
        "logo-mark.svg",
        "image/svg+xml",
        read(&ui.join("logo-mark.svg")),
        true,
        true,
    );

    let index = String::from_utf8(read(&ui.join("index.html")))
        .expect("ui/index.html is UTF-8")
        .replace("{{app.css}}", &app_css)
        .replace("{{app.js}}", &app_js)
        .replace("{{boot.js}}", &boot_js)
        .replace("{{logo-mark.svg}}", &logo);
    assert!(
        !index.contains("{{"),
        "ui/index.html has an unknown placeholder"
    );
    builder.emit(
        "index.html",
        "text/html; charset=utf-8",
        index.into_bytes(),
        true,
        false,
    );

    let generated = builder.generate();
    fs::write(out_dir.join("ui_assets.rs"), generated).expect("write ui_assets.rs");
}

impl Builder {
    fn emit(
        &mut self,
        file: &str,
        content_type: &'static str,
        bytes: Vec<u8>,
        compress: bool,
        immutable: bool,
    ) -> String {
        let digest = Sha256::digest(&bytes);
        let mut hash = String::with_capacity(HASH_LEN);
        for byte in digest.iter().take(HASH_LEN / 2) {
            let _ = write!(hash, "{byte:02x}");
        }
        let name = match immutable {
            true => match file.rsplit_once('.') {
                Some((stem, ext)) => format!("{stem}.{hash}.{ext}"),
                None => format!("{file}.{hash}"),
            },
            false => file.to_string(),
        };
        fs::write(self.out_dir.join(&name), &bytes).expect("write asset");
        if compress {
            let mut compressed = Vec::with_capacity(bytes.len() / 3);
            {
                let mut writer = brotli::CompressorWriter::new(
                    &mut compressed,
                    BROTLI_BUFFER,
                    BROTLI_QUALITY,
                    BROTLI_WINDOW,
                );
                writer.write_all(&bytes).expect("brotli compress");
            }
            fs::write(self.out_dir.join(format!("{name}.br")), compressed)
                .expect("write compressed asset");
        }
        self.outputs.push(Output {
            name: name.clone(),
            content_type,
            hash,
            compress,
            immutable,
        });
        name
    }

    fn generate(&self) -> String {
        let mut out = String::new();
        let mut index = None;
        out.push_str("pub fn asset(name: &[u8]) -> Option<&'static Asset> {\n    hashify::map!(\n        name,\n        Asset,\n");
        for output in &self.outputs {
            let literal = self.asset_literal(output);
            if output.immutable {
                let _ = writeln!(out, "        {:?} => {literal},", output.name);
            } else {
                index = Some(literal);
            }
        }
        out.push_str("    )\n}\n");
        let index = index.expect("index.html is emitted");
        let _ = writeln!(out, "pub static INDEX: Asset = {index};");
        out
    }

    fn asset_literal(&self, output: &Output) -> String {
        let path = self.out_dir.join(&output.name);
        let raw = path.to_str().expect("OUT_DIR is UTF-8");
        let br = match output.compress {
            true => format!("Some(include_bytes!({:?}))", format!("{raw}.br")),
            false => "None".to_string(),
        };
        format!(
            "Asset {{ content_type: {:?}, etag: {:?}, etag_br: {:?}, raw: include_bytes!({raw:?}), br: {br}, immutable: {} }}",
            output.content_type,
            format!("\"{}\"", output.hash),
            format!("\"{}-br\"", output.hash),
            output.immutable
        )
    }
}

fn concat_dir(dir: &Path, ext: &str) -> String {
    let mut out = String::new();
    for file in sorted_files(dir, ext) {
        out.push_str(&String::from_utf8(read(&file)).expect("UI sources are UTF-8"));
        out.push('\n');
    }
    out
}

fn sorted_files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    println!("cargo:rerun-if-changed={}", dir.display());
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .expect("read UI directory")
        .map(|entry| entry.expect("read UI directory entry").path())
        .filter(|path| path.extension().is_some_and(|e| e == ext))
        .collect();
    files.sort_unstable();
    files
}

fn read(path: &Path) -> Vec<u8> {
    println!("cargo:rerun-if-changed={}", path.display());
    fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .expect("UI file names are UTF-8")
}
