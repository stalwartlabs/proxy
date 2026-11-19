/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Deserialize;
use serde_json::{Map, Number, Value as Json};
use toml_edit::{Array, ArrayOfTables, DocumentMut, InlineTable, Item, Table, Value};

use super::confine::ConfigDir;
use super::secret::{MASK, SecretUrl};
use super::{Config, Revision, line_of};
use crate::error::{ConfigError, ConfigErrors};
use crate::runtime::time::UtcTime;

pub const HISTORY_KEEP: usize = 10;
const MAX_PATH_DEPTH: usize = 8;
const STAMP_DATE_DIGITS: usize = 8;
const STAMP_TIME_DIGITS: usize = 6;
const SUFFIX_DIGITS: usize = 2;
const MAX_SAME_SECOND: u32 = 99;
const ADMIN: &str = "admin";

#[derive(Clone, Copy)]
enum SecretKind {
    Token,
    Url,
}

const SECRETS: [(&[&str], SecretKind); 3] = [
    (&["admin", "bearer_token"], SecretKind::Token),
    (&["mapping", "redis", "url"], SecretKind::Url),
    (&["mapping", "sql", "url"], SecretKind::Url),
];

impl SecretKind {
    fn masked(self, value: &str) -> String {
        match self {
            SecretKind::Token => MASK.to_string(),
            SecretKind::Url => SecretUrl::from(value.to_string()).to_string(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EditError {
    #[error("revision mismatch: the file on disk is at {current}")]
    Conflict { current: Revision },
    #[error("{0}")]
    Invalid(ConfigErrors),
    #[error("history entry not found")]
    NotFound,
    #[error("config file I/O: {0}")]
    Io(#[from] io::Error),
}

impl From<ConfigErrors> for EditError {
    fn from(errors: ConfigErrors) -> Self {
        EditError::Invalid(errors)
    }
}

impl EditError {
    fn invalid(path: impl Into<Box<str>>, message: impl Into<String>) -> EditError {
        EditError::Invalid(ConfigErrors(vec![ConfigError::new(path, message.into())]))
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum EditOp {
    Set { path: Vec<String>, value: Json },
    Remove { path: Vec<String> },
}

pub struct Source {
    pub text: String,
    pub revision: Revision,
    dir: Option<ConfigDir>,
}

impl Source {
    pub fn new(text: String) -> Self {
        Source {
            revision: Revision::of(text.as_bytes()),
            text,
            dir: None,
        }
    }

    pub fn read(path: &Path) -> io::Result<Self> {
        let dir = ConfigDir::of(path)?;
        let mut source = fs::read_to_string(path).map(Source::new)?;
        source.dir = Some(dir);
        Ok(source)
    }

    pub fn check(&self, revision: Revision) -> Result<(), EditError> {
        match self.revision == revision {
            true => Ok(()),
            false => Err(EditError::Conflict {
                current: self.revision,
            }),
        }
    }

    pub fn commit(&self, path: &Path, previous: &Source) -> Result<(), EditError> {
        Source::read(path)?.check(previous.revision)?;
        History::for_config(path).save(&previous.text, SystemTime::now())?;
        write_atomic(path, self.text.as_bytes())?;
        Ok(())
    }

    pub fn masked(&self) -> Result<String, EditError> {
        let mut doc = parse_document(&self.text)?;
        for (path, kind) in SECRETS {
            if let Some(value) = secret_value(&mut doc, path) {
                let masked = value.as_str().map(|text| kind.masked(text));
                if let Some(masked) = masked {
                    replace_keeping_decor(value, masked);
                }
            }
        }
        Ok(doc.to_string())
    }

    pub fn apply(&self, ops: &[EditOp]) -> Result<Edited, EditError> {
        let mut doc = parse_document(&self.text)?;
        for op in ops {
            op.apply(&mut doc)?;
        }
        self.finish(doc)
    }

    pub fn replace(&self, submitted: &str) -> Result<Edited, EditError> {
        self.finish(parse_document(submitted)?)
    }

    pub fn validate(&self, submitted: &str) -> Result<Config, EditError> {
        let text = self.restored(parse_document(submitted)?)?;
        let config = Config::parse(&text)?;
        self.check_confined(&config)?;
        Ok(config)
    }

    fn check_confined(&self, config: &Config) -> Result<(), ConfigErrors> {
        let previous = toml::from_str::<Config>(&self.text).ok();
        config.check_confined(previous.as_ref(), self.dir.as_ref())
    }

    fn restored(&self, mut doc: DocumentMut) -> Result<String, EditError> {
        let current = parse_document(&self.text)?;
        restore_secrets(&mut doc, &current);
        Ok(doc.to_string())
    }

    fn finish(&self, doc: DocumentMut) -> Result<Edited, EditError> {
        let text = self.restored(doc)?;
        if admin_table(&self.text)? != admin_table(&text)? {
            return Err(EditError::invalid(
                ADMIN,
                "the [admin] table is read-only through the API",
            ));
        }
        let config = Config::parse(&text)?;
        self.check_confined(&config)?;
        let mut source = Source::new(text);
        source.dir = self.dir.clone();
        Ok(Edited { source, config })
    }
}

pub struct Edited {
    pub source: Source,
    pub config: Config,
}

fn parse_document(text: &str) -> Result<DocumentMut, EditError> {
    text.parse::<DocumentMut>().map_err(|err| {
        let line = err.span().and_then(|span| line_of(text, span.start));
        EditError::Invalid(ConfigErrors(vec![ConfigError {
            path: Box::default(),
            message: format!("TOML parse: {}", err.message()).into(),
            line,
        }]))
    })
}

fn admin_table(text: &str) -> Result<Option<toml::Value>, EditError> {
    let mut table = toml::from_str::<toml::Table>(text)
        .map_err(|err| EditError::invalid("", format!("TOML parse: {}", err.message())))?;
    Ok(table.remove(ADMIN))
}

fn secret_value<'a>(doc: &'a mut DocumentMut, path: &[&str]) -> Option<&'a mut Value> {
    path.iter()
        .try_fold(doc.as_item_mut(), |item, key| {
            item.as_table_like_mut()?.get_mut(key)
        })?
        .as_value_mut()
}

fn replace_keeping_decor(value: &mut Value, text: String) {
    let decor = value.decor().clone();
    *value = Value::from(text);
    *value.decor_mut() = decor;
}

fn restore_secrets(doc: &mut DocumentMut, current: &DocumentMut) {
    for (path, kind) in SECRETS {
        let Some(existing) = path
            .split_last()
            .and_then(|(last, parents)| {
                parents
                    .iter()
                    .try_fold(current.as_item(), |item, key| item.get(*key))
                    .and_then(|item| item.get(*last))
            })
            .and_then(Item::as_str)
        else {
            continue;
        };
        if let Some(value) = secret_value(doc, path)
            && value.as_str() == Some(kind.masked(existing).as_str())
        {
            replace_keeping_decor(value, existing.to_string());
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Missing {
    Create,
    Skip,
}

enum Lookup<'a> {
    Found(Node<'a>),
    Absent,
    NotTable,
}

enum Node<'a> {
    Table(&'a mut Table),
    Inline(&'a mut InlineTable),
    Tables(&'a mut ArrayOfTables),
    Array(&'a mut Array),
}

impl<'a> Node<'a> {
    fn from_item(item: &'a mut Item) -> Option<Self> {
        match item {
            Item::Table(table) => Some(Node::Table(table)),
            Item::ArrayOfTables(tables) => Some(Node::Tables(tables)),
            Item::Value(value) => Node::from_value(value),
            Item::None => None,
        }
    }

    fn from_value(value: &'a mut Value) -> Option<Self> {
        match value {
            Value::InlineTable(table) => Some(Node::Inline(table)),
            Value::Array(array) => Some(Node::Array(array)),
            _ => None,
        }
    }

    fn child(self, key: &str, missing: Missing) -> Lookup<'a> {
        let found = match (self, missing) {
            (Node::Table(table), Missing::Create) => {
                Node::from_item(table.entry(key).or_insert_with(|| {
                    let mut table = Table::new();
                    table.set_implicit(true);
                    Item::Table(table)
                }))
            }
            (Node::Table(table), Missing::Skip) => match table.get_mut(key) {
                Some(item) if !item.is_none() => Node::from_item(item),
                _ => return Lookup::Absent,
            },
            (Node::Inline(table), Missing::Create) => Node::from_value(
                table
                    .entry(key)
                    .or_insert_with(|| Value::InlineTable(InlineTable::new())),
            ),
            (Node::Inline(table), Missing::Skip) => match table.get_mut(key) {
                Some(value) => Node::from_value(value),
                None => return Lookup::Absent,
            },
            (Node::Tables(tables), missing) => {
                match key.parse().ok().map(|index| tables.get_mut(index)) {
                    Some(Some(table)) => Some(Node::Table(table)),
                    Some(None) if missing == Missing::Skip => return Lookup::Absent,
                    _ => None,
                }
            }
            (Node::Array(array), missing) => {
                match key.parse().ok().map(|index| array.get_mut(index)) {
                    Some(Some(value)) => Node::from_value(value),
                    Some(None) if missing == Missing::Skip => return Lookup::Absent,
                    _ => None,
                }
            }
        };
        found.map_or(Lookup::NotTable, Lookup::Found)
    }

    fn set(self, key: &str, json: &Json) -> Option<()> {
        match self {
            Node::Table(table) => {
                let item = json_item(json)?;
                match (table.get_mut(key).and_then(Item::as_value_mut), item) {
                    (Some(existing), Item::Value(value)) => replace_value(existing, value),
                    (_, item) => {
                        table.insert(key, item);
                    }
                }
            }
            Node::Inline(table) => {
                let value = json_value(json)?;
                match table.get_mut(key) {
                    Some(existing) => replace_value(existing, value),
                    None => {
                        table.insert(key, value);
                    }
                }
            }
            Node::Tables(tables) => {
                let index: usize = key.parse().ok()?;
                let Item::Table(table) = json_item(json)? else {
                    return None;
                };
                let len = tables.len();
                match tables.get_mut(index) {
                    Some(existing) => *existing = table,
                    None if index == len => tables.push(table),
                    None => return None,
                }
            }
            Node::Array(array) => {
                let index: usize = key.parse().ok()?;
                let value = json_value(json)?;
                let len = array.len();
                match array.get_mut(index) {
                    Some(existing) => replace_value(existing, value),
                    None if index == len => array.push_formatted(value),
                    None => return None,
                }
            }
        }
        Some(())
    }

    fn remove(self, key: &str) -> Option<()> {
        match self {
            Node::Table(table) => {
                table.remove(key);
            }
            Node::Inline(table) => {
                table.remove(key);
            }
            Node::Tables(tables) => {
                let index: usize = key.parse().ok()?;
                if index < tables.len() {
                    tables.remove(index);
                }
            }
            Node::Array(array) => {
                let index: usize = key.parse().ok()?;
                if index < array.len() {
                    array.remove(index);
                }
            }
        }
        Some(())
    }
}

fn replace_value(existing: &mut Value, mut value: Value) {
    *value.decor_mut() = existing.decor().clone();
    *existing = value;
}

impl EditOp {
    fn apply(&self, doc: &mut DocumentMut) -> Result<(), EditError> {
        let path = match self {
            EditOp::Set { path, .. } | EditOp::Remove { path } => path.as_slice(),
        };
        let dotted = path.join(".");
        let Some((last, parents)) = path.split_last() else {
            return Err(EditError::invalid("", "empty path"));
        };
        if path.len() > MAX_PATH_DEPTH {
            return Err(EditError::invalid(dotted, "path too deep"));
        }
        if path.first().is_some_and(|section| section == ADMIN) {
            return Err(EditError::invalid(
                dotted,
                "the [admin] table is read-only through the API",
            ));
        }
        let (missing, value) = match self {
            EditOp::Set {
                value: Json::Null, ..
            }
            | EditOp::Remove { .. } => (Missing::Skip, None),
            EditOp::Set { value, .. } => (Missing::Create, Some(value)),
        };
        let mut node = Node::Table(doc.as_table_mut());
        for key in parents {
            node = match node.child(key, missing) {
                Lookup::Found(child) => child,
                Lookup::Absent => return Ok(()),
                Lookup::NotTable => {
                    return Err(EditError::invalid(dotted, "path does not name a table"));
                }
            };
        }
        let applied = match value {
            Some(value) => node.set(last, value),
            None => node.remove(last),
        };
        applied.ok_or_else(|| EditError::invalid(dotted, "value cannot be stored at this path"))
    }
}

fn json_item(json: &Json) -> Option<Item> {
    match json {
        Json::Object(object) => json_table(object).map(Item::Table),
        Json::Array(items) if !items.is_empty() && items.iter().all(Json::is_object) => {
            let mut tables = ArrayOfTables::new();
            for item in items.iter().filter_map(Json::as_object) {
                tables.push(json_table(item)?);
            }
            Some(Item::ArrayOfTables(tables))
        }
        json => json_value(json).map(Item::Value),
    }
}

fn json_table(object: &Map<String, Json>) -> Option<Table> {
    let mut table = Table::new();
    table.set_implicit(true);
    for (key, value) in object.iter().filter(|(_, value)| !value.is_null()) {
        table.insert(key, json_item(value)?);
    }
    Some(table)
}

fn json_value(json: &Json) -> Option<Value> {
    match json {
        Json::Null => None,
        Json::Bool(flag) => Some(Value::from(*flag)),
        Json::Number(number) => json_number(number),
        Json::String(text) => Some(Value::from(text.as_str())),
        Json::Array(items) => {
            let mut array = Array::new();
            for item in items {
                array.push(json_value(item)?);
            }
            Some(Value::Array(array))
        }
        Json::Object(object) => {
            let mut table = InlineTable::new();
            for (key, value) in object.iter().filter(|(_, value)| !value.is_null()) {
                table.insert(key.as_str(), json_value(value)?);
            }
            Some(Value::InlineTable(table))
        }
    }
}

fn json_number(number: &Number) -> Option<Value> {
    match number.as_i64() {
        Some(integer) => Some(Value::from(integer)),
        None if number.is_f64() => number.as_f64().map(Value::from),
        None => None,
    }
}

pub struct HistoryEntry {
    pub id: Box<str>,
    pub revision: Revision,
    pub size: u64,
    pub at: SystemTime,
}

pub struct History {
    dir: PathBuf,
}

impl History {
    pub fn for_config(path: &Path) -> Self {
        let mut dir = path.as_os_str().to_owned();
        dir.push(".history");
        History {
            dir: PathBuf::from(dir),
        }
    }

    pub fn list(&self) -> io::Result<Vec<HistoryEntry>> {
        let ids = self.ids()?;
        let mut entries = Vec::with_capacity(ids.len());
        for id in ids {
            let path = self.path(&id);
            let bytes = fs::read(&path)?;
            let metadata = fs::metadata(&path)?;
            entries.push(HistoryEntry {
                id,
                revision: Revision::of(&bytes),
                size: metadata.len(),
                at: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            });
        }
        Ok(entries)
    }

    fn ids(&self) -> io::Result<Vec<Box<str>>> {
        let mut ids = Vec::new();
        let dir = match fs::read_dir(&self.dir) {
            Ok(dir) => dir,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(ids),
            Err(err) => return Err(err),
        };
        for entry in dir {
            let name = entry?.file_name();
            if let Some(id) = name
                .to_str()
                .and_then(|name| name.strip_suffix(".toml"))
                .filter(|id| valid_history_id(id))
            {
                ids.push(Box::from(id));
            }
        }
        ids.sort_unstable_by(|a, b| b.cmp(a));
        Ok(ids)
    }

    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.toml"))
    }

    pub fn read(&self, id: &str) -> Result<Source, EditError> {
        if !valid_history_id(id) {
            return Err(EditError::NotFound);
        }
        match fs::read_to_string(self.path(id)) {
            Ok(text) => Ok(Source::new(text)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Err(EditError::NotFound),
            Err(err) => Err(EditError::Io(err)),
        }
    }

    fn save(&self, text: &str, at: SystemTime) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let stamp = utc_stamp(at);
        let mut suffix = self
            .ids()?
            .iter()
            .filter_map(|id| same_second_suffix(id, &stamp))
            .max()
            .map_or(0, |newest| newest.saturating_add(1))
            .min(MAX_SAME_SECOND);
        let (id, mut file) = loop {
            let id = match suffix {
                0 => stamp.clone(),
                n => format!("{stamp}-{n:02}"),
            };
            match create_private(&self.path(&id)) {
                Err(err)
                    if err.kind() == io::ErrorKind::AlreadyExists && suffix < MAX_SAME_SECOND =>
                {
                    suffix += 1;
                }
                result => break (id, result?),
            }
        };
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        for stale in self
            .ids()?
            .iter()
            .filter(|stale| ***stale != *id)
            .skip(HISTORY_KEEP - 1)
        {
            fs::remove_file(self.path(stale))?;
        }
        Ok(())
    }
}

fn same_second_suffix(id: &str, stamp: &str) -> Option<u32> {
    match id.strip_prefix(stamp)? {
        "" => Some(0),
        rest => rest.strip_prefix('-')?.parse().ok(),
    }
}

fn valid_history_id(id: &str) -> bool {
    let (stamp, suffix) = id.split_once('-').unwrap_or((id, "00"));
    let Some((date, time)) = stamp.split_once('T') else {
        return false;
    };
    let digits =
        |part: &str, len: usize| part.len() == len && part.bytes().all(|b| b.is_ascii_digit());
    digits(date, STAMP_DATE_DIGITS)
        && time
            .strip_suffix('Z')
            .is_some_and(|time| digits(time, STAMP_TIME_DIGITS))
        && digits(suffix, SUFFIX_DIGITS)
}

#[cfg(unix)]
fn create_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".{}.tmp", std::process::id()));
    let tmp = PathBuf::from(tmp);
    let permissions = fs::metadata(path)?.permissions();
    let _ = fs::remove_file(&tmp);
    let result = (|| {
        let mut file = create_private(&tmp)?;
        file.set_permissions(permissions)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    sync_parent(path)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> io::Result<()> {
    match path.parent().filter(|dir| !dir.as_os_str().is_empty()) {
        Some(dir) => File::open(dir)?.sync_all(),
        None => File::open(".")?.sync_all(),
    }
}

#[cfg(not(unix))]
fn sync_parent(_: &Path) -> io::Result<()> {
    Ok(())
}

fn utc_stamp(at: SystemTime) -> String {
    UtcTime(at).compact().to_string()
}

#[cfg(all(test, proxy_tests))]
#[rustfmt::skip]
#[path = "../../../proxy-tests/unit/src/config/edit/tests.rs"]
mod tests;
