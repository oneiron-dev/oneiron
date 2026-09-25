use super::*;
use crate::Vault;
use crate::config::VaultConfig;
use crate::error::ErrorKind;
use crate::off_record::OffRecordBackendClass;

fn open_vault() -> (tempfile::TempDir, Vault) {
    crate::test_util::open_test_vault_with(VaultConfig::device())
}

const OUTPUTS: SideTable<String, Vec<u8>, Raw> = SideTable::new(&CODE_RUN_RAW_OUTPUT);
const TAINTS: SideTable<String, Vec<u8>, Raw> = SideTable::new(&CODE_RUN_RAW_OUTPUT_TAINT);

#[test]
fn no_declared_prefix_is_a_byte_prefix_of_another() {
    let declared: Vec<&SideTableDecl> = declared().collect();
    for (index, first) in declared.iter().enumerate() {
        assert!(
            !first.prefix.is_empty(),
            "{} declares an empty prefix",
            first.name
        );
        for second in &declared[index + 1..] {
            assert_ne!(first.name, second.name, "a table is declared twice");
            if first.db != second.db {
                continue;
            }
            assert!(
                !first.prefix.starts_with(second.prefix)
                    && !second.prefix.starts_with(first.prefix),
                "{} and {} overlap: {:?} and {:?}",
                first.name,
                second.name,
                String::from_utf8_lossy(first.prefix),
                String::from_utf8_lossy(second.prefix),
            );
        }
    }
}

#[test]
fn a_declared_table_round_trips_its_rows_inside_one_transaction() -> crate::Result<()> {
    let (_dir, vault) = open_vault();
    let rows = [
        ("a", b"one".to_vec()),
        ("b", b"two".to_vec()),
        ("c", Vec::new()),
    ];
    vault.with_write_txn(|wtxn| {
        for (key, value) in &rows {
            OUTPUTS.put(&vault.store, wtxn, &(*key).to_owned(), value)?;
        }
        // A row of the neighbouring table shares the leading bytes and stays out of the scan.
        TAINTS.put(&vault.store, wtxn, &"a".to_owned(), &b"taint".to_vec())?;

        assert_eq!(
            OUTPUTS.get(&vault.store, wtxn, &"b".to_owned())?,
            Some(b"two".to_vec())
        );
        let scanned = OUTPUTS.scan(&vault.store, wtxn)?;
        let expected: Vec<(String, Vec<u8>)> = rows
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect();
        assert_eq!(scanned, expected);

        assert!(OUTPUTS.delete(&vault.store, wtxn, &"b".to_owned())?);
        assert!(!OUTPUTS.delete(&vault.store, wtxn, &"b".to_owned())?);
        assert_eq!(OUTPUTS.get(&vault.store, wtxn, &"b".to_owned())?, None);
        assert_eq!(
            OUTPUTS.scan_keys(&vault.store, wtxn, &[])?,
            vec!["a".to_owned(), "c".to_owned()]
        );
        assert_eq!(TAINTS.scan(&vault.store, wtxn)?.len(), 1);
        Ok(())
    })
}

#[test]
fn a_side_table_write_in_an_off_record_session_lands_in_the_overlay() -> crate::Result<()> {
    let (_dir, vault) = open_vault();
    let session = vault
        .off_record_session_vault()
        .enter("sess-side-table", OffRecordBackendClass::Local)?;
    let key = "handle".to_owned();

    session.side_table_put(&OUTPUTS, &key, &b"private".to_vec())?;

    let rtxn = vault.store.env.read_txn()?;
    assert_eq!(OUTPUTS.get(&vault.store, &rtxn, &key)?, None);
    assert_eq!(
        vault
            .store
            .vault_meta
            .get(&rtxn, &OUTPUTS.key_bytes(&key))?,
        None
    );
    drop(rtxn);
    assert_eq!(
        session.side_table_get(&OUTPUTS, &key)?,
        Some(b"private".to_vec())
    );
    Ok(())
}

#[test]
fn a_side_table_key_of_another_shape_is_refused_not_sliced() -> crate::Result<()> {
    const BY_ID: SideTable<crate::EntityId, Vec<u8>, Raw> = SideTable::new(&CODE_RUN_REPLAY);
    let (_dir, vault) = open_vault();
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, &[CODE_RUN_REPLAY.prefix, b"short"].concat(), b"row")
    })?;
    let rtxn = vault.store.env.read_txn()?;
    let error = BY_ID
        .scan(&vault.store, &rtxn)
        .expect_err("a five-byte tail is not an id");
    assert_eq!(error.kind(), ErrorKind::SideTableRow);
    Ok(())
}

/// Rows the full test suites wrote at main ce8fd167, before the typed keyspace: one row per
/// declared table they wrote, as `vm|ss <key hex> <value hex>`.
const PRE_MOVE_ROWS: &str = include_str!("../../tests/fixtures/side-table-pre-move-rows.tsv");

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("fixture hex"))
        .collect()
}

/// Decodes one stored value with its table's declared codec and encodes it again: the bytes a
/// typed table writes back for the value it read.
fn reencode(decl: &SideTableDecl, value: &[u8]) -> Vec<u8> {
    fn msgpack(body: &[u8], table: &str) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(body);
        let decoded = rmpv::decode::read_value(&mut cursor)
            .unwrap_or_else(|error| panic!("{table}: stored row does not decode: {error}"));
        assert_eq!(
            cursor.position(),
            body.len() as u64,
            "{table}: trailing bytes"
        );
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &decoded).expect("encode");
        out
    }
    match decl.codec {
        CodecName::Named | CodecName::LegacyCompact => msgpack(value, decl.name),
        CodecName::VersionedNamed => {
            let (version, body) = value
                .split_first()
                .expect("a versioned row has a version byte");
            [vec![*version], msgpack(body, decl.name)].concat()
        }
        CodecName::LegacyJson => {
            let decoded: serde_json::Value =
                serde_json::from_slice(value).unwrap_or_else(|error| {
                    panic!("{}: stored row does not decode: {error}", decl.name)
                });
            serde_json::to_vec(&decoded).expect("encode")
        }
        CodecName::Raw => value.to_vec(),
    }
}

#[test]
fn a_vault_written_before_the_move_reads_back_unchanged() -> crate::Result<()> {
    let (_dir, vault) = open_vault();
    let rows: Vec<(SideDb, Vec<u8>, Vec<u8>)> = PRE_MOVE_ROWS
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let mut columns = line.split('\t');
            let db = match columns.next() {
                Some("vm") => SideDb::VaultMeta,
                Some("ss") => SideDb::SyncState,
                other => panic!("fixture database {other:?}"),
            };
            let key = unhex(columns.next().expect("key"));
            let value = unhex(columns.next().expect("value"));
            (db, key, value)
        })
        .collect();
    assert!(
        rows.len() > 500,
        "the fixture carries a row per written table"
    );
    vault.with_write_txn(|wtxn| {
        for (db, key, value) in &rows {
            match db {
                SideDb::VaultMeta => vault.store.vault_meta.put(wtxn, key, value)?,
                SideDb::SyncState => vault.store.sync_state.put(
                    wtxn,
                    std::str::from_utf8(key).expect("sync_state keys are text"),
                    value,
                )?,
            }
        }
        Ok(())
    })?;

    let rtxn = vault.store.env.read_txn()?;
    let mut stored = std::collections::BTreeMap::new();
    for decl in declared() {
        let mut rows_of_table = Vec::new();
        match decl.db {
            SideDb::VaultMeta => {
                for row in vault.store.vault_meta.prefix_iter(&rtxn, decl.prefix)? {
                    let (key, value) = row?;
                    rows_of_table.push((key.into_owned(), value.into_owned()));
                }
            }
            SideDb::SyncState => {
                let prefix =
                    std::str::from_utf8(decl.prefix).expect("sync_state prefixes are text");
                for row in vault.store.sync_state.prefix_iter(&rtxn, prefix)? {
                    let (key, value) = row?;
                    rows_of_table.push((key.as_bytes().to_vec(), value.into_owned()));
                }
            }
        }
        for (key, value) in rows_of_table {
            assert_eq!(
                reencode(decl, &value),
                value,
                "{}: a row does not read back as its stored bytes",
                decl.name
            );
            let previous = stored.insert((decl.db == SideDb::SyncState, key), decl.name);
            assert_eq!(previous, None, "a row belongs to two declared tables");
        }
    }
    for (db, key, value) in &rows {
        let read = match db {
            SideDb::VaultMeta => vault
                .store
                .vault_meta
                .get(&rtxn, key)?
                .map(std::borrow::Cow::into_owned),
            SideDb::SyncState => vault
                .store
                .sync_state
                .get(&rtxn, std::str::from_utf8(key).expect("text"))?
                .map(std::borrow::Cow::into_owned),
        };
        assert_eq!(read.as_ref(), Some(value));
        assert!(
            stored.contains_key(&(*db == SideDb::SyncState, key.clone())),
            "a pre-move row belongs to no declared table: {}",
            String::from_utf8_lossy(key)
        );
    }
    let vault_meta_rows = vault.store.vault_meta.iter(&rtxn)?.count();
    let sync_state_rows = vault.store.sync_state.iter(&rtxn)?.count();
    assert_eq!(
        stored.len(),
        vault_meta_rows + sync_state_rows,
        "every row of both side tables belongs to a declared table"
    );
    Ok(())
}

#[test]
fn a_side_table_read_refuses_an_unknown_version_byte() -> crate::Result<()> {
    const BLUEPRINTS: SideTable<Vec<u8>, rmpv::Value, VersionedNamed<1>> =
        SideTable::new(&CHECKOUT_ENV_BLUEPRINT);
    let (_dir, vault) = open_vault();
    let key = vec![7_u8; 32];
    let body = rmpv::Value::Map(vec![("steps".into(), rmpv::Value::Array(Vec::new()))]);
    vault.with_write_txn(|wtxn| BLUEPRINTS.put(&vault.store, wtxn, &key, &body))?;
    let mut next_version = BLUEPRINTS.encode_value(&body)?;
    next_version[0] = 2;
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .vault_meta
            .put(wtxn, &BLUEPRINTS.key_bytes(&key), &next_version)
    })?;

    let rtxn = vault.store.env.read_txn()?;
    let error = BLUEPRINTS
        .get(&vault.store, &rtxn, &key)
        .expect_err("a row of the next version is refused");
    assert!(matches!(
        error,
        crate::Error::Store(crate::error::StoreError::SideTableRow {
            problem: crate::error::SideTableRowProblem::UnknownVersion {
                found: 2,
                expected: 1
            },
            ..
        })
    ));
    Ok(())
}

/// The scan rule, stated once. In every production source file outside `side_table/` (test files,
/// `#[cfg(test)]` modules and `#[cfg(test)]` items masked), find each raw `vault_meta` /
/// `sync_state` call (`get`, `put`, `delete`, `prefix_iter`, `range`, `rev_range`, and the
/// `Vault::sync_state_*` doors) and take its key argument. Collect the key literals that argument
/// is built from: string and byte literals, the head of a `format!` string and its named
/// placeholders, SCREAMING_CASE consts resolved crate-wide (same file first), and, three levels deep,
/// the bodies of `fn` builders and the nearest earlier `let` bindings whose name says key or
/// prefix. A literal counts when it is spelled like a key (no spaces, at least one `.`, `:`, `/`
/// or NUL); literals on a line that feeds a hash (`hash`, `blake3`, `digest`, `derive`,
/// `update(`) are domains, not keys. Each key must be headed by a counted literal that equals a
/// declared prefix of the call's database or lies under one; its other literals are tags inside
/// that table. A `format!` head followed by a placeholder (`manifest:{kind}:`) names a family
/// whose next segment is a variable tag, and passes when a declared prefix continues it.
#[test]
fn every_side_table_prefix_in_the_crate_is_declared() {
    use crate::test_util::source_scan::{SourceTree, mask_cfg_test_modules};
    use std::collections::{BTreeMap, BTreeSet};

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let tree = SourceTree::read(&src);
    let files: Vec<(String, String)> = tree
        .production_sources()
        .map(|(path, source)| {
            (
                tree.relative(path),
                mask_cfg_test_items(&mask_cfg_test_modules(source)),
            )
        })
        .filter(|(rel, _)| !rel.starts_with("side_table/"))
        .collect();
    assert!(files.len() > 900, "the scan reads the crate");

    let scan = Scan::new();
    let mut consts: BTreeMap<String, Vec<(usize, Vec<u8>)>> = BTreeMap::new();
    let mut functions: BTreeMap<String, Vec<(usize, String)>> = BTreeMap::new();
    for (index, (_, source)) in files.iter().enumerate() {
        for found in scan.constant.captures_iter(source) {
            consts
                .entry(found[1].to_owned())
                .or_default()
                .push((index, unescape(&found[3])));
        }
        for found in scan.function.captures_iter(source) {
            let start = found.get(0).expect("match").end();
            if let Some(body) = braced(source, start) {
                functions
                    .entry(found[1].to_owned())
                    .or_default()
                    .push((index, body.to_owned()));
            }
        }
    }
    let paths = files.iter().map(|(rel, _)| rel.clone()).collect();
    let scan = Scan {
        consts,
        functions,
        paths,
        ..scan
    };

    let declared_prefixes: Vec<&SideTableDecl> = declared().collect();
    let mut undeclared = BTreeSet::new();
    let mut checked = 0;
    for (index, (rel, source)) in files.iter().enumerate() {
        for found in scan.call.captures_iter(source) {
            let whole = found.get(0).expect("match");
            let db = if found.get(1).is_some_and(|m| m.as_str() == "vault_meta") {
                SideDb::VaultMeta
            } else {
                SideDb::SyncState
            };
            let Some(arguments) = parenthesized(source, whole.end() - 1) else {
                continue;
            };
            let arguments = top_level_arguments(arguments);
            let key = match (
                found.get(2).map(|m| m.as_str()),
                found.get(3).map(|m| m.as_str()),
            ) {
                (Some(_), _) => arguments.get(1),
                (None, Some("put" | "visit_prefix")) => arguments
                    .len()
                    .checked_sub(2)
                    .and_then(|at| arguments.get(at)),
                (None, _) => arguments.last(),
            };
            let Some(key) = key else {
                continue;
            };
            let mut found_keys = Collected::default();
            scan.collect(key, &source[..whole.start()], index, 3, &mut found_keys);
            let Collected {
                literals, heads, ..
            } = found_keys;
            let literals: Vec<Vec<u8>> = literals
                .into_iter()
                .filter(|literal| key_shaped(literal))
                .collect();
            let covered = |literal: &[u8]| {
                declared_prefixes
                    .iter()
                    .any(|decl| decl.db == db && literal.starts_with(decl.prefix))
            };
            // A `format!` head followed by a placeholder names a family whose next segment is a
            // variable tag: it is declared when a declared prefix continues it.
            let family = |head: &[u8]| {
                declared_prefixes.iter().any(|decl| {
                    decl.db == db
                        && (head.starts_with(decl.prefix) || decl.prefix.starts_with(head))
                })
            };
            let heads: Vec<Vec<u8>> = heads.into_iter().filter(|head| key_shaped(head)).collect();
            for head in &heads {
                checked += 1;
                if !family(head) {
                    undeclared.insert(format!("{rel}: {:?}", String::from_utf8_lossy(head)));
                }
            }
            // A key whose head is declared may carry tag literals after it (`rule\0`, `obj:`).
            let headed = !heads.is_empty() || literals.iter().any(|literal| covered(literal));
            for literal in &literals {
                checked += 1;
                if !headed {
                    undeclared.insert(format!("{rel}: {:?}", String::from_utf8_lossy(literal)));
                }
            }
        }
    }
    assert!(checked > 50, "the scan found the key literals ({checked})");
    assert!(
        undeclared.is_empty(),
        "undeclared side-table prefixes:\n{}",
        {
            let list: Vec<String> = undeclared.into_iter().collect();
            list.join("\n")
        }
    );
}

struct Scan {
    call: regex::Regex,
    constant: regex::Regex,
    function: regex::Regex,
    binding: regex::Regex,
    token: regex::Regex,
    consts: std::collections::BTreeMap<String, Vec<(usize, Vec<u8>)>>,
    functions: std::collections::BTreeMap<String, Vec<(usize, String)>>,
    paths: Vec<String>,
}

impl Scan {
    fn new() -> Self {
        let regex = |pattern: &str| regex::Regex::new(pattern).expect("regex");
        Self {
            call: regex(
                r"\b(vault_meta|sync_state)(?:\(\))?\s*\.\s*(get|put|delete|prefix_iter|range|rev_range)\s*\(|\bsync_state_(get|put|delete|keys_with_prefix|visit_prefix)\w*\s*\(",
            ),
            constant: regex(r#"const\s+([A-Z][A-Z0-9_]*)\s*:[^=;]*=\s*\*?(b?)"((?:[^"\\]|\\.)*)""#),
            function: regex(r"\bfn\s+([a-z_][a-z0-9_]*)\s*[<(]"),
            binding: regex(r"\blet\s+(?:mut\s+)?([a-z_][a-z0-9_]*)\s*(?::[^=;]*)?="),
            token: regex(
                r#"(b?)"((?:[^"\\]|\\.)*)"|\b([A-Z][A-Z0-9_]{2,})\b|\b([a-z_][a-z0-9_]*)\s*\("#,
            ),
            consts: std::collections::BTreeMap::new(),
            functions: std::collections::BTreeMap::new(),
            paths: Vec::new(),
        }
    }

    fn resolve_const(&self, name: &str, file: usize) -> Option<Vec<u8>> {
        self.nearest(self.consts.get(name)?, file)
            .map(|(_, value)| value.clone())
    }

    fn resolve_fn(&self, name: &str, file: usize) -> Option<(usize, &str)> {
        self.nearest(self.functions.get(name)?, file)
            .map(|(at, body)| (*at, body.as_str()))
    }

    /// The definition in the same file, else the only one in the same directory, else the only
    /// one in the crate.
    fn nearest<'a, T>(&self, entries: &'a [(usize, T)], file: usize) -> Option<&'a (usize, T)> {
        let directory = |at: usize| self.paths[at].rsplit_once('/').map_or("", |(dir, _)| dir);
        let sibling: Vec<_> = entries
            .iter()
            .filter(|(at, _)| directory(*at) == directory(file))
            .collect();
        entries
            .iter()
            .find(|(at, _)| *at == file)
            .or_else(|| (sibling.len() == 1).then(|| sibling[0]))
            .or_else(|| (entries.len() == 1).then(|| &entries[0]))
    }

    /// Collects the key literals `text` is built from; `scope` is the source before `text`, where
    /// its `let` bindings live. See the rule on the scan test.
    fn collect(&self, text: &str, scope: &str, file: usize, depth: usize, keys: &mut Collected) {
        const HASHING: [&str; 5] = ["hash", "blake3", "digest", "derive", "update("];
        for line in text.lines() {
            let lowered = line.to_ascii_lowercase();
            if HASHING.iter().any(|needle| lowered.contains(needle)) {
                continue;
            }
            for found in self.token.captures_iter(line) {
                if let Some(literal) = found.get(2) {
                    let raw = literal.as_str();
                    let opening = found.get(0).expect("match").start();
                    let formatted = line[..opening].trim_end().ends_with("format!(");
                    if formatted && raw.contains('{') {
                        keys.heads
                            .push(unescape(raw.split('{').next().unwrap_or_default()));
                    } else {
                        keys.literals.push(unescape(raw));
                    }
                    for placeholder in raw.split('{').skip(1) {
                        let name = placeholder.split(['}', ':']).next().unwrap_or_default();
                        if name.starts_with(|c: char| c.is_ascii_uppercase()) {
                            keys.literals.extend(self.resolve_const(name, file));
                        }
                    }
                } else if let Some(name) = found.get(3) {
                    keys.literals
                        .extend(self.resolve_const(name.as_str(), file));
                } else if let Some(name) = found.get(4) {
                    let name = name.as_str();
                    if depth == 0 || !names_a_key(name) || !keys.seen.insert(format!("fn {name}")) {
                        continue;
                    }
                    if let Some((home, body)) = self.resolve_fn(name, file) {
                        self.collect(body, body, home, depth - 1, keys);
                    }
                }
            }
            for word in line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_')) {
                if !word.starts_with(|c: char| c.is_ascii_lowercase())
                    || !names_a_key(word)
                    || depth == 0
                    || !keys.seen.insert(format!("let {word}"))
                {
                    continue;
                }
                let nearest = self
                    .binding
                    .captures_iter(scope)
                    .filter(|found| &found[1] == word)
                    .last();
                if let Some(found) = nearest {
                    let start = found.get(0).expect("match").end();
                    let end = scope[start..]
                        .find(';')
                        .map_or(scope.len(), |at| start + at);
                    self.collect(&scope[start..end], &scope[..start], file, depth - 1, keys);
                }
            }
        }
    }
}

/// What one key expression is built from: its literals, its `format!` heads, and the builders and
/// bindings already followed.
#[derive(Default)]
struct Collected {
    literals: Vec<Vec<u8>>,
    heads: Vec<Vec<u8>>,
    seen: std::collections::BTreeSet<String>,
}

/// A builder or binding whose name says it holds a key.
fn names_a_key(name: &str) -> bool {
    name.contains("key") || name.contains("prefix")
}

/// A literal spelled like a key: no spaces, and at least one `.`, `:`, `/` or NUL separator.
fn key_shaped(literal: &[u8]) -> bool {
    literal.len() >= 3
        && literal
            .iter()
            .any(|byte| matches!(byte, b'.' | b':' | b'/' | 0))
        && literal.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'/' | b'_' | b'-' | 0)
        })
}

/// Blanks every `#[cfg(test)]` item that carries a `{ .. }` body.
fn mask_cfg_test_items(source: &str) -> String {
    let mut out = source.to_owned();
    let mut from = 0;
    while let Some(at) = out[from..].find("#[cfg(test)]").map(|at| from + at) {
        let after = at + "#[cfg(test)]".len();
        from = after;
        let Some(open) = out[after..].find('{').map(|open| after + open) else {
            break;
        };
        if out[after..open].contains(';') {
            continue;
        }
        if let Some(body) = delimited(&out, open, b'{', b'}') {
            let end = open + body.len() + 2;
            let blank: String = out[at..end]
                .chars()
                .map(|c| if c == '\n' { '\n' } else { ' ' })
                .collect();
            out.replace_range(at..end, &blank);
        }
    }
    out
}

/// Splits call arguments at top-level commas.
fn top_level_arguments(text: &str) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let (mut depth, mut start, mut in_string) = (0_i32, 0, false);
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\\' if in_string => at += 1,
            b'"' => in_string = !in_string,
            b'(' | b'[' | b'{' if !in_string => depth += 1,
            b')' | b']' | b'}' if !in_string => depth -= 1,
            b',' if !in_string && depth == 0 => {
                parts.push(&text[start..at]);
                start = at + 1;
            }
            _ => {}
        }
        at += 1;
    }
    if !text[start..].trim().is_empty() {
        parts.push(&text[start..]);
    }
    parts
}

/// The text between the parenthesis at `open` and its match.
fn parenthesized(source: &str, open: usize) -> Option<&str> {
    delimited(source, open, b'(', b')')
}

/// The body of the first `{ .. }` block at or after `from`.
fn braced(source: &str, from: usize) -> Option<&str> {
    let open = from + source[from..].find('{')?;
    if source[from..open].contains(';') {
        return None;
    }
    delimited(source, open, b'{', b'}')
}

fn delimited(source: &str, open: usize, left: u8, right: u8) -> Option<&str> {
    let bytes = source.as_bytes();
    let mut depth = 0_usize;
    let mut at = open;
    let mut in_string = false;
    while at < bytes.len() {
        let byte = bytes[at];
        if in_string {
            if byte == b'\\' {
                at += 1;
            } else if byte == b'"' {
                in_string = false;
            }
        } else if byte == b'"' {
            in_string = true;
        } else if byte == left {
            depth += 1;
        } else if byte == right {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return source.get(open + 1..at);
            }
        }
        at += 1;
    }
    None
}

fn unescape(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\' && at + 1 < bytes.len() {
            match bytes[at + 1] {
                b'0' => out.push(0),
                b'n' => out.push(b'\n'),
                b'x' if at + 3 < bytes.len() => {
                    out.push(u8::from_str_radix(&text[at + 2..at + 4], 16).unwrap_or(0));
                    at += 2;
                }
                other => out.push(other),
            }
            at += 2;
        } else {
            out.push(bytes[at]);
            at += 1;
        }
    }
    out
}
