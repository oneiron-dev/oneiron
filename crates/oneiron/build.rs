//! Assembles the side-table catalogue from every `side_tables!` row in `src` (core split slice 1;
//! Fable's verdict of 9 Nov 2026, MODIFY A).
//!
//! The `side_tables!` macro expands each row into its `static` where the row is written. This
//! script writes only `$OUT_DIR/side_table_catalogue.rs`, included by `side_table::decls`:
//! - a `pub(crate) use` of every row declared outside `side_table::decls`, so `side_table::NAME`
//!   names every table wherever its row lives, and two rows of one name do not compile. A row no
//!   code reads by that path is still re-exported, so the uses allow `unused_imports`;
//! - `CATALOGUE`, a `&crate::<module>::NAME` reference to every row, sorted by database (`sync_state`
//!   first) and then by prefix bytes. That is the order the actor-scrub sweep runs in and the order
//!   `assert_disjoint` checks at compile time.
//!
//! Convention: rows live in `side_table/decls/*.rs` (included into `side_table::decls`) or in
//! `src/<module path>/tables.rs`, whose module path this script reads from the file path. A file
//! that does not sit at its module path does not compile.
//!
//! Nothing is skipped: a row this script cannot read, or a row attribute other than a doc comment,
//! fails the build. The script reads only the files rows may live in (every `tables.rs`, every file
//! under `side_table/decls/`); `side_tables!` itself refuses, at compile time, to expand anywhere
//! else, and every row names its `side_table::NAME` re-export, so a row this script missed does not
//! compile either.
//!
//! `rerun-if-changed` inputs: this script, the files it reads, `lib.rs` and each directory's module
//! file (`<dir>.rs` or `<dir>/mod.rs`), where a new `mod tables;` has to be declared. Not the
//! directories: Cargo scans a watched directory recursively, so any edit in `src` would rerun the
//! scan. An edit to any other file does not rerun it.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

/// One `side_tables!` row: what the catalogue needs to place it.
struct Row {
    name: String,
    db_rank: u8,
    prefix: Vec<u8>,
    module: String,
    at: String,
}

const DECLS_DIR: &str = "side_table/decls/";
const DECLS_MODULE: &str = "side_table::decls";
const DATABASES: [&str; 2] = ["SyncState", "VaultMeta"];
const CODECS: [&str; 5] = [
    "Named",
    "VersionedNamed",
    "LegacyJson",
    "LegacyCompact",
    "Raw",
];

fn main() {
    // The SDK outputs this crate includes, generated at build time (crates/oneiron-sdk-build).
    oneiron_sdk_build::generate(&[
        "crates/oneiron/src/verbs/generated/verb_catalog.rs",
        "crates/oneiron/src/verbs/generated/run_verb_catalog.rs",
        "crates/oneiron/src/verbs/generated/sdk_generated.rs",
        "crates/oneiron/src/verbs/generated/catalog_fragment_revision.rs",
        "crates/oneiron/src/verbs/generated/catalog_fragment.d.ts",
        "crates/oneiron/src/verbs/generated/code-mode.d.ts",
        "crates/oneiron/src/generated/core_verb_names.rs",
    ]);
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let src = manifest.join("src");
    println!("cargo:rerun-if-changed=build.rs");
    let (mut files, mut dirs) = (Vec::new(), Vec::new());
    collect_row_files(&src, &src.join(DECLS_DIR), &mut files, &mut dirs);
    files.sort();
    dirs.sort();
    // A new `tables.rs` (or decl file) is declared in its directory's module file, so watching the
    // module files sees it without watching the directories themselves.
    println!("cargo:rerun-if-changed={}", src.join("lib.rs").display());
    for dir in &dirs {
        for module_file in [dir.with_extension("rs"), dir.join("mod.rs")] {
            if module_file.is_file() {
                println!("cargo:rerun-if-changed={}", module_file.display());
            }
        }
    }
    let mut rows = Vec::new();
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
        let text = fs::read_to_string(file)
            .unwrap_or_else(|error| panic!("reading {}: {error}", file.display()));
        if !text.contains("side_tables") {
            continue;
        }
        let rel = file
            .strip_prefix(&src)
            .expect("a scanned file is under src")
            .to_string_lossy()
            .replace('\\', "/");
        read_invocations(&rel, &tokens(&text, &rel), &mut rows);
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"))
        .join("side_table_catalogue.rs");
    let generated = render(rows);
    if fs::read_to_string(&out).ok().as_deref() != Some(generated.as_str()) {
        fs::write(&out, generated)
            .unwrap_or_else(|error| panic!("writing {}: {error}", out.display()));
    }
}

/// Every file a row may live in under `dir`: each `tables.rs`, and each `.rs` file under `decls`
/// (nested ones too, so `module_of` refuses them). Every directory below `dir` goes to `dirs`.
fn collect_row_files(dir: &Path, decls: &Path, out: &mut Vec<PathBuf>, dirs: &mut Vec<PathBuf>) {
    let entries =
        fs::read_dir(dir).unwrap_or_else(|error| panic!("listing {}: {error}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|error| panic!("listing {}: {error}", dir.display()))
            .path();
        if path.is_dir() {
            dirs.push(path.clone());
            collect_row_files(&path, decls, out, dirs);
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && (path.starts_with(decls) || path.file_name().is_some_and(|name| name == "tables.rs"))
        {
            out.push(path);
        }
    }
}

/// The module a file's rows are declared in: `side_table::decls` for the included decl files, the
/// file's own module for a `tables.rs`. Anywhere else, rows would not reach the catalogue.
fn module_of(rel: &str) -> String {
    if let Some(name) = rel.strip_prefix(DECLS_DIR) {
        assert!(
            !name.contains('/') && name != "mod.rs",
            "side_tables! rows in {rel}: decl files sit directly in {DECLS_DIR}"
        );
        return DECLS_MODULE.to_owned();
    }
    let Some(dir) = rel.strip_suffix("/tables.rs") else {
        panic!(
            "side_tables! is invoked in {rel}: rows live in a module's tables.rs or in {DECLS_DIR}*.rs"
        );
    };
    format!("{}::tables", dir.replace('/', "::"))
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Punct(String),
    /// A literal: its source text.
    Literal(String),
    Open(char),
    Close(char),
}

/// The tokens of a Rust file, without comments. Enough of the lexer to find macro invocations and read
/// rows: identifiers, punctuation (`::` and `=>` as one token), literals (strings, byte strings, raw
/// strings, chars, numbers) and delimiters. A lifetime is one punctuation token.
fn tokens(text: &str, rel: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            let mut depth = 0usize;
            loop {
                assert!(i < chars.len(), "{rel}: an unterminated block comment");
                if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    i += 1;
                }
            }
        } else if let Some(end) = string_literal_end(&chars, i, rel) {
            out.push(Token::Literal(chars[i..end].iter().collect()));
            i = end;
        } else if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            out.push(Token::Ident(chars[start..i].iter().collect()));
        } else if c.is_ascii_digit() {
            let start = i;
            while i < chars.len()
                && (chars[i].is_alphanumeric()
                    || chars[i] == '_'
                    || (chars[i] == '.' && chars.get(i + 1).is_some_and(char::is_ascii_digit)))
            {
                i += 1;
            }
            out.push(Token::Literal(chars[start..i].iter().collect()));
        } else if c == '\'' {
            i = char_or_lifetime(&chars, i, rel, &mut out);
        } else if "([{".contains(c) {
            out.push(Token::Open(c));
            i += 1;
        } else if ")]}".contains(c) {
            out.push(Token::Close(c));
            i += 1;
        } else {
            let two: String = chars[i..chars.len().min(i + 2)].iter().collect();
            if two == "::" || two == "=>" {
                out.push(Token::Punct(two));
                i += 2;
            } else {
                out.push(Token::Punct(c.to_string()));
                i += 1;
            }
        }
    }
    out
}

/// The end of a string-like literal starting at `i` (`"..."`, `b"..."`, `c"..."`, `r#"..."#`,
/// `br"..."`, `b'x'`), or `None` when none starts there. `i` is a token boundary.
fn string_literal_end(chars: &[char], i: usize, rel: &str) -> Option<usize> {
    let mut j = i;
    if matches!(chars.get(j), Some('b' | 'c')) {
        j += 1;
    }
    if chars.get(j) == Some(&'r') && matches!(chars.get(j + 1), Some('"' | '#')) {
        let mut k = j + 1;
        let mut hashes = 0;
        while chars.get(k) == Some(&'#') {
            hashes += 1;
            k += 1;
        }
        if chars.get(k) != Some(&'"') {
            return None; // a raw identifier (`r#type`)
        }
        k += 1;
        loop {
            assert!(k < chars.len(), "{rel}: an unterminated raw string");
            if chars[k] == '"' && (0..hashes).all(|h| chars.get(k + 1 + h) == Some(&'#')) {
                return Some(k + 1 + hashes);
            }
            k += 1;
        }
    }
    match chars.get(j) {
        Some('"') => Some(quoted_end(chars, j, '"', rel)),
        Some('\'') if j == i + 1 && chars[i] == 'b' => Some(quoted_end(chars, j, '\'', rel)),
        _ => None,
    }
}

fn quoted_end(chars: &[char], open: usize, quote: char, rel: &str) -> usize {
    let mut j = open + 1;
    loop {
        assert!(j < chars.len(), "{rel}: an unterminated literal");
        match chars[j] {
            '\\' => j += 2,
            c if c == quote => return j + 1,
            _ => j += 1,
        }
    }
}

fn char_or_lifetime(chars: &[char], i: usize, rel: &str, out: &mut Vec<Token>) -> usize {
    // `'x'`, `'\n'`, `'\u{..}'` are chars; `'a` (not closed one char later) is a lifetime or label
    if chars.get(i + 1) == Some(&'\\') || chars.get(i + 2) == Some(&'\'') {
        let end = quoted_end(chars, i, '\'', rel);
        out.push(Token::Literal(chars[i..end].iter().collect()));
        return end;
    }
    let mut j = i + 1;
    while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
        j += 1;
    }
    out.push(Token::Punct(chars[i..j].iter().collect()));
    j
}

/// Every `side_tables!` invocation in a file's tokens: its rows, placed in the file's module.
fn read_invocations(rel: &str, toks: &[Token], rows: &mut Vec<Row>) {
    let mut i = 0;
    while i < toks.len() {
        let is_call = toks[i] == Token::Ident("side_tables".to_owned())
            && toks.get(i + 1) == Some(&Token::Punct("!".to_owned()));
        if !is_call {
            // `side_tables` not followed by `!` is a field, a variable or the macro's own name
            i += 1;
            continue;
        }
        let module = module_of(rel);
        let Some(Token::Open(open)) = toks.get(i + 2) else {
            panic!("{rel}: side_tables! is not followed by a delimiter");
        };
        let close = match open {
            '{' => '}',
            '(' => ')',
            _ => ']',
        };
        let (body, end) = group(toks, i + 2, *open, close, rel);
        read_rows(rel, &module, body, rows);
        i = end;
    }
}

/// The tokens inside the group opened at `start`, and the index after its close.
fn group<'a>(
    toks: &'a [Token],
    start: usize,
    open: char,
    close: char,
    rel: &str,
) -> (&'a [Token], usize) {
    let mut depth = 0usize;
    for (index, tok) in toks.iter().enumerate().skip(start) {
        match tok {
            Token::Open(_) => depth += 1,
            Token::Close(c) => {
                depth -= 1;
                if depth == 0 {
                    assert_eq!(
                        *c, close,
                        "{rel}: a side_tables! group opened with {open} closes with {c}"
                    );
                    return (&toks[start + 1..index], index + 1);
                }
            }
            _ => {}
        }
    }
    panic!("{rel}: an unclosed side_tables! invocation");
}

fn read_rows(rel: &str, module: &str, body: &[Token], rows: &mut Vec<Row>) {
    let mut segments: Vec<&[Token]> = Vec::new();
    let (mut depth, mut start) = (0usize, 0usize);
    for (index, tok) in body.iter().enumerate() {
        match tok {
            Token::Open(_) => depth += 1,
            Token::Close(_) => depth -= 1,
            Token::Punct(p) if p == ";" && depth == 0 => {
                segments.push(&body[start..index]);
                start = index + 1;
            }
            _ => {}
        }
    }
    assert!(
        body[start..].is_empty(),
        "{rel}: a side_tables! row does not end with `;`"
    );
    for (index, segment) in segments.into_iter().enumerate() {
        // the decl files' list name (`VAULT_META_M;`), first and alone
        if index == 0 && segment.len() == 1 && matches!(&segment[0], Token::Ident(_)) {
            continue;
        }
        rows.push(read_row(rel, module, segment));
    }
}

/// `#[doc ..]* NAME: DB b"prefix" CODEC ...;` (the rest of the row is the macro's to read).
fn read_row(rel: &str, module: &str, row: &[Token]) -> Row {
    // Doc comments are comments to this lexer; a `#[doc ..]` attribute is read past. Any other
    // attribute (a `#[cfg]`) would make a static the catalogue names unconditionally exist only in
    // some builds, so the catalogue would depend on the feature set: refused.
    let mut i = 0;
    while row.get(i) == Some(&Token::Punct("#".to_owned())) {
        let (Some(Token::Open('[')), Some(Token::Ident(attribute))) =
            (row.get(i + 1), row.get(i + 2))
        else {
            panic!("{rel}: a side_tables! row has a malformed attribute");
        };
        assert!(
            attribute == "doc",
            "{rel}: a side_tables! row carries #[{attribute} ..]: only doc attributes are allowed"
        );
        let (_, end) = group(row, i + 1, '[', ']', rel);
        i = end;
    }
    let at = format!("{rel}, row {:?}", row.get(i));
    let (
        Some(Token::Ident(name)),
        Some(Token::Punct(colon)),
        Some(Token::Ident(db)),
        Some(Token::Literal(prefix)),
        Some(Token::Ident(codec)),
    ) = (
        row.get(i),
        row.get(i + 1),
        row.get(i + 2),
        row.get(i + 3),
        row.get(i + 4),
    )
    else {
        panic!("{at}: cannot read `NAME: DB b\"prefix\" CODEC`");
    };
    assert!(colon == ":", "{at}: expected `:` after the name");
    assert!(
        name.chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'),
        "{at}: a table name is SCREAMING_CASE"
    );
    let db_rank = DATABASES
        .iter()
        .position(|d| d == db)
        .unwrap_or_else(|| panic!("{at}: unknown database {db}")) as u8;
    assert!(
        CODECS.contains(&codec.as_str()),
        "{at}: unknown codec {codec}"
    );
    Row {
        name: name.clone(),
        db_rank,
        prefix: byte_string(prefix, &at),
        module: module.to_owned(),
        at,
    }
}

/// The bytes of a `b"..."` literal.
fn byte_string(literal: &str, at: &str) -> Vec<u8> {
    let inner = literal
        .strip_prefix("b\"")
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or_else(|| panic!("{at}: a prefix is a b\"...\" literal, not {literal}"));
    let mut out = Vec::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            assert!(c.is_ascii(), "{at}: a byte string holds ASCII only");
            out.push(c as u8);
            continue;
        }
        match chars.next() {
            Some('n') => out.push(b'\n'),
            Some('r') => out.push(b'\r'),
            Some('t') => out.push(b'\t'),
            Some('0') => out.push(0),
            Some('\\') => out.push(b'\\'),
            Some('\'') => out.push(b'\''),
            Some('"') => out.push(b'"'),
            Some('x') => {
                let hex: String = [chars.next(), chars.next()].into_iter().flatten().collect();
                out.push(
                    u8::from_str_radix(&hex, 16).unwrap_or_else(|_| panic!("{at}: bad \\x escape")),
                );
            }
            Some('\n') => {
                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                    chars.next();
                }
            }
            other => panic!("{at}: unknown escape \\{other:?}"),
        }
    }
    out
}

fn render(mut rows: Vec<Row>) -> String {
    let mut names = BTreeSet::new();
    for row in &rows {
        assert!(
            names.insert(row.name.clone()),
            "{}: the table name {} is declared twice",
            row.at,
            row.name
        );
    }
    rows.sort_by(|a, b| (a.db_rank, &a.prefix).cmp(&(b.db_rank, &b.prefix)));
    for pair in rows.windows(2) {
        assert!(
            pair[0].db_rank != pair[1].db_rank || pair[0].prefix != pair[1].prefix,
            "{}: prefix declared twice ({})",
            pair[1].at,
            pair[0].name
        );
    }
    let mut by_module: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for row in &rows {
        if row.module != DECLS_MODULE {
            by_module.entry(&row.module).or_default().push(&row.name);
        }
    }
    let mut out = String::from(
        "// @generated by crates/oneiron/build.rs from every `side_tables!` row in src: do not edit.\n\n",
    );
    for (module, mut members) in by_module {
        members.sort_unstable();
        // Every row is re-exported, read through `side_table::NAME` or not: the re-export is what
        // makes two rows of one name fail to compile.
        writeln!(
            out,
            "#[allow(unused_imports, reason = \"every row is re-exported, so a name declared twice does not compile\")]\npub(crate) use crate::{module}::{{{}}};",
            members.join(", ")
        )
        .expect("writing to a String");
    }
    writeln!(
        out,
        "\n/// Every declared table, sorted by database (`sync_state` first) and prefix bytes: the catalogue order.\n\
         pub(crate) static CATALOGUE: [&SideTableDecl; {}] = [",
        rows.len()
    )
    .expect("writing to a String");
    for row in &rows {
        writeln!(out, "    &crate::{}::{},", row.module, row.name).expect("writing to a String");
    }
    out.push_str("];\n");
    out
}
