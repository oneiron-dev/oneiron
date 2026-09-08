//! Test-only-file classification shared by every source-scanning fence.
//!
//! Mounted twice on purpose so there is exactly ONE answer to "is this file
//! test code?": `crate::test_util::source_scan` for the unit-test fences under
//! `src/**`, and `common::source_scan` (a `#[path]` mount in
//! `tests/common/mod.rs`) for the integration fences under `tests/`. Only
//! `std` is used, so both mounts compile identically. Fences keep their own
//! needles, allowlists, assertion messages and in-file masking; this module
//! only decides which FILES they read.
//!
//! A file is test-only when
//! - (a) its basename is `tests.rs` or ends with `_tests.rs`;
//! - (b) a directory named `tests` or `benches` lies on its path relative to
//!   the scanned tree (`src/x/tests/y.rs`, `tests/it/x.rs`, `benches/x.rs`);
//! - (c) it is reached only through a `#[cfg(test)] mod x;` or
//!   `#[cfg(test)] #[path = ".."] mod x;` declaration, through a declaration
//!   inside an inline `#[cfg(test)] mod <any name> { .. }` body (each with an
//!   optional visibility), or through any `mod x;` / `#[path]` mount from a
//!   file that is itself test-only — transitively.
//!
//! Unknown `#[path]` syntax keeps every file scanned, and a production mount of
//! the same basename anywhere in the tree vetoes (c): scanning a test file as
//! production is the safe failure, hiding production code is not.
#![allow(dead_code)] // each mount uses a subset of these helpers

use std::collections::BTreeSet;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};

/// Every `.rs` file under one root, read once, with the test-only set resolved.
pub(crate) struct SourceTree {
    root: PathBuf,
    sources: Vec<(PathBuf, String)>,
    test_only: BTreeSet<PathBuf>,
}

impl SourceTree {
    /// Reads every `.rs` file under `root` (skipping `.git` and `target`),
    /// sorted by path, and classifies each one. Panics on any unreadable
    /// entry: a fence that silently skips files is not a fence.
    pub(crate) fn read(root: &Path) -> Self {
        let mut files = Vec::new();
        collect_rust_files(root, &mut files);
        files.sort();
        let sources = files
            .into_iter()
            .map(|path| {
                let source = fs::read_to_string(&path)
                    .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
                (path, source)
            })
            .collect::<Vec<_>>();
        let mut test_only = cfg_test_external_files(root, &sources);
        test_only.extend(
            sources
                .iter()
                .filter(|(path, _)| test_only_by_path(&relative(root, path)))
                .map(|(path, _)| path.clone()),
        );
        Self {
            root: root.to_path_buf(),
            sources,
            test_only,
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// Every file in the tree, test-only ones included.
    pub(crate) fn sources(&self) -> &[(PathBuf, String)] {
        &self.sources
    }

    /// `/`-joined path of `path` relative to the tree root.
    pub(crate) fn relative(&self, path: &Path) -> String {
        relative(&self.root, path)
    }

    pub(crate) fn is_test_only(&self, path: &Path) -> bool {
        self.test_only.contains(path)
    }

    /// The files a fence must scan: everything that is not test-only.
    pub(crate) fn production_sources(&self) -> impl Iterator<Item = (&Path, &str)> {
        self.sources
            .iter()
            .filter(|(path, _)| !self.test_only.contains(path))
            .map(|(path, source)| (path.as_path(), source.as_str()))
    }
}

/// Rules (a) and (b) on a `/`-joined path relative to the scanned tree.
pub(crate) fn test_only_by_path(rel: &str) -> bool {
    let mut parts = rel.split('/').rev();
    let Some(name) = parts.next() else {
        return false;
    };
    name == "tests.rs"
        || name.ends_with("_tests.rs")
        || parts.any(|dir| matches!(dir, "tests" | "benches"))
}

/// `/`-joined path of `path` relative to `root`. Every scanned file lies under
/// its root; anything else is a caller bug, never a reason to classify an
/// absolute path (whose directories could spell `tests` anywhere).
pub(crate) fn relative(root: &Path, path: &Path) -> String {
    let rel = path
        .strip_prefix(root)
        .unwrap_or_else(|_| panic!("{} is not under {}", path.display(), root.display()));
    normalized(rel)
}

pub(crate) fn normalized(path: &Path) -> String {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display())) {
        let entry = entry.expect("directory entry");
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), ".git" | "target") {
                continue;
            }
            collect_rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Rule (c). A file is test-only when a `#[cfg(test)]` mount reaches it, or
/// when the file mounting it is itself test-only by name or by an earlier
/// round of this closure. Unknown path syntax keeps every file scanned. Other
/// mounts of the same basename from production files veto an exclusion, even
/// across directories: false positives are safer than hiding code.
pub(crate) fn cfg_test_external_files(
    root: &Path,
    sources: &[(PathBuf, String)],
) -> BTreeSet<PathBuf> {
    let Some(mounts) = external_mounts(sources) else {
        return BTreeSet::new();
    };
    let test_only_file = |path: &Path| test_only_by_path(&relative(root, path));
    let mut tests = BTreeSet::new();
    loop {
        let before = tests.len();
        for mount in &mounts {
            if mount.cfg_test || tests.contains(&mount.parent) || test_only_file(&mount.parent) {
                tests.extend(mount.targets.iter().cloned());
            }
        }
        if tests.len() == before {
            break;
        }
    }
    let production_names = mounts
        .iter()
        .filter(|mount| {
            !mount.cfg_test && !tests.contains(&mount.parent) && !test_only_file(&mount.parent)
        })
        .map(|mount| mount.file_name.clone())
        .collect::<BTreeSet<_>>();
    tests.retain(|path| {
        let file_name = path
            .file_name()
            .expect("mounted filename")
            .to_string_lossy();
        !production_names.contains(file_name.as_ref())
    });
    tests
}

struct ExternalMount {
    parent: PathBuf,
    /// Basename of the mounted file, for the cross-directory veto.
    file_name: String,
    /// Where the mount resolves on disk; empty when the path is not simple.
    targets: Vec<PathBuf>,
    /// A `#[cfg(test)]` (plus optional `#[path]`) mount whose only enclosing
    /// braces are inline modules, or any mount inside an inline `#[cfg(test)]`
    /// module body.
    cfg_test: bool,
}

// Every `mod <name>;` declaration outside comments and literals. `None` means
// unknown `#[path]` syntax somewhere: keep every file scanned.
fn external_mounts(sources: &[(PathBuf, String)]) -> Option<Vec<ExternalMount>> {
    let mut mounts = Vec::new();
    for (parent, source) in sources {
        let clean = strip_comments_and_literals(source);
        let blocks = inline_module_blocks(&clean);
        let test_blocks = cfg_test_module_ranges(&clean);
        for (start, _) in clean.match_indices("mod") {
            if start > 0 && is_ident_byte(clean.as_bytes()[start - 1]) {
                continue;
            }
            let tail = &clean[start + 3..];
            if !tail.starts_with(char::is_whitespace) {
                continue;
            }
            let tail = tail.trim_start();
            let name_end = tail.bytes().take_while(|byte| is_ident_byte(*byte)).count();
            if name_end == 0 || !tail[name_end..].trim_start().starts_with(';') {
                continue;
            }
            let name = &tail[..name_end];
            let chain = inline_module_chain(&blocks, start);
            let inside_test_module = test_blocks.iter().any(|range| range.contains(&start));
            let prefix_start = clean[..start].rfind([';', '{', '}']).map_or(0, |i| i + 1);
            let prefix = &clean[prefix_start..start];
            let compact = prefix.split_whitespace().collect::<String>();
            let compact = without_visibility(&compact);
            let depth = clean[..start]
                .bytes()
                .fold(0isize, |depth, byte| match byte {
                    b'{' | b'(' | b'[' => depth + 1,
                    b'}' | b')' | b']' => depth - 1,
                    _ => depth,
                });
            // Only inline modules enclose this declaration, so the mount
            // resolves exactly; a fn body or macro arm in between does not.
            let simple_nesting = usize::try_from(depth).is_ok_and(|depth| depth == chain.len());
            if !compact.contains("path=") {
                let base = mount_base(parent, &chain, false);
                mounts.push(ExternalMount {
                    parent: parent.clone(),
                    file_name: format!("{name}.rs"),
                    targets: vec![
                        base.join(format!("{name}.rs")),
                        base.join(name).join("mod.rs"),
                    ],
                    cfg_test: inside_test_module || (simple_nesting && compact == "#[cfg(test)]"),
                });
                continue;
            }
            let path_start = prefix_start + prefix.find("#[path")? + "#[path".len();
            let path_end = clean[path_start..start].find(']')?;
            let literal = source[path_start..path_start + path_end]
                .trim()
                .strip_prefix('=')
                .map(str::trim)
                .and_then(|value| value.strip_prefix('"'))
                .and_then(|value| value.strip_suffix('"'))?;
            if literal.contains(['\\', '"']) || compact.matches("path=").count() != 1 {
                return None;
            }
            let mounted = Path::new(literal);
            let file_name = mounted.file_name()?.to_string_lossy().into_owned();
            let simple = mounted.is_relative()
                && mounted
                    .components()
                    .all(|component| matches!(component, std::path::Component::Normal(_)));
            mounts.push(ExternalMount {
                parent: parent.clone(),
                file_name,
                targets: if simple {
                    vec![mount_base(parent, &chain, true).join(mounted)]
                } else {
                    Vec::new()
                },
                cfg_test: inside_test_module
                    || (simple_nesting
                        && matches!(compact, "#[cfg(test)]#[path=]" | "#[path=]#[cfg(test)]")
                        && mounted.components().count() == 1
                        && mounted.is_relative()),
            });
        }
    }
    Some(mounts)
}

// `#[cfg(test)] pub(crate) mod x;` is as test-only as the bare form: drop a
// trailing visibility from the whitespace-free attribute prefix.
fn without_visibility(compact: &str) -> &str {
    if let Some(head) = compact.strip_suffix("pub") {
        return head;
    }
    if let Some(open) = compact.rfind("pub(") {
        let inner = &compact[open + "pub(".len()..];
        if inner.ends_with(')') && !inner[..inner.len() - 1].contains(['(', ')']) {
            return &compact[..open];
        }
    }
    compact
}

// Directory a mount inside `parent` resolves against. `mod name;` next to a
// `mod.rs`/`lib.rs`/`main.rs` parent lives in the parent's directory, else
// under the parent's own stem; inline modules add one directory each. A
// top-level `#[path]` is relative to the parent's directory whatever the
// parent is called (Rust reference, "The path attribute").
fn mount_base(parent: &Path, chain: &[String], path_attr: bool) -> PathBuf {
    let dir = parent.parent().expect("source directory");
    let mod_rs = matches!(
        parent.file_name().and_then(|file| file.to_str()),
        Some("mod.rs" | "lib.rs" | "main.rs")
    );
    let mut base = if mod_rs || (path_attr && chain.is_empty()) {
        dir.to_path_buf()
    } else {
        dir.join(parent.file_stem().expect("source file stem"))
    };
    for module in chain {
        base.push(module);
    }
    base
}

// Every inline `mod <ident> { .. }` block: its byte range and name.
fn inline_module_blocks(clean: &str) -> Vec<(Range<usize>, String)> {
    let mut blocks = Vec::new();
    for (start, _) in clean.match_indices("mod") {
        if start > 0 && is_ident_byte(clean.as_bytes()[start - 1]) {
            continue;
        }
        let Some((name, open)) = inline_module_header(clean, start) else {
            continue;
        };
        let Some(end) = matching_brace_end(clean.as_bytes(), open) else {
            continue;
        };
        blocks.push((start..end, name.to_owned()));
    }
    blocks
}

// Names of the inline modules enclosing byte `at`, outermost first.
fn inline_module_chain(blocks: &[(Range<usize>, String)], at: usize) -> Vec<String> {
    let mut chain = blocks
        .iter()
        .filter(|(range, _)| range.contains(&at))
        .collect::<Vec<_>>();
    chain.sort_by_key(|(range, _)| range.start);
    chain.into_iter().map(|(_, name)| name.clone()).collect()
}

/// Strips comments and string/char literals, then masks every inline
/// `#[cfg(test)] mod <ident> { .. }` body. Byte offsets and line breaks are
/// preserved, so hits in the result map straight back to the original.
pub(crate) fn production_source(source: &str) -> String {
    mask_cfg_test_modules(&strip_comments_and_literals(source))
}

pub(crate) fn strip_comments_and_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = vec![b' '; bytes.len()];
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            i += 1;
        } else if bytes[i..].starts_with(b"//") {
            i = copy_until_newline(bytes, &mut out, i);
        } else if bytes[i..].starts_with(b"/*") {
            i = skip_block_comment(bytes, &mut out, i);
        } else if raw_string_hashes(bytes, i).is_some() {
            i = skip_raw_string(bytes, &mut out, i);
        } else if bytes[i] == b'"' {
            i = skip_quoted(bytes, &mut out, i, b'"');
        } else if bytes[i] == b'\'' && looks_like_char_literal(bytes, i) {
            i = skip_quoted(bytes, &mut out, i, b'\'');
        } else {
            out[i] = bytes[i];
            i += 1;
        }
    }
    String::from_utf8(out).expect("sanitized source is ASCII/newline")
}

fn copy_until_newline(bytes: &[u8], out: &mut [u8], mut i: usize) -> usize {
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            return i + 1;
        }
        i += 1;
    }
    i
}

fn skip_block_comment(bytes: &[u8], out: &mut [u8], mut i: usize) -> usize {
    let mut depth = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            i += 1;
        } else if bytes[i..].starts_with(b"/*") {
            depth += 1;
            i += 2;
        } else if bytes[i..].starts_with(b"*/") {
            depth = depth.saturating_sub(1);
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    i
}

fn raw_string_hashes(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'r') {
        return None;
    }
    if start > 0 && is_ident_byte(bytes[start - 1]) {
        return None;
    }

    let mut i = start + 1;
    while bytes.get(i) == Some(&b'#') {
        i += 1;
    }
    (bytes.get(i) == Some(&b'"')).then_some(i - start - 1)
}

fn skip_raw_string(bytes: &[u8], out: &mut [u8], start: usize) -> usize {
    let hashes = raw_string_hashes(bytes, start).expect("raw string start");
    let terminator = vec![b'#'; hashes];
    let mut i = start + hashes + 2;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            i += 1;
            continue;
        }
        if bytes[i] == b'"' && bytes.get(i + 1..i + 1 + hashes) == Some(&terminator[..]) {
            return i + hashes + 1;
        }
        i += 1;
    }
    i
}

fn looks_like_char_literal(bytes: &[u8], start: usize) -> bool {
    let mut i = start + 1;
    if bytes.get(i) == Some(&b'\\') {
        i += 2;
    } else {
        i += 1;
    }
    bytes.get(i) == Some(&b'\'')
}

fn skip_quoted(bytes: &[u8], out: &mut [u8], mut i: usize, quote: u8) -> usize {
    i += 1;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            out[i] = b'\n';
            i += 1;
        } else if bytes[i] == b'\\' {
            i = (i + 2).min(bytes.len());
        } else if bytes[i] == quote {
            return i + 1;
        } else {
            i += 1;
        }
    }
    i
}

/// Masks every inline `#[cfg(test)] mod <ident> { ... }` body, whatever the
/// module is called: cfg(test) items never link into a production build.
pub(crate) fn mask_cfg_test_modules(source: &str) -> String {
    let mut out = source.as_bytes().to_vec();
    for range in cfg_test_module_ranges(source) {
        mask_range_preserving_newlines(&mut out, range.start, range.end);
    }
    String::from_utf8(out).expect("masked source remains utf8")
}

// Byte ranges of every `#[cfg(test)] mod <ident> { ... }`, attribute included.
fn cfg_test_module_ranges(source: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    let mut search_start = 0;
    while let Some(rel_cfg) = source[search_start..].find("#[cfg(test)]") {
        let cfg_start = search_start + rel_cfg;
        search_start = cfg_start + "#[cfg(test)]".len();
        let Some((_, open)) = inline_module_header(source, search_start) else {
            continue;
        };
        let Some(end) = matching_brace_end(source.as_bytes(), open) else {
            break;
        };
        ranges.push(cfg_start..end);
        search_start = end;
    }
    ranges
}

// `[pub[(..)]] mod <ident> {` directly after `start`, with only whitespace
// between the tokens. Returns the module name and the byte index of the
// opening brace.
fn inline_module_header(source: &str, start: usize) -> Option<(&str, usize)> {
    let body = after_visibility(source[start..].trim_start()).strip_prefix("mod")?;
    if !body.starts_with(char::is_whitespace) {
        return None;
    }
    let body = body.trim_start();
    let name_len = body.bytes().take_while(|byte| is_ident_byte(*byte)).count();
    if name_len == 0 {
        return None;
    }
    let tail = body[name_len..].trim_start();
    tail.starts_with('{')
        .then_some((&body[..name_len], source.len() - tail.len()))
}

// Skips a leading `pub`, `pub(crate)`, `pub(super)` or `pub(in path)`.
fn after_visibility(body: &str) -> &str {
    let Some(rest) = body.strip_prefix("pub") else {
        return body;
    };
    if rest.starts_with(char::is_whitespace) {
        return rest.trim_start();
    }
    if let Some(rest) = rest.strip_prefix('(')
        && let Some(close) = rest.find(')')
        && !rest[..close].contains('(')
    {
        return rest[close + 1..].trim_start();
    }
    body
}

fn matching_brace_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx + 1);
                }
            }
            _ => {}
        }
    }
    None
}

fn mask_range_preserving_newlines(bytes: &mut [u8], start: usize, end: usize) {
    for byte in &mut bytes[start..end] {
        if *byte != b'\n' {
            *byte = b' ';
        }
    }
}

pub(crate) fn is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

pub(crate) fn is_ident_byte(byte: u8) -> bool {
    is_ident_start(byte) || byte.is_ascii_digit()
}
