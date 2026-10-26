//! The dotenv reading (FIX 7608 slice 6, owner ruling SECRETS-IN-REPOS =
//! A: ".env: values -> secret store, names -> .oneiron/secret-manifest.toml").
//! Every `KEY=value` assignment of a dotenv file, by name and by where its
//! value sits. Receive marks each value [`dotenv_value_lifts`] takes (CALL
//! DOTENV-IMPORT), token-shaped or not; a remediation names each one in the
//! manifest and leaves its name, blank, in an example file.
//!
//! The reading is the common dotenv form: blank lines and `#` comments pass;
//! an optional `export ` prefix; a name ([`is_secret_env_name`]); `=`; then
//! a value that is single-quoted (as written), double- or backtick-quoted
//! (it may span lines, and a backslash keeps the next byte), or bare up to
//! a ` #` comment, trimmed. A line that is no assignment is passed over,
//! never an error. A value's span is its bytes inside any quotes.

use std::ops::Range;

use crate::secret_manifest::is_secret_env_name;

/// The reason a dotenv value's mark carries.
pub(crate) const REPO_ENV_VALUE_REASON: &str = "gate.secret_scan.dotenv_value";

/// The name parts that make a dotenv file an example of its names
/// (`.env.example`, `example.env`), which documents names and loads none.
const EXAMPLE_NAME_PARTS: [&str; 5] = ["example", "sample", "template", "dist", "defaults"];

/// What a dotenv file is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RepoEnvFileKind {
    /// A file a program loads values from: `.env`, `.env.local`,
    /// `prod.env`.
    Live,
    /// A file that documents names: `.env.example`, `.env.sample`.
    Example,
}

/// One assignment: its name and its value's byte span in the file. No
/// value byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepoEnvEntry {
    pub(crate) name: String,
    pub(crate) value: Range<usize>,
}

/// CALL DOTENV-IMPORT: whether receive lifts a dotenv value into custody.
/// Every non-empty value does, token-shaped or not; an empty one never
/// mints, so an example file's blank names stay unmarked. One hook, so a
/// ruling changes one line.
pub(crate) fn dotenv_value_lifts(value: &[u8]) -> bool {
    !value.is_empty()
}

/// What the dotenv file at the repo-relative `path` is for, or `None` when
/// its name is no dotenv file's: `.env`, `.env.<anything>` or
/// `<anything>.env`.
pub(crate) fn repo_env_file(path: &str) -> Option<RepoEnvFileKind> {
    let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
    let dotenv = name == ".env"
        || name.starts_with(".env.")
        || (name.len() > ".env".len() && name.ends_with(".env"));
    if !dotenv {
        return None;
    }
    if name
        .split('.')
        .any(|part| EXAMPLE_NAME_PARTS.contains(&part))
    {
        Some(RepoEnvFileKind::Example)
    } else {
        Some(RepoEnvFileKind::Live)
    }
}

/// Every assignment `bytes` holds, in file order.
pub(crate) fn repo_env_entries(bytes: &[u8]) -> Vec<RepoEnvEntry> {
    let mut entries = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let end = line_end(bytes, at);
        match assignment(bytes, at, end) {
            Some((entry, resume)) => {
                entries.push(entry);
                at = resume;
            }
            None => at = end + 1,
        }
    }
    entries
}

/// The assignment on the line `start..end`, and where reading resumes
/// after its value.
fn assignment(bytes: &[u8], start: usize, end: usize) -> Option<(RepoEnvEntry, usize)> {
    let mut at = blank_end(bytes, start, end);
    if let Some(rest) = bytes.get(at..end)
        && rest.starts_with(b"export")
        && rest.get(6).is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        at = blank_end(bytes, at + 6, end);
    }
    let name_start = at;
    while at < end && bytes.get(at).is_some_and(|byte| name_byte(*byte)) {
        at += 1;
    }
    let name = std::str::from_utf8(bytes.get(name_start..at)?).ok()?;
    if !is_secret_env_name(name) {
        return None;
    }
    at = blank_end(bytes, at, end);
    if bytes.get(at) != Some(&b'=') || at >= end {
        return None;
    }
    at = blank_end(bytes, at + 1, end);
    let (value, resume) = match bytes.get(at) {
        Some(&quote @ (b'"' | b'\'' | b'`')) if at < end => {
            match closing_quote(bytes, at + 1, quote) {
                Some(close) => (at + 1..close, line_end(bytes, close) + 1),
                // An unclosed quote holds the rest of its line.
                None => (at + 1..trimmed_end(bytes, at + 1, end), end + 1),
            }
        }
        Some(&b'#') => (at..at, end + 1),
        _ => {
            let stop = (at..end)
                .find(|&i| {
                    bytes.get(i) == Some(&b'#')
                        && i > at
                        && bytes.get(i - 1).is_some_and(|byte| matches!(byte, b' ' | b'\t'))
                })
                .unwrap_or(end);
            (at..trimmed_end(bytes, at, stop), end + 1)
        }
    };
    Some((
        RepoEnvEntry {
            name: name.to_owned(),
            value,
        },
        resume,
    ))
}

fn name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
}

/// The offset of the newline ending the line at `start`, or the end.
fn line_end(bytes: &[u8], start: usize) -> usize {
    bytes
        .get(start..)
        .and_then(|rest| rest.iter().position(|byte| *byte == b'\n'))
        .map_or(bytes.len(), |offset| start + offset)
}

/// The first offset from `start` before `end` that is no space or tab.
fn blank_end(bytes: &[u8], start: usize, end: usize) -> usize {
    (start..end)
        .find(|&i| !bytes.get(i).is_some_and(|byte| matches!(byte, b' ' | b'\t')))
        .unwrap_or(end)
}

/// `end` with trailing spaces, tabs and a carriage return taken off, never
/// before `start`.
fn trimmed_end(bytes: &[u8], start: usize, mut end: usize) -> usize {
    while end > start
        && bytes
            .get(end - 1)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r'))
    {
        end -= 1;
    }
    end
}

/// The offset of the quote closing a value opened by `quote` just before
/// `start`. A single-quoted value ends at its line; the others may span
/// lines, and a backslash in them keeps the byte after it.
fn closing_quote(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut at = start;
    while let Some(&byte) = bytes.get(at) {
        if byte == quote {
            return Some(at);
        }
        if quote == b'\'' && byte == b'\n' {
            return None;
        }
        at += if byte == b'\\' && quote != b'\'' { 2 } else { 1 };
    }
    None
}
