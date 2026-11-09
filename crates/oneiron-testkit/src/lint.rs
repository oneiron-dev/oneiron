//! The test lint: no sleeps, no wall clock, no network and no real model in
//! tests (Fable's verdict, sections 3 and 4).
//!
//! It reads Rust test code under `crates/` and `apps/`: every file under a
//! `tests/` directory, every `tests.rs`, `*_tests.rs` and `*_test.rs`, every
//! file gated by an inner `#![cfg(test)]`, and the item after each
//! `#[cfg(test)]`-style attribute in any other file. Vendored
//! trees are skipped. Each [`Rule`] looks for plain text patterns, outside
//! comments; [`Rule::Sleep`] and [`Rule::WallClock`] read code only, the
//! others also read string literals.
//!
//! Tests written before the lint are counted in a baseline
//! (`crates/oneiron-testkit/lint-baseline.txt`). A rule fails when its total
//! across the workspace rises above the baseline's; the report names the
//! files that grew. A count may fall; moving a file moves its findings and
//! changes no total.
//!
//! One line may opt out, with a reason, by carrying (or following a line that
//! carries) `testkit-lint: allow(<rule>) <reason>`, for example a budget test's
//! `Instant::now`. An allow with no reason allows nothing.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};

/// What a test must not do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// Sleeping: `thread::sleep`, `tokio::time::sleep`, `sleep_until`. Wait on
    /// a barrier, a channel or the fake clock instead.
    Sleep,
    /// Reading the wall clock: `SystemTime::now`, `Instant::now`,
    /// `Utc::now`, `Local::now`, `OffsetDateTime::now_utc`. Use
    /// [`crate::clock::FakeClock`].
    WallClock,
    /// A URL to a host other than loopback or a reserved test domain
    /// (`example.com`, `.test`, `.example`, `.invalid`, `.localhost`).
    Network,
    /// A fixed loopback port (`127.0.0.1:8080`). Bind port 0.
    FixedPort,
    /// A real model: provider API keys, provider hosts, model files
    /// (`.gguf`, `.safetensors`, `.onnx`), local model servers. Use
    /// [`crate::provider::ScriptedProvider`] and
    /// [`crate::embedder::HashingEmbedder`].
    RealModel,
}

impl Rule {
    /// Every rule, in report order.
    pub const ALL: [Self; 5] = [
        Self::Sleep,
        Self::WallClock,
        Self::Network,
        Self::FixedPort,
        Self::RealModel,
    ];

    /// The rule's name in reports, allows and the baseline.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Sleep => "sleep",
            Self::WallClock => "wall-clock",
            Self::Network => "network",
            Self::FixedPort => "fixed-port",
            Self::RealModel => "real-model",
        }
    }

    /// The rule named `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|rule| rule.name() == name)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One line of test code that breaks a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The file, relative to the workspace root, with `/` separators.
    pub path: String,
    /// The 1-based line.
    pub line: usize,
    pub rule: Rule,
    /// The line, trimmed and cut to 160 bytes.
    pub excerpt: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}: {}: {}", self.path, self.line, self.rule, self.excerpt)
    }
}

const SLEEP_CALLS: [&str; 3] = ["sleep(", "sleep_until(", "sleep_ms("];
const WALL_CLOCK_CALLS: [&str; 5] = [
    "SystemTime::now",
    "Instant::now",
    "Utc::now",
    "Local::now",
    "OffsetDateTime::now_utc",
];
const MODEL_KEYS: [&str; 7] = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "OPENROUTER_API_KEY",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
];
const MODEL_HOSTS: [&str; 8] = [
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "openrouter.ai",
    "huggingface.co",
    "api.together.xyz",
    "api.groq.com",
    "api.mistral.ai",
];
const MODEL_FILES: [&str; 3] = [".gguf", ".safetensors", ".onnx"];
const MODEL_SERVERS: [&str; 3] = ["ollama", "llama-server", ":11434"];
const LOOPBACK_HOSTS: [&str; 5] = ["127.0.0.1", "localhost", "[::1]", "::1", "0.0.0.0"];
/// The hosts a fixed port is looked for after (`<host>:<port>`).
const PORT_HOSTS: [&str; 4] = ["127.0.0.1", "localhost", "[::1]", "0.0.0.0"];
const RESERVED_SUFFIXES: [&str; 7] = [
    "example.com",
    "example.org",
    "example.net",
    ".test",
    ".example",
    ".invalid",
    ".localhost",
];
const ALLOW_MARK: &str = "testkit-lint: allow(";
/// Directories the walk never enters.
const SKIPPED_DIRS: [&str; 5] = ["target", "vendor", "node_modules", ".git", "fixtures-out"];
/// Workspace-excluded vendored trees under `crates/`.
const SKIPPED_CRATES: [&str; 3] = ["crates/heed", "crates/paste", "crates/loro"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Code,
    Str,
    Comment,
}

fn is_ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The lexical class of every byte: code, string literal (quotes included)
/// or comment. Good enough for test code; not a Rust parser.
fn classify(source: &str) -> Vec<Class> {
    let bytes = source.as_bytes();
    let mut classes = vec![Class::Code; bytes.len()];
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let (class, end) = match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                let end = bytes[i..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map_or(bytes.len(), |n| i + n);
                (Class::Comment, end)
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => (Class::Comment, block_comment_end(bytes, i)),
            b'"' => (Class::Str, string_end(bytes, i)),
            b'r' if (i == 0 || !is_ident(bytes[i - 1]) || (bytes[i - 1] == b'b' && (i < 2 || !is_ident(bytes[i - 2]))))
                && raw_string_start(bytes, i).is_some() =>
            {
                let hashes = raw_string_start(bytes, i).unwrap_or(0);
                (Class::Str, raw_string_end(bytes, i + 1 + hashes, hashes))
            }
            b'\'' => match char_literal_end(bytes, i) {
                Some(end) => (Class::Str, end),
                None => (Class::Code, i + 1),
            },
            _ => (Class::Code, i + 1),
        };
        let end = end.max(start + 1).min(bytes.len());
        for class_of in &mut classes[start..end] {
            *class_of = class;
        }
        i = end;
    }
    classes
}

fn block_comment_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 0_usize;
    let mut i = start;
    while i + 1 < bytes.len() {
        if bytes[i] == b'/' && bytes[i + 1] == b'*' {
            depth += 1;
            i += 2;
        } else if bytes[i] == b'*' && bytes[i + 1] == b'/' {
            depth -= 1;
            i += 2;
            if depth == 0 {
                return i;
            }
        } else {
            i += 1;
        }
    }
    bytes.len()
}

fn string_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

/// The number of `#` of a raw string opening at `r`, if one opens there.
fn raw_string_start(bytes: &[u8], r: usize) -> Option<usize> {
    let mut i = r + 1;
    while bytes.get(i) == Some(&b'#') {
        i += 1;
    }
    (bytes.get(i) == Some(&b'"')).then_some(i - r - 1)
}

fn raw_string_end(bytes: &[u8], quote: usize, hashes: usize) -> usize {
    let mut i = quote + 1;
    while i < bytes.len() {
        if bytes[i] == b'"' && bytes[i + 1..].iter().take(hashes).filter(|&&b| b == b'#').count() == hashes {
            return i + 1 + hashes;
        }
        i += 1;
    }
    bytes.len()
}

/// The end of a char literal opening at `start`; `None` for a lifetime.
fn char_literal_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start + 1) == Some(&b'\\') {
        // The escaped character itself may be a quote (`'\''`), so the
        // closing quote is searched for after it.
        let close = bytes.get(start + 3..)?.iter().position(|&b| b == b'\'')?;
        return Some(start + 3 + close + 1);
    }
    // One character, which may take up to four UTF-8 bytes.
    let first = *bytes.get(start + 1)?;
    let width = match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    };
    (bytes.get(start + 1 + width) == Some(&b'\'')).then_some(start + 2 + width)
}

/// Whether the file at workspace-relative `path` is test code as a whole.
#[must_use]
pub fn whole_file_is_test(path: &str) -> bool {
    let name = path.rsplit('/').next().unwrap_or(path);
    path.split('/').any(|part| part == "tests")
        || name == "tests.rs"
        || name.ends_with("_tests.rs")
        || name.ends_with("_test.rs")
}

/// Whether an attribute's text (`#[cfg(...)]` or `#![cfg(...)]`) gates on
/// `test`.
fn gates_on_test(attribute: &str) -> bool {
    let Some(inner) = attribute
        .strip_prefix("#[cfg(")
        .or_else(|| attribute.strip_prefix("#![cfg("))
    else {
        return false;
    };
    let bytes = inner.as_bytes();
    // `test` as a bare cfg name: not part of an identifier, and not inside a
    // string such as `feature = "test-hooks"`, and not under `not(...)`.
    let joins = |byte: u8| is_ident(byte) || byte == b'"' || byte == b'-';
    inner.match_indices("test").any(|(at, _)| {
        let before = at.checked_sub(1).map(|b| bytes[b]);
        let after = bytes.get(at + 4).copied();
        !before.is_some_and(joins)
            && !after.is_some_and(joins)
            && !inner[..at].trim_end().ends_with("not(")
    })
}

/// Whether the file carries an inner `#![cfg(test)]`-style attribute (in
/// code, not in a string or comment): then all of it is test code.
fn gated_as_test_file(source: &str, classes: &[Class]) -> bool {
    source.match_indices("#![cfg(").any(|(at, _)| {
        classes[at] == Class::Code
            && source[at..]
                .find(']')
                .is_some_and(|close| gates_on_test(&source[at..=at + close]))
    })
}

/// The byte ranges of test code in a file that is not test code as a
/// whole: the item after each `#[cfg(test)]`-style attribute, through its
/// closing brace, or through its `;` for an item with no body.
fn test_items(source: &str, classes: &[Class]) -> Vec<Range<usize>> {
    let bytes = source.as_bytes();
    let mut ranges: Vec<Range<usize>> = Vec::new();
    let mut search = 0;
    while let Some(found) = source[search..].find("#[cfg(") {
        let at = search + found;
        search = at + 6;
        if classes[at] != Class::Code || ranges.last().is_some_and(|last| last.contains(&at)) {
            continue;
        }
        let Some(close) = source[at..].find(']') else { break };
        if !gates_on_test(&source[at..=at + close]) {
            continue;
        }
        let mut i = at + close + 1;
        let mut depth = 0_usize;
        let mut open = None;
        while i < bytes.len() {
            if classes[i] == Class::Code {
                match bytes[i] {
                    b'{' => {
                        if depth == 0 && open.is_none() {
                            open = Some(i);
                        }
                        depth += 1;
                    }
                    b'}' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 && open.is_some() {
                            break;
                        }
                    }
                    b';' if depth == 0 && open.is_none() => {
                        open = Some(i);
                        break;
                    }
                    _ => {}
                }
            }
            i += 1;
        }
        if open.is_some() {
            ranges.push(at..(i + 1).min(bytes.len()));
            search = (i + 1).min(bytes.len());
        }
    }
    ranges
}

fn line_starts(source: &str) -> Vec<usize> {
    std::iter::once(0)
        .chain(source.match_indices('\n').map(|(at, _)| at + 1))
        .collect()
}

fn excerpt(line: &str) -> String {
    let line = line.trim();
    if line.len() <= 160 {
        return line.to_owned();
    }
    let mut end = 160;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &line[..end])
}

/// The rules an allow on `line` names, when it gives a reason.
fn allows(line: &str) -> Vec<Rule> {
    let Some(at) = line.find(ALLOW_MARK) else {
        return Vec::new();
    };
    let rest = &line[at + ALLOW_MARK.len()..];
    let Some((names, reason)) = rest.split_once(')') else {
        return Vec::new();
    };
    if reason.trim().is_empty() {
        return Vec::new();
    }
    names
        .split(',')
        .filter_map(|name| Rule::parse(name.trim()))
        .collect()
}

/// The rules one line breaks, given its code-only and code-and-string text.
fn line_rules(code: &str, code_and_strings: &str) -> Vec<Rule> {
    let mut rules = Vec::new();
    let code_bytes = code.as_bytes();
    let sleeps = SLEEP_CALLS.iter().any(|call| {
        code.match_indices(call).any(|(at, _)| {
            let before = at.checked_sub(1).map(|b| code_bytes[b]);
            !before.is_some_and(|b| is_ident(b) || b == b'.') && !code[..at].trim_end().ends_with("fn")
        })
    });
    if sleeps {
        rules.push(Rule::Sleep);
    }
    if WALL_CLOCK_CALLS.iter().any(|call| code.contains(call)) {
        rules.push(Rule::WallClock);
    }
    let text = code_and_strings;
    let mut network = false;
    let mut fixed_port = false;
    let mut real_model = MODEL_KEYS.iter().any(|key| text.contains(key))
        || MODEL_FILES.iter().any(|ext| text.contains(ext))
        || MODEL_SERVERS.iter().any(|server| text.contains(server));
    for scheme in ["http://", "https://", "ws://", "wss://"] {
        for (at, _) in text.match_indices(scheme) {
            let authority: String = text[at + scheme.len()..]
                .chars()
                .take_while(|c| !matches!(c, '/' | '"' | '\'' | '?' | '#' | ' ' | '\\' | ')' | '`'))
                .collect();
            let host = host_of(&authority);
            if host.is_empty() || host.contains('{') || host.contains('$') {
                continue;
            }
            if MODEL_HOSTS.iter().any(|model| host == *model || host.ends_with(&format!(".{model}"))) {
                real_model = true;
            } else if !is_local_or_reserved(host) {
                network = true;
            }
        }
    }
    for host in PORT_HOSTS {
        for (at, _) in text.match_indices(&format!("{host}:")) {
            let before = at.checked_sub(1).map(|b| text.as_bytes()[b]);
            if before.is_some_and(|b| b.is_ascii_alphanumeric() || b == b'.') {
                continue;
            }
            let port: String = text[at + host.len() + 1..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if port.parse::<u32>().is_ok_and(|port| port != 0) {
                fixed_port = true;
            }
        }
    }
    if network {
        rules.push(Rule::Network);
    }
    if fixed_port {
        rules.push(Rule::FixedPort);
    }
    if real_model {
        rules.push(Rule::RealModel);
    }
    rules
}

fn host_of(authority: &str) -> &str {
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split(']').next().map_or(authority, |host| {
            if host == "::1" { "[::1]" } else { host }
        });
    }
    authority.split(':').next().unwrap_or(authority)
}

fn is_local_or_reserved(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if LOOPBACK_HOSTS.contains(&host.as_str()) || host.starts_with("127.") {
        return true;
    }
    RESERVED_SUFFIXES
        .iter()
        .any(|suffix| match suffix.strip_prefix('.') {
            // A reserved top-level name: `test` itself or any `*.test`.
            Some(top) => host == top || host.ends_with(suffix),
            // A reserved domain: `example.com` itself or any subdomain.
            None => host == *suffix || host.ends_with(&format!(".{suffix}")),
        })
}

/// The findings in one file's source. `path` is workspace-relative; it
/// decides whether the whole file is test code.
#[must_use]
pub fn scan_source(path: &str, source: &str) -> Vec<Finding> {
    let whole = whole_file_is_test(path);
    if !whole
        && !((source.contains("#[cfg(") || source.contains("#![cfg(")) && source.contains("test"))
    {
        return Vec::new();
    }
    let classes = classify(source);
    let ranges = if whole || gated_as_test_file(source, &classes) {
        vec![0..source.len()]
    } else {
        test_items(source, &classes)
    };
    if ranges.is_empty() {
        return Vec::new();
    }
    let starts = line_starts(source);
    let mut findings = Vec::new();
    let mut previous_allows: Vec<Rule> = Vec::new();
    for (index, &start) in starts.iter().enumerate() {
        let end = starts.get(index + 1).map_or(source.len(), |next| next - 1);
        let line = &source[start..end.max(start)];
        let here_allows = allows(line);
        let in_test = ranges.iter().any(|range| range.start < end.max(start + 1) && start < range.end);
        if in_test {
            let mut code = String::with_capacity(line.len());
            let mut code_and_strings = String::with_capacity(line.len());
            for (offset, ch) in line.char_indices() {
                let class = classes[start + offset];
                code.push(if class == Class::Code { ch } else { ' ' });
                code_and_strings.push(if class == Class::Comment { ' ' } else { ch });
            }
            for rule in line_rules(&code, &code_and_strings) {
                if here_allows.contains(&rule) || previous_allows.contains(&rule) {
                    continue;
                }
                findings.push(Finding {
                    path: path.to_owned(),
                    line: index + 1,
                    rule,
                    excerpt: excerpt(line),
                });
            }
        }
        // An allow on a line of its own covers the next line.
        previous_allows = if line.trim_start().starts_with("//") { here_allows } else { Vec::new() };
    }
    findings
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            let relative = relative_path(root, &path);
            if SKIPPED_DIRS.contains(&name.as_ref()) || SKIPPED_CRATES.contains(&relative.as_str()) {
                continue;
            }
            walk(root, &path, out)?;
        } else if kind.is_file() && name.ends_with(".rs") {
            out.push(path);
        }
    }
    Ok(())
}

fn relative_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|part| part.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
}

/// The workspace root this crate sits in (two levels above its manifest).
#[must_use]
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Every finding under `root`'s `crates/` and `apps/`, in path order.
///
/// # Errors
/// A directory or file under them cannot be read.
pub fn scan_workspace(root: &Path) -> io::Result<Vec<Finding>> {
    let mut files = Vec::new();
    for top in ["crates", "apps"] {
        let dir = root.join(top);
        if dir.is_dir() {
            walk(root, &dir, &mut files)?;
        }
    }
    let mut findings = Vec::new();
    for file in files {
        let source = match fs::read_to_string(&file) {
            Ok(source) => source,
            Err(error) if error.kind() == io::ErrorKind::InvalidData => continue,
            Err(error) => return Err(error),
        };
        findings.extend(scan_source(&relative_path(root, &file), &source));
    }
    Ok(findings)
}

/// Finding counts per rule and per file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Baseline {
    totals: BTreeMap<Rule, usize>,
    files: BTreeMap<(Rule, String), usize>,
}

impl Baseline {
    /// The counts of `findings`.
    #[must_use]
    pub fn of(findings: &[Finding]) -> Self {
        let mut baseline = Self::default();
        for finding in findings {
            *baseline.totals.entry(finding.rule).or_default() += 1;
            *baseline
                .files
                .entry((finding.rule, finding.path.clone()))
                .or_default() += 1;
        }
        baseline
    }

    /// Parses the baseline file: `<rule> <total>` and
    /// `<rule> <path> <count>` lines; `#` starts a comment.
    ///
    /// # Errors
    /// A line names no known rule or carries no count.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut baseline = Self::default();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            let bad = || format!("lint baseline line {}: {line:?}", index + 1);
            let rule = Rule::parse(fields[0]).ok_or_else(bad)?;
            match fields.as_slice() {
                [_, total] => {
                    baseline.totals.insert(rule, total.parse().map_err(|_| bad())?);
                }
                [_, path, count] => {
                    baseline
                        .files
                        .insert((rule, (*path).to_owned()), count.parse().map_err(|_| bad())?);
                }
                _ => return Err(bad()),
            }
        }
        Ok(baseline)
    }

    /// The baseline file's text.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = String::from(
            "# oneiron-testkit test lint baseline: findings in tests written before the lint.\n\
             # A rule fails when its total rises above the line `<rule> <total>`. Counts may fall.\n\
             # Regenerate (fleet only): ONEIRON_TESTKIT_LINT=write cargo test -p oneiron-testkit --test test_lint\n",
        );
        for rule in Rule::ALL {
            out.push_str(&format!("{rule} {}\n", self.totals.get(&rule).copied().unwrap_or(0)));
        }
        for ((rule, path), count) in &self.files {
            out.push_str(&format!("{rule} {path} {count}\n"));
        }
        out
    }

    /// The rule's total.
    #[must_use]
    pub fn total(&self, rule: Rule) -> usize {
        self.totals.get(&rule).copied().unwrap_or(0)
    }

    /// The rule's count in `path`.
    #[must_use]
    pub fn count(&self, rule: Rule, path: &str) -> usize {
        self.files
            .get(&(rule, path.to_owned()))
            .copied()
            .unwrap_or(0)
    }
}

/// What a scan says against a baseline.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LintReport {
    /// Rules whose total rose: the rule, the baseline total, the new total,
    /// and the findings in files that grew.
    pub failures: Vec<(Rule, usize, usize, Vec<Finding>)>,
    /// Rules whose total fell: the baseline can be lowered.
    pub fallen: Vec<(Rule, usize, usize)>,
}

impl LintReport {
    /// Compares `findings` with `baseline`.
    #[must_use]
    pub fn compare(findings: &[Finding], baseline: &Baseline) -> Self {
        let now = Baseline::of(findings);
        let mut report = Self::default();
        for rule in Rule::ALL {
            let (was, is) = (baseline.total(rule), now.total(rule));
            if is > was {
                let grown: Vec<Finding> = findings
                    .iter()
                    .filter(|finding| {
                        finding.rule == rule
                            && now.count(rule, &finding.path) > baseline.count(rule, &finding.path)
                    })
                    .cloned()
                    .collect();
                report.failures.push((rule, was, is, grown));
            } else if is < was {
                report.fallen.push((rule, was, is));
            }
        }
        report
    }

    /// Whether no rule's total rose.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.failures.is_empty()
    }
}

impl fmt::Display for LintReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (rule, was, is, grown) in &self.failures {
            writeln!(f, "test lint: {rule}: {is} findings, the baseline allows {was}. In files that grew:")?;
            for finding in grown {
                writeln!(f, "  {finding}")?;
            }
        }
        for (rule, was, is) in &self.fallen {
            writeln!(f, "test lint: {rule}: {is} findings, below the baseline's {was}; lower it")?;
        }
        Ok(())
    }
}
