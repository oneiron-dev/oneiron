//! A per-API verb-class table (ARCH-0069 #door-reads-action): pack data that
//! maps a call to read, write, destructive, send or pay, and is never engine
//! policy. A pack carries one as `knowledge/verb-classes.json`; the door's
//! class registry reads the installed ones ([`super::verb_class`]).
//!
//! ```json
//! {
//!   "hosts": ["api.github.com"],
//!   "rows": [
//!     {"protocol": "rest", "verb": "DELETE", "pattern": "/repos/{owner}/{repo}", "class": "destructive"},
//!     {"protocol": "graphql", "verb": "mutation", "pattern": "deleteRepository", "class": "destructive"},
//!     {"protocol": "graphql", "verb": "query", "class": "read"},
//!     {"protocol": "mcp", "verb": "tools/call", "pattern": "delete_file", "class": "destructive"},
//!     {"protocol": "json_rpc", "verb": "eth_sendTransaction", "class": "pay"}
//!   ]
//! }
//! ```
//!
//! A row's `verb` is the action's verb ([`ApiAction::verb`]), or `*` for any.
//! Its `pattern` matches the action's target, and an absent pattern is `*`.
//! A REST pattern is a path template, the grammar the slate's HTTP operation
//! paths use: literal segments, `{name}` for exactly one segment, and a final
//! `{name*}` for one or more. Literal segments match case-blind and
//! percent-decoded, and empty segments are dropped, so a doubled or trailing
//! `/` reads as the same path. Any other protocol's pattern is a GraphQL root
//! field or an MCP tool name, or `*`. A JSON-RPC action has no target, so a
//! JSON-RPC row names its method as its verb.
//!
//! When several rows match one action, the most specific wins: more literal
//! segments, then fewer tail captures, then a named verb over `*`. Rows tied
//! on that order all apply, and the action carries each of their classes, so
//! a tie never picks the laxer class. Two rows with the same selector refuse
//! the table, naming both.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::api_action::{ApiAction, ApiProtocol, host_key};
use crate::error::{Error, Result};
use crate::secret_record::ApiVerbClass;

/// `*`: any verb, or any target.
const ANY: &str = "*";

/// One row of a table, as its file spells it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiVerbClassRow {
    pub protocol: ApiProtocol,
    pub verb: String,
    #[serde(default = "any_pattern")]
    pub pattern: String,
    pub class: ApiVerbClass,
}

fn any_pattern() -> String {
    ANY.to_owned()
}

impl ApiVerbClassRow {
    fn describe(&self, index: usize) -> String {
        format!(
            "row {} ({} {} {} -> {})",
            index + 1,
            self.protocol.as_str(),
            self.verb,
            self.pattern,
            self.class.as_str()
        )
    }
}

/// The table file's shape.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TableFile {
    hosts: Vec<String>,
    rows: Vec<ApiVerbClassRow>,
}

/// A table that passed its load check: its hosts, its rows as written, and
/// each row's selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiVerbClassTable {
    hosts: BTreeSet<String>,
    rows: Vec<ApiVerbClassRow>,
    selectors: Vec<Selector>,
}

/// What one row selects: a protocol, a verb (`None` for any) and a target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Selector {
    protocol: ApiProtocol,
    verb: Option<String>,
    target: Target,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Any,
    Name(String),
    Path { segments: Vec<Segment>, tail: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Segment {
    /// Lower-cased and percent-decoded.
    Literal(String),
    /// `{name}`: exactly one segment.
    One,
}

impl ApiVerbClassTable {
    /// Reads and checks a table file. A file that does not read, a host or a
    /// row that does not check, and two rows with the same selector refuse
    /// the table.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let file: TableFile = serde_json::from_slice(bytes)
            .map_err(|error| refused(&format!("does not read: {error}")))?;
        if file.hosts.is_empty() {
            return Err(refused("names no host"));
        }
        let mut hosts = BTreeSet::new();
        for written in &file.hosts {
            let host = table_host(written).ok_or_else(|| {
                refused(&format!(
                    "host {written:?} is not a host or host:port, or names port 443 or 80 \
                     (a call to its scheme's default port carries no port: write the host alone)"
                ))
            })?;
            hosts.insert(host);
        }
        if file.rows.is_empty() {
            return Err(refused("has no row"));
        }
        let mut selectors = Vec::with_capacity(file.rows.len());
        let mut seen: BTreeMap<Selector, usize> = BTreeMap::new();
        for (index, row) in file.rows.iter().enumerate() {
            let selector = Selector::of(row)
                .map_err(|reason| refused(&format!("{}: {reason}", row.describe(index))))?;
            if let Some(first) = seen.insert(selector.clone(), index) {
                return Err(refused(&format!(
                    "{} and {} select the same calls",
                    file.rows[first].describe(first),
                    row.describe(index)
                )));
            }
            selectors.push(selector);
        }
        Ok(Self {
            hosts,
            rows: file.rows,
            selectors,
        })
    }

    /// The hosts the table classes calls to, as [`ApiAction::host`] names
    /// them.
    pub fn hosts(&self) -> impl Iterator<Item = &str> {
        self.hosts.iter().map(String::as_str)
    }

    /// The rows as the file wrote them.
    #[must_use]
    pub fn rows(&self) -> &[ApiVerbClassRow] {
        &self.rows
    }

    /// The classes this table gives `action`: the class of its most specific
    /// matching row, or of every row tied at that rank. Empty when the
    /// action's host is not the table's or no row matches: unknown.
    #[must_use]
    pub fn class_of(&self, action: &ApiAction) -> BTreeSet<ApiVerbClass> {
        let mut classes = BTreeSet::new();
        if !self.hosts.contains(&action.host.to_ascii_lowercase()) {
            return classes;
        }
        let path = (action.protocol == ApiProtocol::Rest).then(|| path_segments(&action.target));
        let mut best = None;
        for (row, selector) in self.rows.iter().zip(&self.selectors) {
            if !selector.matches(action, path.as_deref()) {
                continue;
            }
            let rank = selector.rank();
            match best.map(|best| rank.cmp(&best)) {
                Some(std::cmp::Ordering::Less) => {}
                Some(std::cmp::Ordering::Equal) => {
                    classes.insert(row.class);
                }
                None | Some(std::cmp::Ordering::Greater) => {
                    best = Some(rank);
                    classes = BTreeSet::from([row.class]);
                }
            }
        }
        classes
    }
}

impl Selector {
    fn of(row: &ApiVerbClassRow) -> std::result::Result<Self, String> {
        let verb = row.verb.trim();
        let verb = match (row.protocol, verb) {
            (_, ANY) => None,
            (ApiProtocol::Rest, method)
                if !method.is_empty() && method.bytes().all(|b| b.is_ascii_alphabetic()) =>
            {
                Some(method.to_ascii_uppercase())
            }
            (ApiProtocol::GraphQl, kind @ ("query" | "mutation" | "subscription")) => {
                Some(kind.to_owned())
            }
            (ApiProtocol::Mcp, "tools/call") => Some(verb.to_owned()),
            (ApiProtocol::JsonRpc, method)
                if !method.is_empty() && !method.bytes().any(|b| b.is_ascii_whitespace()) =>
            {
                Some(method.to_owned())
            }
            _ => {
                return Err(match row.protocol {
                    ApiProtocol::Rest => "a REST verb is a method or *",
                    ApiProtocol::GraphQl => "a GraphQL verb is query, mutation, subscription or *",
                    ApiProtocol::Mcp => "an MCP verb is tools/call or *",
                    ApiProtocol::JsonRpc => "a JSON-RPC verb is a method name or *",
                }
                .to_owned());
            }
        };
        let pattern = row.pattern.trim();
        let target = match row.protocol {
            _ if pattern == ANY => Target::Any,
            ApiProtocol::Rest => path_pattern(pattern)?,
            ApiProtocol::JsonRpc => {
                return Err(
                    "a JSON-RPC row names its method as its verb, with no pattern".to_owned(),
                );
            }
            ApiProtocol::GraphQl | ApiProtocol::Mcp => {
                if pattern.is_empty() || pattern.bytes().any(|b| b.is_ascii_whitespace()) {
                    return Err("a pattern is a name or *".to_owned());
                }
                Target::Name(pattern.to_owned())
            }
        };
        Ok(Self {
            protocol: row.protocol,
            verb,
            target,
        })
    }

    /// Whether this selector selects `action`; `path` is a REST action's
    /// path segments.
    fn matches(&self, action: &ApiAction, path: Option<&[String]>) -> bool {
        if self.protocol != action.protocol {
            return false;
        }
        let verb_matches = match &self.verb {
            None => true,
            Some(verb) if self.protocol == ApiProtocol::Rest => {
                verb.eq_ignore_ascii_case(&action.verb)
            }
            Some(verb) => *verb == action.verb,
        };
        verb_matches
            && match &self.target {
                Target::Any => true,
                Target::Name(name) => *name == action.target,
                Target::Path { segments, tail } => path.is_some_and(|path| {
                    let fits = if *tail {
                        path.len() > segments.len()
                    } else {
                        path.len() == segments.len()
                    };
                    fits && segments
                        .iter()
                        .zip(path)
                        .all(|(segment, part)| match segment {
                            Segment::Literal(literal) => literal == part,
                            Segment::One => true,
                        })
                }),
            }
    }

    /// The selector's specificity: literal segments, then no tail capture
    /// over one and one over any target, then a named verb over `*`.
    fn rank(&self) -> (usize, u8, bool) {
        let (literals, shape) = match &self.target {
            Target::Any => (0, 0),
            Target::Name(_) => (1, 2),
            Target::Path { segments, tail } => (
                segments
                    .iter()
                    .filter(|segment| matches!(segment, Segment::Literal(_)))
                    .count(),
                if *tail { 1 } else { 2 },
            ),
        };
        (literals, shape, self.verb.is_some())
    }
}

/// A REST pattern's segments: `/` then literal, `{name}` and a final
/// `{name*}` segments.
fn path_pattern(pattern: &str) -> std::result::Result<Target, String> {
    let Some(rest) = pattern.strip_prefix('/') else {
        return Err("a REST pattern is a path that starts with / or *".to_owned());
    };
    let parts: Vec<&str> = rest.split('/').filter(|part| !part.is_empty()).collect();
    let mut segments = Vec::with_capacity(parts.len());
    let mut tail = false;
    for (index, part) in parts.iter().enumerate() {
        if let Some(name) = part
            .strip_prefix('{')
            .and_then(|part| part.strip_suffix('}'))
        {
            let (name, captures_tail) = match name.strip_suffix('*') {
                Some(name) => (name, true),
                None => (name, false),
            };
            if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return Err(format!("capture {part:?} is not {{name}} or {{name*}}"));
            }
            if captures_tail {
                if index + 1 != parts.len() {
                    return Err(format!("capture {part:?} must end the pattern"));
                }
                tail = true;
            } else {
                segments.push(Segment::One);
            }
        } else if part.contains(['{', '}', '*']) {
            return Err(format!(
                "segment {part:?} is neither a literal nor a capture"
            ));
        } else {
            segments.push(Segment::Literal(decode_segment(part)));
        }
    }
    Ok(Target::Path { segments, tail })
}

/// A request path's segments as a pattern's literals compare them: empty
/// segments dropped, each percent-decoded and lower-cased.
fn path_segments(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|part| !part.is_empty())
        .map(decode_segment)
        .collect()
}

/// One path segment percent-decoded, then lower-cased. A `%` that does not
/// start an escape stays as it is.
fn decode_segment(segment: &str) -> String {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        let escaped = if byte == b'%' {
            bytes
                .get(at + 1..at + 3)
                .filter(|hex| hex.iter().all(u8::is_ascii_hexdigit))
                .and_then(|hex| std::str::from_utf8(hex).ok())
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        } else {
            None
        };
        match escaped {
            Some(value) => {
                decoded.push(value);
                at += 3;
            }
            None => {
                decoded.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&decoded).to_lowercase()
}

/// A table's host as [`ApiAction::host`] names a call's ([`host_key`]).
/// `None` when it is not a host or `host:port`, or when it names port 443 or
/// 80: a call to its scheme's default port carries no port, so that host
/// would never match.
fn table_host(written: &str) -> Option<String> {
    if written
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return None;
    }
    // An IPv6 host holds `:` too: the text after the last `:` is a port
    // unless it closes a `[..]` or that `:` is part of a `::`.
    let (name, port) = match written.rsplit_once(':') {
        Some((name, port)) if !name.ends_with(':') && !port.ends_with(']') => {
            (name, Some(port.parse::<u16>().ok()?))
        }
        _ => (written, None),
    };
    if name.is_empty() || name == "." || matches!(port, Some(443 | 80)) {
        return None;
    }
    Some(host_key(name, port))
}

fn refused(reason: &str) -> Error {
    Error::InvalidConfig(format!("pack source: verb-class table {reason}"))
}
