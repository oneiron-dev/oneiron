//! The Rust-text scanner (strings, char literals, comments, brackets), the
//! attribute readers and the type parser.
//!
//! Every offset is a byte offset on a char boundary. Where the Python steps one character (`i + 1`, `x - 1`,
//! `text[i + 2]`), the port steps one code point, so a non-ASCII character counts as one, as it does in Python:
//! the engine sources hold non-ASCII char literals (`'…'`), which the char-literal heuristic reads by position.
//! Patterns are Python's, compiled through `py::re::compile`, which spells `\w` and `\s` as Python's classes; a `\b`
//! (Unicode's in `regex`, not Python's) is checked by hand where a pattern needs one.

use std::sync::LazyLock;

use indexmap::IndexSet;
use regex::Regex;

use super::{RECURSION_LIMIT, recursion_error};
use crate::error::GenerateError;
use crate::py::re::compile;
use crate::py::text::{is_space, is_word, strip};
use crate::py::value::{Dict, Value};

pub(crate) use type_parser::{Ast, parse_type};

mod type_parser;

// ---------------------------------------------------------------- code-point offsets

/// The UTF-8 length of the char a lead byte starts.
fn char_width(lead: u8) -> usize {
    match lead {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

/// `i + 1` in code points: the offset past the char at `i` (`i < len`, on a boundary).
pub(crate) fn next_char(text: &str, i: usize) -> usize {
    i + char_width(text.as_bytes()[i])
}

/// `i - 1` in code points: the offset of the char that ends at `i` (`0` at `0`).
pub(crate) fn prev_char(text: &str, i: usize) -> usize {
    text[..i].char_indices().next_back().map_or(0, |(at, _)| at)
}

/// The char that ends at `i`, if any.
pub(crate) fn char_before(text: &str, i: usize) -> Option<char> {
    text[..i].chars().next_back()
}

/// Python's `text[a:b]` for offsets on char boundaries: empty when `b <= a`.
pub(crate) fn slice(text: &str, a: usize, b: usize) -> &str {
    let b = b.min(text.len());
    if a >= b { "" } else { &text[a..b] }
}

/// Python's `text.find(sub, start)`.
pub(crate) fn find_from(text: &str, sub: &str, start: usize) -> Option<usize> {
    if start > text.len() {
        return None;
    }
    text[start..].find(sub).map(|at| at + start)
}

/// The offset past the Python whitespace that starts at `i`.
pub(crate) fn skip_space(text: &str, i: usize) -> usize {
    let rest = &text[i..];
    i + (rest.len() - rest.trim_start_matches(is_space).len())
}

/// The offset of the first code point past the first `n` of `text[i..]` (Python's `i + n`, clamped to the end).
pub(crate) fn advance_chars(text: &str, i: usize, n: usize) -> usize {
    text[i..]
        .char_indices()
        .nth(n)
        .map_or(text.len(), |(at, _)| i + at)
}

/// Whether Python's `\b` holds before a match that starts with a word character at `i`.
pub(crate) fn word_start(text: &str, i: usize) -> bool {
    char_before(text, i).is_none_or(|c| !is_word(c))
}

/// Whether Python's `\b` holds after a match that ends with a word character at `i`.
pub(crate) fn word_end(text: &str, i: usize) -> bool {
    text[i..].chars().next().is_none_or(|c| !is_word(c))
}

/// `re.search(pattern, text, start)` for a pattern Python writes as `\b<pattern>` (`lead`) and/or `<pattern>\b`
/// (`trail`), where the pattern begins and ends with word characters: Rust's `\b` is Unicode's, not Python's, so
/// the boundaries are checked here, and a start that fails them is retried one code point on, as the Python
/// engine does.
pub(crate) fn search_bounded<'t>(
    pattern: &Regex,
    text: &'t str,
    start: usize,
    lead: bool,
    trail: bool,
) -> Option<regex::Captures<'t>> {
    let mut from = start;
    while from <= text.len() {
        let found = pattern.captures_at(text, from)?;
        let whole = found.get(0)?;
        if (!lead || word_start(text, whole.start())) && (!trail || word_end(text, whole.end())) {
            return Some(found);
        }
        if whole.start() >= text.len() {
            return None;
        }
        from = next_char(text, whole.start());
    }
    None
}

/// Every non-overlapping match of a `\b<pattern>` pattern (see [`search_bounded`]), as `re.finditer` gives them.
pub(crate) fn finditer_bounded<'t>(
    pattern: &Regex,
    text: &'t str,
    lead: bool,
    trail: bool,
) -> Vec<regex::Captures<'t>> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(found) = search_bounded(pattern, text, from, lead, trail) {
        let Some(whole) = found.get(0) else { break };
        from = if whole.end() > whole.start() {
            whole.end()
        } else {
            next_char(text, whole.start())
        };
        out.push(found);
        if from > text.len() {
            break;
        }
    }
    out
}

/// The offset past each `(` that `re.finditer(<lead> + name + r'\s*\(', text)` ends on, where `lead` is `\b`
/// when `bounded` (the name is all word characters).
fn call_opens(text: &str, name: &str, bounded: bool) -> Vec<usize> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = find_from(text, name, from) {
        let open = skip_space(text, at + name.len());
        if (!bounded || word_start(text, at)) && text[open..].starts_with('(') {
            out.push(open);
            from = open + 1;
        } else {
            from = next_char(text, at);
        }
    }
    out
}

// ---------------------------------------------------------------- Rust text

/// If a raw string starts at `i`, the offset past its close
/// (the end of the text when it does not close); else `None`.
fn raw_string_end(text: &str, i: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut j = if bytes[i] == b'r' { i + 1 } else { i + 2 };
    let mut hashes = 0;
    while j < bytes.len() && bytes[j] == b'#' {
        hashes += 1;
        j += 1;
    }
    if j >= bytes.len() || bytes[j] != b'"' {
        return None;
    }
    let close = format!("\"{}", "#".repeat(hashes));
    Some(find_from(text, &close, j + 1).map_or(bytes.len(), |at| at + 1 + hashes))
}

/// The string loop of `_skip`, from the offset past the opening quote: past the close,
/// or the end of the text.
fn string_end(text: &str, mut j: usize) -> usize {
    let bytes = text.as_bytes();
    while j < bytes.len() {
        if bytes[j] == b'\\' {
            // `j += 2`: the backslash and the character it escapes.
            if j + 1 >= bytes.len() {
                return bytes.len();
            }
            j = next_char(text, j + 1);
            continue;
        }
        if bytes[j] == b'"' {
            return j + 1;
        }
        j = next_char(text, j);
    }
    bytes.len()
}

/// The char-literal branch of `_skip` for a quote at Python offset `i`, where `after`
/// is the offset of the char past the quote (`i + 1`). Every return is an offset Python counts from `i`: `i + 1`
/// is `after`, `i + 3` the offset past the char at `i + 2`.
fn char_literal_end(text: &str, after: usize) -> usize {
    let bytes = text.as_bytes();
    if text[after..].starts_with('\\') {
        // `text.find("'", i + 3)`: past the quote, the backslash and the escaped character.
        let escaped = after + 1;
        if escaped >= bytes.len() {
            return after;
        }
        return find_from(text, "'", next_char(text, escaped)).map_or(after, |at| at + 1);
    }
    // `i + 2 < len(text) and text[i + 2] == "'"`
    if after < bytes.len() {
        let second = next_char(text, after);
        if second < bytes.len() && bytes[second] == b'\'' {
            return second + 1;
        }
    }
    after
}

/// Past a string, char literal or comment at `i`; `i` itself when none
/// starts there. An unclosed string or comment runs to the end of the text.
pub(crate) fn skip(text: &str, i: usize) -> usize {
    let bytes = text.as_bytes();
    let c = bytes[i];
    if c == b'"' {
        return string_end(text, i + 1);
    }
    if c == b'/' && bytes[i..].starts_with(b"//") {
        return find_from(text, "\n", i).unwrap_or(bytes.len());
    }
    if c == b'/' && bytes[i..].starts_with(b"/*") {
        let (mut depth, mut j) = (0_i64, i);
        while j < bytes.len() {
            if bytes[j..].starts_with(b"/*") {
                depth += 1;
                j += 2;
                continue;
            }
            if bytes[j..].starts_with(b"*/") {
                depth -= 1;
                j += 2;
                if depth == 0 {
                    return j;
                }
                continue;
            }
            j = next_char(text, j);
        }
        return bytes.len();
    }
    if c == b'\'' {
        return char_literal_end(text, i + 1);
    }
    if (c == b'r' || c == b'b') && (i == 0 || char_before(text, i).is_none_or(|p| !is_word(p))) {
        let rest = &bytes[i..];
        let raw = rest.starts_with(b"r\"")
            || rest.starts_with(b"r#")
            || rest.starts_with(b"br\"")
            || rest.starts_with(b"br#");
        if raw && let Some(end) = raw_string_end(text, i) {
            return end;
        }
    }
    i
}

/// `_skip(text, -1)`: Python's negative index makes `text[-1]` the last character (`last`), and the scan then
/// runs from offset 0. `None` stands for Python's `-1` (nothing skipped).
fn skip_from_minus_one(text: &str, last: char) -> Option<usize> {
    match last {
        '"' => Some(string_end(text, 0)),
        '\'' => Some(char_literal_end(text, 0)),
        _ => None,
    }
}

/// The offset past the bracket that closes the one at `i`, skipping
/// strings and comments; bracket kinds are not checked, and an unclosed bracket runs to the end of the text.
pub(crate) fn close_of(text: &str, i: usize) -> usize {
    close_of_with_depth(text, i, 0)
}

/// `close_of` from `i` with `depth` brackets already open.
fn close_of_with_depth(text: &str, mut i: usize, mut depth: i64) -> usize {
    let bytes = text.as_bytes();
    while i < bytes.len() {
        let j = skip(text, i);
        if j != i {
            i = j;
            continue;
        }
        let c = bytes[i];
        if b"([{".contains(&c) {
            depth += 1;
        } else if b")]}".contains(&c) {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
        i = next_char(text, i);
    }
    bytes.len()
}

/// The text without its comments; strings are kept.
pub(crate) fn strip_comments(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let (mut i, mut start) = (0, 0);
    while i < bytes.len() {
        if bytes[i..].starts_with(b"//") || bytes[i..].starts_with(b"/*") {
            out.push_str(&text[start..i]);
            i = skip(text, i);
            start = i;
            continue;
        }
        let j = skip(text, i);
        i = if j != i { j } else { next_char(text, i) };
    }
    out.push_str(&text[start..]);
    out
}

/// Splits at `sep` outside brackets, angle brackets and strings;
/// the parts are stripped and empty ones dropped. `->` is stepped over; any other `>` closes an angle.
pub(crate) fn split_top(text: &str, sep: u8) -> Vec<&str> {
    let bytes = text.as_bytes();
    let mut parts = Vec::new();
    let (mut depth, mut start, mut i) = (0_i64, 0, 0);
    while i < bytes.len() {
        let j = skip(text, i);
        if j != i {
            i = j;
            continue;
        }
        let c = bytes[i];
        if c == b'-' && bytes[i..].starts_with(b"->") {
            i += 2;
            continue;
        }
        if b"([{<".contains(&c) {
            depth += 1;
        } else if b")]}>".contains(&c) {
            depth -= 1;
        } else if c == sep && depth == 0 {
            parts.push(&text[start..i]);
            start = i + 1;
        }
        i = next_char(text, i);
    }
    parts.push(&text[start..]);
    parts
        .into_iter()
        .map(strip)
        .filter(|part| !part.is_empty())
        .collect()
}

/// A chunk's leading `#[...]` attributes as one string, and the
/// rest of it.
pub(crate) fn leading_attrs(chunk: &str) -> (String, &str) {
    let mut attrs: Vec<&str> = Vec::new();
    let mut rest = strip(chunk);
    while rest.starts_with("#[") {
        let end = close_of(rest, 1);
        attrs.push(&rest[..end]);
        rest = strip(&rest[end..]);
    }
    (attrs.join(" "), rest)
}

/// `re.match(r'(\w+)\s*=\s*(.*)$', part, re.S)`
static PAIR: LazyLock<Regex> = LazyLock::new(|| compile(r"(?s)\A(\w+)\s*=\s*(.*)"));
/// `re.match(r'(\w+)\s*\(', part)`
static NESTED: LazyLock<Regex> = LazyLock::new(|| compile(r"\A(\w+)\s*\("));

/// The merged `name(...)` arguments in the attributes, as key ->
/// value: a quoted value read as JSON (a JSON error is Python's `JSONDecodeError`), any other value as its text, a
/// nested `key(...)` as its own arguments (or `True` when it has none), a bare flag as `True`.
pub(crate) fn attr_args(attrs: &str, name: &str) -> Result<Dict, GenerateError> {
    attr_args_at_depth(attrs, name, 0)
}

/// `attr_args` for a `key(...)` nested `depth` deep. Python recurses once per nesting level, so a nesting as deep
/// as its recursion limit is its `RecursionError` here, not an exhausted native stack.
fn attr_args_at_depth(attrs: &str, name: &str, depth: usize) -> Result<Dict, GenerateError> {
    if depth >= RECURSION_LIMIT {
        return Err(recursion_error());
    }
    let mut found = Dict::new();
    for open in call_opens(attrs, name, true) {
        let inner = slice(attrs, open + 1, prev_char(attrs, close_of(attrs, open)));
        for part in split_top(inner, b',') {
            let pair = PAIR.captures(part);
            let nested = NESTED.captures(part);
            if let Some(pair) = pair {
                let value = strip(&pair[2]);
                let value = if value.starts_with('"') {
                    crate::py::json::loads(value)
                        .map_err(|error| error.into_error("a Rust attribute value"))?
                } else {
                    Value::Str(value.to_owned())
                };
                found.insert(pair[1].to_owned(), value);
            } else if let Some(nested) = nested {
                let inner = attr_args_at_depth(part, &nested[1], depth + 1)?;
                found.insert(
                    nested[1].to_owned(),
                    if inner.is_empty() {
                        Value::Bool(true)
                    } else {
                        Value::Dict(inner)
                    },
                );
            } else {
                found.insert(strip(part).to_owned(), Value::Bool(true));
            }
        }
    }
    Ok(found)
}

/// The last path segment of every name a `derive(...)` lists (a
/// set; only membership is read).
pub(crate) fn derives(attrs: &str) -> IndexSet<String> {
    let mut names = IndexSet::new();
    for open in call_opens(attrs, "derive", false) {
        let inner = slice(attrs, open + 1, prev_char(attrs, close_of(attrs, open)));
        for part in split_top(inner, b',') {
            names.insert(
                part.rsplit_once("::")
                    .map_or(part, |(_, last)| last)
                    .to_owned(),
            );
        }
    }
    names
}

/// Serde's `rename_all`, where a variant name is PascalCase and a field
/// name snake_case. A case that is not a string compares unequal to every spelling, so the name stays.
pub(crate) fn rename(name: &str, case: Option<&Value>, variant: bool) -> String {
    let Some(case) = case.filter(|case| case.truthy()) else {
        return name.to_owned();
    };
    let words: Vec<String> = if variant {
        crate::py::text::lower(&crate::py::re::sub_underscore_before_capitals(name))
            .split('_')
            .map(str::to_owned)
            .collect()
    } else {
        name.split('_').map(str::to_owned).collect()
    };
    let Value::Str(case) = case else {
        return name.to_owned();
    };
    let lower = crate::py::text::lower;
    let upper = crate::py::text::upper;
    let pascal = || {
        if variant {
            name.to_owned()
        } else {
            words
                .iter()
                .map(|word| crate::py::text::title(word))
                .collect()
        }
    };
    match case.as_str() {
        "lowercase" => {
            if variant {
                lower(name)
            } else {
                name.to_owned()
            }
        }
        "UPPERCASE" => upper(name),
        "PascalCase" => pascal(),
        "camelCase" => {
            let pascal = pascal();
            let mut chars = pascal.chars();
            match chars.next() {
                Some(first) => lower(&first.to_string()) + chars.as_str(),
                None => String::new(),
            }
        }
        "snake_case" => words.join("_"),
        "SCREAMING_SNAKE_CASE" => upper(&words.join("_")),
        "kebab-case" => words.join("-"),
        "SCREAMING-KEBAB-CASE" => upper(&words.join("-")),
        _ => name.to_owned(),
    }
}

/// Python's `a or b` over attribute values: `a` when it is truthy, else `b`.
pub(crate) fn or_value<'v>(a: Option<&'v Value>, b: Option<&'v Value>) -> Option<&'v Value> {
    match a {
        Some(value) if value.truthy() => Some(value),
        _ => b,
    }
}

/// Whether an attribute value is truthy (`serde.get(key)` in a condition).
pub(crate) fn truthy(value: Option<&Value>) -> bool {
    value.is_some_and(Value::truthy)
}

/// Whether an attribute value `is True`.
pub(crate) fn is_true(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true)))
}

/// The codec a field is read through, when it names one
/// (`serde.get('with') or serde.get('deserialize_with')`).
pub(crate) fn codec_of(serde: &Dict) -> Option<&Value> {
    or_value(serde.get("with"), serde.get("deserialize_with"))
}

/// A `rename_all`/`rename` value, or its `serialize = ...`
/// half.
pub(crate) fn serialize_case(value: Option<&Value>) -> Option<Value> {
    match value {
        Some(Value::Dict(dict)) => dict.get("serialize").cloned(),
        Some(value @ Value::Str(_)) => Some(value.clone()),
        _ => None,
    }
}

/// `serialize_case(...) or fallback`.
pub(crate) fn case_or(value: Option<Value>, fallback: impl FnOnce() -> Value) -> Value {
    match value {
        Some(value) if value.truthy() => value,
        _ => fallback(),
    }
}

// ---------------------------------------------------------------- Rust types

/// A `type` alias body, from past the first `=` at or after `position` to the
/// first `;` outside brackets, strings and comments, stripped.
pub(crate) fn alias_body(text: &str, position: usize) -> String {
    match find_from(text, "=", position) {
        Some(equals) => strip(slice(text, equals + 1, alias_semicolon(text, equals))).to_owned(),
        None => alias_body_without_equals(text),
    }
}

/// The Python loop `while semi < len(text) and text[semi] != ';'`, from `semi`.
fn alias_semicolon(text: &str, mut semi: usize) -> usize {
    let bytes = text.as_bytes();
    while semi < bytes.len() && bytes[semi] != b';' {
        let j = skip(text, semi);
        semi = if b"([{".contains(&bytes[semi]) {
            close_of(text, semi)
        } else if j != semi {
            j
        } else {
            next_char(text, semi)
        };
    }
    semi
}

/// The alias body when no `=` follows the header: Python's `text.find` gives `-1`, so `semi` starts at `-1`,
/// `text[-1]` is the last character, and the body is `text[0:semi]` (`text[0:-1]` when that last character is
/// the `;`).
fn alias_body_without_equals(text: &str) -> String {
    let Some(last) = text.chars().next_back() else {
        return String::new();
    };
    if last == ';' {
        return strip(slice(text, 0, prev_char(text, text.len()))).to_owned();
    }
    let first = if "([{".contains(last) {
        // `close_of(text, -1)`: the last character opens, then the scan runs from 0.
        close_of_with_depth(text, 0, 1)
    } else {
        // `j = _skip(text, -1)`; `semi = j if j != semi else semi + 1`, and `-1 + 1` is 0.
        skip_from_minus_one(text, last).unwrap_or(0)
    };
    strip(slice(text, 0, alias_semicolon(text, first))).to_owned()
}

#[cfg(test)]
mod tests;
