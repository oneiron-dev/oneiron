//! Port of facade_types.py:121-364: the Rust-text scanner (strings, char literals, comments, brackets), the
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

use super::{RECURSION_LIMIT, index_error, recursion_error};
use crate::error::GenerateError;
use crate::py::re::compile;
use crate::py::text::{is_space, is_word, strip};
use crate::py::value::{Dict, Value};

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

/// Port of facade_types.py:123-132 (`_raw_string_end`): if a raw string starts at `i`, the offset past its close
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

/// The string loop of `_skip` (facade_types.py:139-144), from the offset past the opening quote: past the close,
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

/// The char-literal branch of `_skip` (facade_types.py:158-164) for a quote at Python offset `i`, where `after`
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

/// Port of facade_types.py:135-169 (`_skip`): past a string, char literal or comment at `i`; `i` itself when none
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

/// Port of facade_types.py:172-185 (`close_of`): the offset past the bracket that closes the one at `i`, skipping
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

/// Port of facade_types.py:188-196 (`strip_comments`): the text without its comments; strings are kept.
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

/// Port of facade_types.py:199-215 (`split_top`): splits at `sep` outside brackets, angle brackets and strings;
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

/// Port of facade_types.py:218-224 (`leading_attrs`): a chunk's leading `#[...]` attributes as one string, and the
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

/// Port of facade_types.py:227-243 (`attr_args`): the merged `name(...)` arguments in the attributes, as key ->
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

/// Port of facade_types.py:246-251 (`derives`): the last path segment of every name a `derive(...)` lists (a
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

/// Port of facade_types.py:254-268 (`rename`): serde's `rename_all`, where a variant name is PascalCase and a field
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

/// Port of facade_types.py:271-273 (`codec_of`): the codec a field is read through, when it names one
/// (`serde.get('with') or serde.get('deserialize_with')`).
pub(crate) fn codec_of(serde: &Dict) -> Option<&Value> {
    or_value(serde.get("with"), serde.get("deserialize_with"))
}

/// Port of facade_types.py:276-279 (`serialize_case`): a `rename_all`/`rename` value, or its `serialize = ...`
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

/// A Rust type as a tree (Python's `parse_type` tuples).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Ast {
    /// `("path", segments, args)`
    Path(Vec<String>, Vec<Ast>),
    /// `("tuple", items)`
    Tuple(Vec<Ast>),
    /// `("array", item)`
    Array(Box<Ast>),
    /// `("ref", item)`
    Ref(Box<Ast>),
    /// `("raw", text)`
    Raw(String),
}

/// Port of facade_types.py:284 (`TOKEN`): `re.compile(r"\s*(::|->|'[A-Za-z_]\w*|r#\w+|[A-Za-z_]\w*|\d+|.)", re.S)`.
static TOKEN: LazyLock<Regex> =
    LazyLock::new(|| compile(r"(?s)\s*(::|->|'[A-Za-z_]\w*|r#\w+|[A-Za-z_]\w*|\d+|.)"));

/// `re.match(r'(r#)?[A-Za-z_]\w*$', name)` on a token (a token holds no newline).
fn is_path_segment(name: &str) -> bool {
    let ident = |text: &str| {
        let mut chars = text.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(is_word)
    };
    name.strip_prefix("r#").is_some_and(ident) || ident(name)
}

/// The Python loop `parse_type` never leaves: a `dyn`, `impl`, `fn`, `*`, `<`, `!` or `_` in a type argument or
/// a tuple, which `typ()` returns as raw without taking it, so the loop appends to its list forever. The port
/// stops there instead (FIX row filed; documented in the PR).
fn no_progress(text: &str, token: &str) -> GenerateError {
    GenerateError::exception(
        "RuntimeError",
        format!(
            "parse_type does not advance at `{token}` in `{text}` (facade_types.py:307-320 and 330-336 loop here without end)"
        ),
    )
}

/// The cursor `parse_type`'s nested functions share.
struct TypeParser<'t> {
    text: &'t str,
    tokens: Vec<&'t str>,
    position: usize,
    /// How many `typ()` and `args()` calls are open (Python's frames for the nested functions): a type nested as
    /// deep as Python's recursion limit is its `RecursionError` here, not an exhausted native stack.
    depth: usize,
}

impl<'t> TypeParser<'t> {
    fn peek(&self, offset: usize) -> Option<&'t str> {
        self.tokens.get(self.position + offset).copied()
    }

    /// `take()`: Python's `tokens[position - 1]` past the end is an `IndexError`.
    fn take(&mut self) -> Result<&'t str, GenerateError> {
        self.position += 1;
        self.tokens
            .get(self.position - 1)
            .copied()
            .ok_or_else(index_error)
    }

    fn raw(&self) -> Ast {
        Ast::Raw(self.text.to_owned())
    }

    fn until_close(&mut self, open: &str, close: &str) -> Result<(), GenerateError> {
        let mut depth: i64 = 1;
        while self.peek(0).is_some() && depth != 0 {
            let token = self.take()?;
            depth += i64::from(token == open);
            depth -= i64::from(token == close);
        }
        Ok(())
    }

    /// Opens one of Python's frames for `typ()` or `args()`.
    fn enter(&mut self) -> Result<(), GenerateError> {
        if self.depth >= RECURSION_LIMIT {
            return Err(recursion_error());
        }
        self.depth += 1;
        Ok(())
    }

    fn args(&mut self) -> Result<Vec<Ast>, GenerateError> {
        self.enter()?;
        let out = self.args_frame();
        self.depth -= 1;
        out
    }

    /// The body of Python's `args()`, inside the frame `args` opens.
    fn args_frame(&mut self) -> Result<Vec<Ast>, GenerateError> {
        let mut out = Vec::new();
        while let Some(token) = self.peek(0).filter(|token| *token != ">") {
            let before = self.position;
            if token.starts_with('\'') {
                self.take()?;
            } else if self.peek(1) == Some("=") && self.peek(2) != Some("=") {
                self.take()?;
                self.take()?;
                self.typ()?;
            } else if token == "{" {
                self.take()?;
                self.until_close("{", "}")?;
            } else {
                out.push(self.typ()?);
            }
            if self.peek(0) == Some(",") {
                self.take()?;
            }
            if self.position == before {
                return Err(no_progress(self.text, token));
            }
        }
        if self.peek(0) == Some(">") {
            self.take()?;
        }
        Ok(out)
    }

    fn typ(&mut self) -> Result<Ast, GenerateError> {
        self.enter()?;
        let node = self.typ_frame();
        self.depth -= 1;
        node
    }

    /// The body of Python's `typ()`, inside the frame `typ` opens.
    fn typ_frame(&mut self) -> Result<Ast, GenerateError> {
        let Some(token) = self.peek(0) else {
            return Ok(self.raw());
        };
        if token == "&" {
            self.take()?;
            if self.peek(0).is_some_and(|next| next.starts_with('\'')) {
                self.take()?;
            }
            if self.peek(0) == Some("mut") {
                self.take()?;
            }
            return Ok(Ast::Ref(Box::new(self.typ()?)));
        }
        if token == "(" {
            self.take()?;
            let mut items = Vec::new();
            while let Some(next) = self.peek(0).filter(|next| *next != ")") {
                let before = self.position;
                items.push(self.typ()?);
                if self.peek(0) == Some(",") {
                    self.take()?;
                }
                if self.position == before {
                    return Err(no_progress(self.text, next));
                }
            }
            self.take()?;
            return Ok(Ast::Tuple(items));
        }
        if token == "[" {
            self.take()?;
            let item = self.typ()?;
            if self.peek(0) == Some(";") {
                self.take()?;
                while self.peek(0).is_some_and(|next| next != "]") {
                    // `take() in '([{'` is a substring test; a token is one bracket or a longer word.
                    if "([{".contains(self.take()?) {
                        self.until_close("[", "]")?;
                    }
                }
            }
            self.take()?;
            return Ok(Ast::Array(Box::new(item)));
        }
        if matches!(token, "dyn" | "impl" | "fn" | "*" | "<" | "!" | "_") {
            return Ok(self.raw());
        }
        let (mut segments, mut generic) = (Vec::new(), Vec::new());
        if token == "::" {
            self.take()?;
        }
        loop {
            let name = self.take()?;
            if !is_path_segment(name) {
                return Ok(self.raw());
            }
            segments.push(name.strip_prefix("r#").unwrap_or(name).to_owned());
            if self.peek(0) == Some("::") && self.peek(1) == Some("<") {
                self.take()?;
            }
            if self.peek(0) == Some("<") {
                self.take()?;
                generic = self.args()?;
            }
            if self.peek(0) == Some("::")
                && self.peek(1).is_some_and(|next| {
                    next.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                })
            {
                self.take()?;
                continue;
            }
            break;
        }
        Ok(Ast::Path(segments, generic))
    }
}

/// Port of facade_types.py:287-364 (`parse_type`): a Rust type as a tree; lifetimes, associated assignments and
/// const arguments are dropped, `dyn`/`impl`/`fn`/pointer/unknown syntax is raw, and leftover tokens make the
/// whole type raw.
pub(crate) fn parse_type(text: &str) -> Result<Ast, GenerateError> {
    let tokens = TOKEN
        .captures_iter(text)
        .filter_map(|found| found.get(1))
        .map(|token| token.as_str())
        .filter(|token| !strip(token).is_empty())
        .collect();
    let mut parser = TypeParser {
        text,
        tokens,
        position: 0,
        depth: 0,
    };
    let result = parser.typ()?;
    Ok(if parser.position >= parser.tokens.len() {
        result
    } else {
        parser.raw()
    })
}

// ---------------------------------------------------------------- an alias body (read_item)

/// Port of facade_types.py:466-471: a `type` alias body, from past the first `=` at or after `position` to the
/// first `;` outside brackets, strings and comments, stripped.
pub(crate) fn alias_body(text: &str, position: usize) -> String {
    match find_from(text, "=", position) {
        Some(equals) => strip(slice(text, equals + 1, alias_semicolon(text, equals))).to_owned(),
        None => alias_body_without_equals(text),
    }
}

/// The `while semi < len(text) and text[semi] != ';'` loop of facade_types.py:468-470, from `semi`.
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

/// facade_types.py:466-471 when no `=` follows the header: `text.find` gives `-1`, so `semi` starts at `-1`,
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
mod tests {
    use super::*;

    // Every expected value is what Python 3.14.7 prints on nelly with main's facade_types.py, run from the checkout:
    // python3 -c 'import sys; sys.path.insert(0, "scripts/sdk"); import facade_types as f; print(<call>)'
    // Python's offsets count code points; the port's are UTF-8 bytes, so each is converted with
    // len(t[:i].encode()).

    #[test]
    fn skip_reads_strings_comments_and_char_literals() {
        // f._skip(t, 0) for each t (then len(t[:i].encode()))
        assert_eq!(skip(r#""a\"b" x"#, 0), 6);
        assert_eq!(skip("\"unclosed", 0), 9);
        assert_eq!(skip("// c\nx", 0), 4);
        assert_eq!(skip("/* a /* b */ c */x", 0), 17);
        // An unclosed block comment runs to the end (facade_types.py:157, which no corpus run reaches): 12, 4, 3.
        assert_eq!(skip("/* a /* b */", 0), 12);
        assert_eq!(skip("/* …", 0), 6);
        assert_eq!(skip("/*/", 0), 3);
        assert_eq!(skip("'…' x", 0), 5);
        assert_eq!(skip("'a x", 0), 1);
        assert_eq!(skip(r"'\n' x", 0), 4);
        assert_eq!(skip(r##"r#"a"# x"##, 0), 6);
        assert_eq!(skip("br\"a\" x", 0), 5);
        // f._skip('xr"a"', 1) == 1: a word character before `r` is no raw string
        assert_eq!(skip("xr\"a\"", 1), 1);
    }

    #[test]
    fn close_of_counts_brackets_without_kinds() {
        // f.close_of('(a]b)', 0) == 3; f.close_of('{ "}" }x', 0) == 7; f.close_of('(é', 0) == 2 code points
        assert_eq!(close_of("(a]b)", 0), 3);
        assert_eq!(close_of("{ \"}\" }x", 0), 7);
        assert_eq!(close_of("(é", 0), 3);
    }

    #[test]
    fn split_top_and_leading_attrs() {
        // f.split_top('a<b, c>, d -> e, (f, g),') == ['a<b, c>', 'd -> e', '(f, g)']
        assert_eq!(
            split_top("a<b, c>, d -> e, (f, g),", b','),
            vec!["a<b, c>", "d -> e", "(f, g)"]
        );
        // f.leading_attrs(' #[a] #[b(c)] x: u8 ') == ('#[a] #[b(c)]', 'x: u8')
        assert_eq!(
            leading_attrs(" #[a] #[b(c)] x: u8 "),
            ("#[a] #[b(c)]".to_owned(), "x: u8")
        );
    }

    #[test]
    fn attr_args_merges_and_derives_take_last_segments() {
        // f.attr_args('#[serde(rename = "a", default, with = crate::x, rename_all(serialize = "camelCase"), tag)]
        //   #[serde(default = "f")]', 'serde')
        // == {'rename': 'a', 'default': 'f', 'with': 'crate::x', 'rename_all': {'serialize': 'camelCase'}, 'tag': True}
        let attrs = r#"#[serde(rename = "a", default, with = crate::x, rename_all(serialize = "camelCase"), tag)] #[serde(default = "f")]"#;
        let found = attr_args(attrs, "serde").expect("attributes read");
        assert_eq!(
            found.keys().collect::<Vec<_>>(),
            ["rename", "default", "with", "rename_all", "tag"]
        );
        assert_eq!(found["default"].as_str(), Some("f"));
        assert_eq!(found["with"].as_str(), Some("crate::x"));
        assert_eq!(
            found["rename_all"].get("serialize").and_then(Value::as_str),
            Some("camelCase")
        );
        assert!(found["tag"].is_true());
        // sorted(f.derives('#[derive(Debug, serde::Serialize)] #[cfg_attr(x, derive(Deserialize))]'))
        // == ['Debug', 'Deserialize', 'Serialize']
        let mut names: Vec<String> =
            derives("#[derive(Debug, serde::Serialize)] #[cfg_attr(x, derive(Deserialize))]")
                .into_iter()
                .collect();
        names.sort();
        assert_eq!(names, ["Debug", "Deserialize", "Serialize"]);
    }

    #[test]
    fn rename_follows_serde_cases() {
        // f.rename(name, case, variant) for each row
        let cases: &[(&str, Option<&str>, bool, &str)] = &[
            ("HTTPServer", Some("snake_case"), true, "h_t_t_p_server"),
            ("field_name", Some("camelCase"), false, "fieldName"),
            ("MyVariant", Some("kebab-case"), true, "my-variant"),
            ("x_y", Some("PascalCase"), false, "XY"),
            ("Ab", Some("SCREAMING_SNAKE_CASE"), true, "AB"),
            ("ab_c", Some("lowercase"), false, "ab_c"),
            ("ÀbÇ", Some("lowercase"), true, "àbç"),
            ("a", None, true, "a"),
            ("a_b", Some("unknown"), false, "a_b"),
        ];
        for (name, case, variant, expected) in cases {
            let case = case.map(|case| Value::Str(case.to_owned()));
            assert_eq!(
                rename(name, case.as_ref(), *variant),
                *expected,
                "{name} {case:?}"
            );
        }
    }

    #[test]
    fn parse_type_trees() {
        let path = |segments: &[&str], args: Vec<Ast>| {
            Ast::Path(segments.iter().map(|s| (*s).to_owned()).collect(), args)
        };
        // f.parse_type('Vec<Option<crate::a::B>>')
        // == ('path', ['Vec'], [('path', ['Option'], [('path', ['crate', 'a', 'B'], [])])])
        assert_eq!(
            parse_type("Vec<Option<crate::a::B>>").ok(),
            Some(path(
                &["Vec"],
                vec![path(&["Option"], vec![path(&["crate", "a", "B"], vec![])])]
            ))
        );
        // f.parse_type("&'a mut [u8; 16]") == ('ref', ('array', ('path', ['u8'], [])))
        assert_eq!(
            parse_type("&'a mut [u8; 16]").ok(),
            Some(Ast::Ref(Box::new(Ast::Array(Box::new(path(
                &["u8"],
                vec![]
            ))))))
        );
        // f.parse_type('u8 u8') == ('raw', 'u8 u8'): leftover tokens
        assert_eq!(parse_type("u8 u8").ok(), Some(Ast::Raw("u8 u8".to_owned())));
        // f.parse_type('Foo<A>::Bar') == ('path', ['Foo', 'Bar'], [('path', ['A'], [])])
        assert_eq!(
            parse_type("Foo<A>::Bar").ok(),
            Some(path(&["Foo", "Bar"], vec![path(&["A"], vec![])]))
        );
        // f.parse_type('::') raises IndexError: list index out of range
        assert_eq!(
            parse_type("::")
                .err()
                .map(|error| error.to_string())
                .as_deref(),
            Some("IndexError: list index out of range")
        );
    }

    /// The outcome of `run` on a thread with the binary's 256 MiB stack (a test thread has 2 MiB).
    fn on_big_stack<T: Send + 'static>(run: impl FnOnce() -> T + Send + 'static) -> T {
        std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn(run)
            .expect("a test thread")
            .join()
            .expect("the test thread returns")
    }

    #[test]
    fn nesting_past_the_recursion_limit_is_python_recursion_error() {
        // python3 -c '...; f.parse_type("&" * n + "u8")': n = 19990 parses, n = 20001 raises
        // RecursionError: maximum recursion depth exceeded (the exact cut-off depends on the frames below it and is
        // not part of the contract; the outcome past it is).
        let outcomes = on_big_stack(|| {
            let message = |result: Result<Ast, GenerateError>| result.err().map(|e| e.to_string());
            (
                message(parse_type(&format!("{}u8", "&".repeat(19_990)))),
                message(parse_type(&format!("{}u8", "&".repeat(20_001)))),
                message(parse_type(&format!(
                    "{}u8{}",
                    "Vec<".repeat(10_001),
                    ">".repeat(10_001)
                ))),
            )
        });
        let refused = Some("RecursionError: maximum recursion depth exceeded".to_owned());
        assert_eq!(outcomes, (None, refused.clone(), refused.clone()));
        // attr_args recurses once per nested `key(...)`: at the limit the next level is refused.
        let nested = "serde(x(default))";
        assert!(attr_args_at_depth(nested, "serde", RECURSION_LIMIT - 2).is_ok());
        assert_eq!(
            attr_args_at_depth(nested, "serde", RECURSION_LIMIT - 1)
                .err()
                .map(|e| e.to_string()),
            refused
        );
    }
}
