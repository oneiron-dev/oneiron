//! Python's `json` (brief H1, H1b): `loads` as CPython 3.14.7's C scanner reads a `str`, with `JSONDecodeError`'s
//! messages and positions, and `dumps` as `json.dumps` writes.
//!
//! `loads` keeps a duplicate key at its first position with its last value, takes `NaN`, `Infinity` and `-Infinity`,
//! reads `1` as an int and `1.0`/`1e3` as floats, and counts positions in code points. An integer of more than 4,300
//! digits is Python's own `ValueError` (`sys.get_int_max_str_digits()`), raised where the scanner meets it.
//!
//! Two values Python reads are refused (DESIGN 3 and 9.5): an integer outside `i64`, and a `\uXXXX` escape that leaves
//! a lone surrogate (no Rust `String` holds one). Each is refused only once the whole text has decoded, and only if
//! it survives into the result (a duplicate key's later value drops an earlier one), so a text Python refuses fails
//! with Python's own error first and a result that holds neither is never refused.

use std::fmt;

use crate::error::GenerateError;
use crate::py::value::{Dict, Value, float_json};

/// The deepest nesting `loads` reads. CPython's limit is its C stack: on nelly (8 MiB) it reads 52,184 nested arrays
/// or objects and refuses one more with `RecursionError: Stack overflow (used ... kB) while decoding a JSON array from
/// a unicode string`. The port reads every depth Python reads and refuses past this one with the older wording
/// (recursion depth counted by the port, DESIGN 9.5). The binary runs on a 256 MiB stack, which this depth fits.
pub(crate) const MAX_DEPTH: usize = 100_000;

/// `sys.get_int_max_str_digits()` on nelly's Python 3.14.7: `int()` of a longer decimal text is a `ValueError`.
pub(crate) const INT_MAX_STR_DIGITS: usize = 4300;

/// Why `loads` refused its text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JsonError {
    /// `json.decoder.JSONDecodeError`.
    Decode {
        /// Python's message (`Expecting value`, `Extra data`, ...).
        msg: &'static str,
        /// The code point offset.
        pos: usize,
        /// `doc.count('\n', 0, pos) + 1`.
        lineno: usize,
        /// `pos - doc.rfind('\n', 0, pos)`.
        colno: usize,
    },
    /// `RecursionError`: nested deeper than `MAX_DEPTH`.
    Recursion {
        /// `array` or `object`.
        container: &'static str,
    },
    /// Python's `ValueError` for an integer of more than `INT_MAX_STR_DIGITS` digits.
    IntDigitLimit {
        /// Its digits, the sign aside.
        digits: usize,
    },
    /// An integer outside `i64` (Python reads it; the port refuses it).
    IntOutOfRange {
        /// The integer's text.
        text: String,
        /// Where it starts (code points), with its line and column.
        pos: usize,
        lineno: usize,
        colno: usize,
    },
    /// A `\uXXXX` escape of a lone surrogate (Python reads it; the port refuses it).
    LoneSurrogate {
        /// The surrogate.
        code: u32,
        /// Where its backslash is (code points), with its line and column.
        pos: usize,
        lineno: usize,
        colno: usize,
    },
}

impl JsonError {
    /// The error the generator stops with. A refusal Python would not make names `source` (the file), since
    /// Python's own `JSONDecodeError` text names no file.
    pub(crate) fn into_error(self, source: &str) -> GenerateError {
        match self {
            Self::Decode { .. } => {
                GenerateError::exception("json.decoder.JSONDecodeError", self.to_string())
            }
            Self::Recursion { container } => GenerateError::exception(
                "RecursionError",
                format!(
                    "maximum recursion depth exceeded while decoding a JSON {container} from a unicode string"
                ),
            ),
            Self::IntDigitLimit { digits } => GenerateError::value(format!(
                "Exceeds the limit ({INT_MAX_STR_DIGITS} digits) for integer string conversion: value has {digits} \
                 digits; use sys.set_int_max_str_digits() to increase the limit"
            )),
            Self::IntOutOfRange {
                text,
                lineno,
                colno,
                pos,
            } => GenerateError::value(format!(
                "{source}: the integer {text} at line {lineno} column {colno} (char {pos}) is outside the 64-bit \
                 range the Rust SDK generator reads"
            )),
            Self::LoneSurrogate {
                code,
                lineno,
                colno,
                pos,
            } => GenerateError::value(format!(
                "{source}: the escape \\u{code:04x} at line {lineno} column {colno} (char {pos}) is a lone \
                 surrogate, which the Rust SDK generator cannot hold in a string"
            )),
        }
    }
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode {
                msg,
                pos,
                lineno,
                colno,
            } => write!(f, "{msg}: line {lineno} column {colno} (char {pos})"),
            Self::Recursion { container } => write!(
                f,
                "nested deeper than {MAX_DEPTH} levels in a JSON {container}"
            ),
            Self::IntDigitLimit { digits } => write!(f, "an integer of {digits} digits"),
            Self::IntOutOfRange { text, pos, .. } => {
                write!(f, "integer {text} at char {pos} is outside i64")
            }
            Self::LoneSurrogate { code, pos, .. } => {
                write!(f, "lone surrogate \\u{code:04x} at char {pos}")
            }
        }
    }
}

/// A scan that failed: Python's `StopIteration(pos)` (no value starts there; the caller says `Expecting value`), or
/// an error raised where it was found.
enum Fail {
    Stop(usize),
    Error(JsonError),
}

impl From<JsonError> for Fail {
    fn from(error: JsonError) -> Self {
        Self::Error(error)
    }
}

type Scan<T> = Result<(T, usize), Fail>;

/// A value Python reads and the port cannot hold, refused only if it survives the decode.
enum Unheld {
    /// An integer outside `i64`, its text (a placeholder `0` stands in).
    Int(String),
    /// A lone surrogate's code (a placeholder U+FFFD stands in).
    Surrogate(u32),
}

struct Deferred {
    unheld: Unheld,
    /// Where it starts (code points).
    pos: usize,
    /// False once a duplicate key's later value has dropped the value holding it.
    alive: bool,
}

struct Scanner<'a> {
    s: &'a [char],
    depth: usize,
    /// Every unheld value met, in text order.
    deferred: Vec<Deferred>,
}

fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r')
}

fn hex4(digits: &[char]) -> Option<u32> {
    digits
        .iter()
        .try_fold(0, |acc, c| c.to_digit(16).map(|d| (acc << 4) | d))
}

impl Scanner<'_> {
    fn line_col(&self, pos: usize) -> (usize, usize) {
        let before = &self.s[..pos];
        let lineno = before.iter().filter(|&&c| c == '\n').count() + 1;
        let colno = before
            .iter()
            .rposition(|&c| c == '\n')
            .map_or(pos + 1, |nl| pos - nl);
        (lineno, colno)
    }

    fn error(&self, msg: &'static str, pos: usize) -> JsonError {
        let (lineno, colno) = self.line_col(pos);
        JsonError::Decode {
            msg,
            pos,
            lineno,
            colno,
        }
    }

    fn at(&self, idx: usize) -> Option<char> {
        self.s.get(idx).copied()
    }

    fn skip_ws(&self, mut idx: usize) -> usize {
        while self.at(idx).is_some_and(is_ws) {
            idx += 1;
        }
        idx
    }

    fn word_at(&self, idx: usize, word: &str) -> bool {
        let len = word.chars().count();
        self.s
            .get(idx..idx + len)
            .is_some_and(|got| got.iter().copied().eq(word.chars()))
    }

    /// `scan_once_unicode`.
    fn scan_once(&mut self, idx: usize) -> Scan<Value> {
        let Some(c) = self.at(idx) else {
            return Err(Fail::Stop(idx));
        };
        match c {
            '"' => {
                return self
                    .scanstring(idx + 1)
                    .map(|(s, end)| (Value::Str(s), end));
            }
            '{' | '[' => {
                let container = if c == '{' { "object" } else { "array" };
                if self.depth >= MAX_DEPTH {
                    return Err(JsonError::Recursion { container }.into());
                }
                self.depth += 1;
                let result = if c == '{' {
                    self.parse_object(idx + 1)
                } else {
                    self.parse_array(idx + 1)
                };
                self.depth -= 1;
                return result;
            }
            'n' if self.word_at(idx, "null") => return Ok((Value::None, idx + 4)),
            't' if self.word_at(idx, "true") => return Ok((Value::Bool(true), idx + 4)),
            'f' if self.word_at(idx, "false") => return Ok((Value::Bool(false), idx + 5)),
            'N' if self.word_at(idx, "NaN") => return Ok((Value::Float(f64::NAN), idx + 3)),
            'I' if self.word_at(idx, "Infinity") => {
                return Ok((Value::Float(f64::INFINITY), idx + 8));
            }
            '-' if self.word_at(idx, "-Infinity") => {
                return Ok((Value::Float(f64::NEG_INFINITY), idx + 9));
            }
            _ => {}
        }
        self.match_number(idx)
    }

    /// `_match_number_unicode`: `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?`, an exponent with no digit left
    /// unread.
    fn match_number(&mut self, start: usize) -> Scan<Value> {
        let digit = |idx: usize| self.at(idx).is_some_and(|c| c.is_ascii_digit());
        let mut idx = start;
        if self.at(idx) == Some('-') {
            idx += 1;
        }
        match self.at(idx) {
            Some('1'..='9') => {
                idx += 1;
                while digit(idx) {
                    idx += 1;
                }
            }
            Some('0') => idx += 1,
            _ => return Err(Fail::Stop(start)),
        }
        let mut is_float = false;
        if self.at(idx) == Some('.') && digit(idx + 1) {
            is_float = true;
            idx += 2;
            while digit(idx) {
                idx += 1;
            }
        }
        if matches!(self.at(idx), Some('e' | 'E')) {
            let e_start = idx;
            idx += 1;
            if matches!(self.at(idx), Some('-' | '+')) {
                idx += 1;
            }
            let digits_start = idx;
            while digit(idx) {
                idx += 1;
            }
            if idx > digits_start {
                is_float = true;
            } else {
                idx = e_start;
            }
        }
        let text: String = self.s[start..idx].iter().collect();
        if is_float {
            // Python's float(): correctly rounded, an overflow is inf (`1e999`).
            let value = text
                .parse::<f64>()
                .map_err(|_| Fail::Error(self.error("Expecting value", start)))?;
            return Ok((Value::Float(value), idx));
        }
        if let Ok(value) = text.parse::<i64>() {
            return Ok((Value::Int(value), idx));
        }
        // Python's int(): past the digit limit a ValueError at once; else an int the port does not hold.
        let digits = text.trim_start_matches('-').len();
        if digits > INT_MAX_STR_DIGITS {
            return Err(JsonError::IntDigitLimit { digits }.into());
        }
        self.deferred.push(Deferred {
            unheld: Unheld::Int(text),
            pos: start,
            alive: true,
        });
        Ok((Value::Int(0), idx))
    }

    /// `scanstring_unicode`: `end` is just past the opening quote.
    fn scanstring(&mut self, mut end: usize) -> Scan<String> {
        let begin = end - 1;
        let len = self.s.len();
        let mut out = String::new();
        loop {
            let mut next = end;
            let terminator = loop {
                let Some(c) = self.at(next) else {
                    return Err(self.error("Unterminated string starting at", begin).into());
                };
                if c == '"' || c == '\\' {
                    break c;
                }
                if c <= '\u{1f}' {
                    return Err(self.error("Invalid control character at", next).into());
                }
                next += 1;
            };
            out.extend(&self.s[end..next]);
            next += 1;
            if terminator == '"' {
                return Ok((out, next));
            }
            let Some(escape) = self.at(next) else {
                return Err(self.error("Unterminated string starting at", begin).into());
            };
            if escape != 'u' {
                end = next + 1;
                let c = match escape {
                    '"' | '\\' | '/' => escape,
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    _ => return Err(self.error("Invalid \\escape", end - 2).into()),
                };
                out.push(c);
                continue;
            }
            // `u` is at `next`; its four digits follow.
            let u_at = next;
            end = u_at + 5;
            if end > len {
                return Err(self.error("Invalid \\uXXXX escape", u_at).into());
            }
            let mut code = hex4(&self.s[u_at + 1..end])
                .ok_or_else(|| self.error("Invalid \\uXXXX escape", u_at))?;
            if (0xD800..=0xDBFF).contains(&code)
                && end + 6 < len
                && self.at(end) == Some('\\')
                && self.at(end + 1) == Some('u')
            {
                let low = hex4(&self.s[end + 2..end + 6])
                    .ok_or_else(|| self.error("Invalid \\uXXXX escape", end + 1))?;
                if (0xDC00..=0xDFFF).contains(&low) {
                    code = 0x10000 + (((code - 0xD800) << 10) | (low - 0xDC00));
                    end += 6;
                }
            }
            let c = char::from_u32(code).unwrap_or_else(|| {
                self.deferred.push(Deferred {
                    unheld: Unheld::Surrogate(code),
                    pos: u_at - 1,
                    alive: true,
                });
                char::REPLACEMENT_CHARACTER
            });
            out.push(c);
        }
    }

    /// `_parse_object_unicode`: `idx` is just past `{`.
    fn parse_object(&mut self, idx: usize) -> Scan<Value> {
        let mut dict = Dict::new();
        // Per entry, the unheld values its value holds (a range of `deferred`).
        let mut held: Vec<(usize, usize)> = Vec::new();
        let mut idx = self.skip_ws(idx);
        if self.at(idx) != Some('}') {
            loop {
                if self.at(idx) != Some('"') {
                    return Err(self
                        .error("Expecting property name enclosed in double quotes", idx)
                        .into());
                }
                let (key, after_key) = self.scanstring(idx + 1)?;
                idx = self.skip_ws(after_key);
                if self.at(idx) != Some(':') {
                    return Err(self.error("Expecting ':' delimiter", idx).into());
                }
                idx = self.skip_ws(idx + 1);
                let first = self.deferred.len();
                let (value, after_value) = self.scan_once(idx)?;
                let span = (first, self.deferred.len());
                // A duplicate key keeps its first position and takes the last value, as Python's dict does; the
                // dropped value's unheld values go with it.
                if let Some(at) = dict.get_index_of(&key) {
                    let (from, to) = held[at];
                    for dropped in &mut self.deferred[from..to] {
                        dropped.alive = false;
                    }
                    held[at] = span;
                    dict[at] = value;
                } else {
                    dict.insert(key, value);
                    held.push(span);
                }
                idx = self.skip_ws(after_value);
                if self.at(idx) == Some('}') {
                    break;
                }
                if self.at(idx) != Some(',') {
                    return Err(self.error("Expecting ',' delimiter", idx).into());
                }
                let comma = idx;
                idx = self.skip_ws(idx + 1);
                if self.at(idx) == Some('}') {
                    return Err(self
                        .error("Illegal trailing comma before end of object", comma)
                        .into());
                }
            }
        }
        Ok((Value::Dict(dict), idx + 1))
    }

    /// `_parse_array_unicode`: `idx` is just past `[`.
    fn parse_array(&mut self, idx: usize) -> Scan<Value> {
        let mut list = Vec::new();
        let mut idx = self.skip_ws(idx);
        if self.at(idx) != Some(']') {
            loop {
                let (value, after_value) = self.scan_once(idx)?;
                list.push(value);
                idx = self.skip_ws(after_value);
                if self.at(idx) == Some(']') {
                    break;
                }
                if self.at(idx) != Some(',') {
                    return Err(self.error("Expecting ',' delimiter", idx).into());
                }
                let comma = idx;
                idx = self.skip_ws(idx + 1);
                if self.at(idx) == Some(']') {
                    return Err(self
                        .error("Illegal trailing comma before end of array", comma)
                        .into());
                }
            }
        }
        Ok((Value::List(list), idx + 1))
    }
}

/// `json.loads(text)` of a `str`.
pub(crate) fn loads(text: &str) -> Result<Value, JsonError> {
    let s: Vec<char> = text.chars().collect();
    let mut scanner = Scanner {
        s: &s,
        depth: 0,
        deferred: Vec::new(),
    };
    if s.first() == Some(&'\u{feff}') {
        return Err(scanner.error("Unexpected UTF-8 BOM (decode using utf-8-sig)", 0));
    }
    let idx = scanner.skip_ws(0);
    let (value, end) = match scanner.scan_once(idx) {
        Ok(found) => found,
        Err(Fail::Stop(pos)) => return Err(scanner.error("Expecting value", pos)),
        Err(Fail::Error(error)) => return Err(error),
    };
    let end = scanner.skip_ws(end);
    if end != s.len() {
        return Err(scanner.error("Extra data", end));
    }
    if let Some(first) = scanner.deferred.iter().find(|deferred| deferred.alive) {
        let pos = first.pos;
        let (lineno, colno) = scanner.line_col(pos);
        return Err(match &first.unheld {
            Unheld::Int(text) => JsonError::IntOutOfRange {
                text: text.clone(),
                pos,
                lineno,
                colno,
            },
            Unheld::Surrogate(code) => JsonError::LoneSurrogate {
                code: *code,
                pos,
                lineno,
                colno,
            },
        });
    }
    Ok(value)
}

/// `json.dumps` keyword arguments; the default is `json.dumps(value)`'s.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DumpOptions {
    /// `ensure_ascii` (default `True`): escape every character outside `' '..='~'`, astral ones as a surrogate pair.
    pub(crate) ensure_ascii: bool,
}

impl Default for DumpOptions {
    fn default() -> Self {
        Self { ensure_ascii: true }
    }
}

fn push_hex4(out: &mut String, unit: u32) {
    out.push_str(&format!("\\u{unit:04x}"));
}

/// `json.dumps(s)` of a string: `"é"`, `"😀"`, `/`, `'`, `<`, `>` and `&` as they are.
fn push_json_str(out: &mut String, s: &str, ensure_ascii: bool) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            _ if c < ' ' => push_hex4(out, u32::from(c)),
            _ if ensure_ascii && !(' '..='~').contains(&c) => {
                let mut units = [0; 2];
                for unit in c.encode_utf16(&mut units) {
                    push_hex4(out, u32::from(*unit));
                }
            }
            _ => out.push(c),
        }
    }
    out.push('"');
}

fn push_json(out: &mut String, value: &Value, opts: DumpOptions) {
    match value {
        Value::None => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int(i) => out.push_str(&i.to_string()),
        Value::Float(f) => out.push_str(&float_json(*f)),
        Value::Str(s) => push_json_str(out, s, opts.ensure_ascii),
        Value::List(items) if items.is_empty() => out.push_str("[]"),
        Value::List(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push_str(", ");
                }
                push_json(out, item, opts);
            }
            out.push(']');
        }
        Value::Dict(dict) if dict.is_empty() => out.push_str("{}"),
        Value::Dict(dict) => {
            out.push('{');
            for (at, (key, item)) in dict.iter().enumerate() {
                if at > 0 {
                    out.push_str(", ");
                }
                push_json_str(out, key, opts.ensure_ascii);
                out.push_str(": ");
                push_json(out, item, opts);
            }
            out.push('}');
        }
    }
}

/// `json.dumps(value, ...)` with the given keyword arguments.
pub(crate) fn dumps(value: &Value, opts: DumpOptions) -> String {
    let mut out = String::new();
    push_json(&mut out, value, opts);
    out
}

/// `json.dumps(s)` of a string, with the defaults (about ninety generator calls).
pub(crate) fn dumps_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    push_json_str(&mut out, s, true);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each row: python3 -c "import json; print(json.loads(TEXT))" on nelly (Python 3.14.7), the decoded value's
    // repr or the JSONDecodeError's str().
    const LOADS_CASES: &[(&str, &str)] = &[
        ("", "ERR Expecting value: line 1 column 1 (char 0)"),
        (" ", "ERR Expecting value: line 1 column 2 (char 1)"),
        (
            "{",
            "ERR Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
        ),
        ("[", "ERR Expecting value: line 1 column 2 (char 1)"),
        (
            "{\"a\"",
            "ERR Expecting ':' delimiter: line 1 column 5 (char 4)",
        ),
        ("{\"a\":", "ERR Expecting value: line 1 column 6 (char 5)"),
        ("{\"a\": }", "ERR Expecting value: line 1 column 7 (char 6)"),
        (
            "{\"a\" 1}",
            "ERR Expecting ':' delimiter: line 1 column 6 (char 5)",
        ),
        (
            "{\"a\": 1",
            "ERR Expecting ',' delimiter: line 1 column 8 (char 7)",
        ),
        (
            "{\"a\": 1 \"b\": 2}",
            "ERR Expecting ',' delimiter: line 1 column 9 (char 8)",
        ),
        (
            "{\"a\": 1,}",
            "ERR Illegal trailing comma before end of object: line 1 column 8 (char 7)",
        ),
        (
            "[1,]",
            "ERR Illegal trailing comma before end of array: line 1 column 3 (char 2)",
        ),
        (
            "[1 2]",
            "ERR Expecting ',' delimiter: line 1 column 4 (char 3)",
        ),
        (
            "[1",
            "ERR Expecting ',' delimiter: line 1 column 3 (char 2)",
        ),
        (
            "{1: 2}",
            "ERR Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
        ),
        (
            "{\"a\": 1,  }",
            "ERR Illegal trailing comma before end of object: line 1 column 8 (char 7)",
        ),
        (
            "[1,  ]",
            "ERR Illegal trailing comma before end of array: line 1 column 3 (char 2)",
        ),
        (
            "\"abc",
            "ERR Unterminated string starting at: line 1 column 1 (char 0)",
        ),
        (
            "\"a\\",
            "ERR Unterminated string starting at: line 1 column 1 (char 0)",
        ),
        ("\"a\\x\"", "ERR Invalid \\escape: line 1 column 3 (char 2)"),
        (
            "\"\\u12\"",
            "ERR Invalid \\uXXXX escape: line 1 column 3 (char 2)",
        ),
        (
            "\"\\u12",
            "ERR Invalid \\uXXXX escape: line 1 column 3 (char 2)",
        ),
        (
            "\"\\u123\"",
            "ERR Invalid \\uXXXX escape: line 1 column 3 (char 2)",
        ),
        (
            "\"\\u1234",
            "ERR Unterminated string starting at: line 1 column 1 (char 0)",
        ),
        (
            "\"\\uZZZZ\"",
            "ERR Invalid \\uXXXX escape: line 1 column 3 (char 2)",
        ),
        (
            "\"\\ud800\\uZZZZ\"",
            "ERR Invalid \\uXXXX escape: line 1 column 9 (char 8)",
        ),
        ("\"\\ud800\\udc00\"", "OK '\u{10000}'"),
        (
            "\"\\ud800\\udc00",
            "ERR Unterminated string starting at: line 1 column 1 (char 0)",
        ),
        (
            "\"\\ud800\\u",
            "ERR Invalid \\uXXXX escape: line 1 column 9 (char 8)",
        ),
        (
            "\"\\ud800\\x\"",
            "ERR Invalid \\escape: line 1 column 8 (char 7)",
        ),
        (
            "\"\\uDC00\\uZZZZ\"",
            "ERR Invalid \\uXXXX escape: line 1 column 9 (char 8)",
        ),
        (
            "\"a\u{1}b\"",
            "ERR Invalid control character at: line 1 column 3 (char 2)",
        ),
        (
            "\"a\u{a}b\"",
            "ERR Invalid control character at: line 1 column 3 (char 2)",
        ),
        ("\"\u{7f}\"", "OK '\\x7f'"),
        ("nul", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("null", "OK None"),
        ("nulll", "ERR Extra data: line 1 column 5 (char 4)"),
        ("tru", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("True", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("NaN", "OK nan"),
        ("Nan", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("Infinity", "OK inf"),
        ("-Infinity", "OK -inf"),
        ("-Inf", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("-", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("-a", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("01", "ERR Extra data: line 1 column 2 (char 1)"),
        ("1.", "ERR Extra data: line 1 column 2 (char 1)"),
        ("1.e5", "ERR Extra data: line 1 column 2 (char 1)"),
        ("1e", "ERR Extra data: line 1 column 2 (char 1)"),
        ("1e+", "ERR Extra data: line 1 column 2 (char 1)"),
        ("1E5", "OK 100000.0"),
        ("1e-7", "OK 1e-07"),
        ("-0", "OK 0"),
        ("-0.0", "OK -0.0"),
        ("1e999", "OK inf"),
        (".5", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("+1", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("{\"a\": 1}x", "ERR Extra data: line 1 column 9 (char 8)"),
        ("{\"a\": 1} ", "OK {'a': 1}"),
        (
            "{\"a\": 1}\u{a}\u{a} x",
            "ERR Extra data: line 3 column 2 (char 11)",
        ),
        (
            "\u{feff}{}",
            "ERR Unexpected UTF-8 BOM (decode using utf-8-sig): line 1 column 1 (char 0)",
        ),
        (
            "\u{a}\u{a}  {\"a\": [1, 2,\u{a}  ]}",
            "ERR Illegal trailing comma before end of array: line 3 column 14 (char 15)",
        ),
        (
            "{\"a\": 1,\u{a} \"b\"\u{a} 2}",
            "ERR Expecting ':' delimiter: line 3 column 2 (char 15)",
        ),
        ("{\"a\":1,\"b\":2,\"a\":3}", "OK {'a': 3, 'b': 2}"),
        (
            "[\u{a}\u{a}\u{a}  \"\\q\"]",
            "ERR Invalid \\escape: line 4 column 4 (char 7)",
        ),
        (
            "{\u{a}\"\u{e9}\": \"\\u00e9\u{1f600}\", \"x\": tru}",
            "ERR Expecting value: line 2 column 22 (char 23)",
        ),
        (
            "\"\u{9}\"",
            "ERR Invalid control character at: line 1 column 2 (char 1)",
        ),
        (
            "[1,\u{a}2,,]",
            "ERR Expecting value: line 2 column 3 (char 6)",
        ),
        ("{\"a\":1}{", "ERR Extra data: line 1 column 8 (char 7)"),
        ("[] []", "ERR Extra data: line 1 column 4 (char 3)"),
        ("123abc", "ERR Extra data: line 1 column 4 (char 3)"),
        ("1 2", "ERR Extra data: line 1 column 3 (char 2)"),
        ("nan", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("[NaN, Infinity, -Infinity]", "OK [nan, inf, -inf]"),
        (
            "{\"a\": {\"b\": [1, {\"c\": nul}]}}",
            "ERR Expecting value: line 1 column 23 (char 22)",
        ),
        ("[-]", "ERR Expecting value: line 1 column 2 (char 1)"),
        ("[-0]", "OK [0]"),
        (
            "\"\\/\\b\\f\\n\\r\\t\\\"\\\\\"",
            "OK '/\\x08\\x0c\\n\\r\\t\"\\\\'",
        ),
        ("\"\u{1f600}\"", "OK '\u{1f600}'"),
        ("\"\\uD83D\\uDE00\"", "OK '\u{1f600}'"),
        (
            " \u{9}\u{d}\u{a}[ \u{9}\u{d}\u{a}1 \u{9}\u{d}\u{a}] \u{9}\u{d}\u{a}",
            "OK [1]",
        ),
        ("\u{a0}[]", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("[1]\u{a0}", "ERR Extra data: line 1 column 4 (char 3)"),
        ("{\"a\" : 1 , \"b\":[ ] }", "OK {'a': 1, 'b': []}"),
        ("\"\\u00e9\\u4e00\"", "OK '\u{e9}\u{4e00}'"),
        ("1.5e+3", "OK 1500.0"),
        ("1.5E-3", "OK 0.0015"),
        ("-12.5e2", "OK -1250.0"),
        ("0.1", "OK 0.1"),
        ("1e400", "OK inf"),
        ("-1e400", "OK -inf"),
        (
            "[1e5,]",
            "ERR Illegal trailing comma before end of array: line 1 column 5 (char 4)",
        ),
        (
            "{\"\u{e9}\u{1f600}\": \"\u{1f600}\"}\u{a}\u{1f600}",
            "ERR Extra data: line 2 column 1 (char 12)",
        ),
        (
            "\"\u{1f600}\u{a}\"",
            "ERR Invalid control character at: line 1 column 3 (char 2)",
        ),
        ("[true,false,null]", "OK [True, False, None]"),
        (
            "[truex]",
            "ERR Expecting ',' delimiter: line 1 column 6 (char 5)",
        ),
        ("fals", "ERR Expecting value: line 1 column 1 (char 0)"),
        ("falsey", "ERR Extra data: line 1 column 6 (char 5)"),
        (
            "{\"a\":1,}",
            "ERR Illegal trailing comma before end of object: line 1 column 7 (char 6)",
        ),
        (
            "{,}",
            "ERR Expecting property name enclosed in double quotes: line 1 column 2 (char 1)",
        ),
        ("[,]", "ERR Expecting value: line 1 column 2 (char 1)"),
        (
            "{\"a\":1 , }",
            "ERR Illegal trailing comma before end of object: line 1 column 8 (char 7)",
        ),
    ];

    #[test]
    fn loads_matches_python() {
        for (text, expected) in LOADS_CASES {
            let got = match loads(text) {
                Ok(value) => format!("OK {}", value.repr()),
                Err(error) => format!("ERR {error}"),
            };
            assert_eq!(got, *expected, "{text:?}");
        }
    }

    // python3 -c "import json; print(json.loads('{\"a\":1,\"b\":2,\"a\":3}'), repr(json.loads('[1, 1.0, 1e3, -0, -0.0]')))"
    // prints: {'a': 3, 'b': 2} [1, 1.0, 1000.0, 0, -0.0]
    #[test]
    fn loads_keeps_python_types_and_order() {
        let value = loads(r#"{"a":1,"b":2,"a":3}"#).expect("valid");
        let keys: Vec<&String> = value.as_dict().expect("a dict").keys().collect();
        assert_eq!(keys, ["a", "b"]);
        assert_eq!(value.repr(), "{'a': 3, 'b': 2}");
        assert_eq!(
            loads("[1, 1.0, 1e3, -0, -0.0]").expect("valid").repr(),
            "[1, 1.0, 1000.0, 0, -0.0]"
        );
        assert!(matches!(loads("1").expect("valid"), Value::Int(1)));
        assert!(matches!(loads("1.0").expect("valid"), Value::Float(_)));
    }

    #[test]
    fn loads_refuses_what_rust_cannot_hold() {
        let error = loads("[\n 99999999999999999999]").expect_err("outside i64");
        assert_eq!(
            error.into_error("x.json").to_string(),
            "ValueError: x.json: the integer 99999999999999999999 at line 2 column 2 (char 3) is outside the 64-bit \
             range the Rust SDK generator reads"
        );
        assert!(matches!(
            loads("-9223372036854775808").expect("i64::MIN"),
            Value::Int(i64::MIN)
        ));
        let error = loads(r#""\ud800""#).expect_err("lone surrogate");
        assert_eq!(
            error.into_error("x.json").to_string(),
            "ValueError: x.json: the escape \\ud800 at line 1 column 2 (char 1) is a lone surrogate, which the Rust \
             SDK generator cannot hold in a string"
        );
        assert!(
            matches!(loads(r#""\ud800\udc00""#).expect("a pair"), Value::Str(s) if s == "\u{10000}")
        );
    }

    // Python 3.14.7 on nelly: json.loads of each text (Sol's G1a review, P1-2 and P1-3). A text Python refuses fails
    // with Python's error first; a value a duplicate key drops is not refused; past 4,300 digits Python's own
    // ValueError comes at once, before a later syntax error.
    #[test]
    fn unheld_values_are_refused_only_when_they_survive() {
        let error =
            loads(r#"{"name":"x","extra":9223372036854775808,}"#).expect_err("trailing comma");
        assert_eq!(
            error.to_string(),
            "Illegal trailing comma before end of object: line 1 column 40 (char 39)"
        );
        let error = loads(r#"{"name":"x","extra":"\ud800",}"#).expect_err("trailing comma");
        assert_eq!(
            error.to_string(),
            "Illegal trailing comma before end of object: line 1 column 29 (char 28)"
        );
        // python3 -c "import json; print(json.loads('{\"name\":\"x\",\"discard\":\"\\\\ud800\",\"discard\":\"ok\"}'))"
        // prints: {'name': 'x', 'discard': 'ok'}
        let value = loads(r#"{"name":"x","discard":"\ud800","discard":"ok"}"#).expect("dropped");
        assert_eq!(value.repr(), "{'name': 'x', 'discard': 'ok'}");
        let value =
            loads(r#"{"a": {"b": [99999999999999999999]}, "c": 1, "a": 2}"#).expect("dropped");
        assert_eq!(value.repr(), "{'a': 2, 'c': 1}");
        let error =
            loads(r#"{"a": 1, "a": 99999999999999999999, "b": "\udc00"}"#).expect_err("kept");
        assert!(
            matches!(error, JsonError::IntOutOfRange { pos: 14, .. }),
            "{error:?}"
        );
        let error = loads(r#"{"\ud800": 1, "a": 1, "a": 2}"#).expect_err("a key survives");
        assert!(
            matches!(error, JsonError::LoneSurrogate { pos: 2, .. }),
            "{error:?}"
        );
        // python3 -c "import json; json.loads('[' + '1' * 4301 + ',]')": the traceback's last line.
        let error = loads(&format!("[{},]", "1".repeat(4301))).expect_err("digit limit");
        assert_eq!(
            error.into_error("x.json").to_string(),
            "ValueError: Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits; use \
             sys.set_int_max_str_digits() to increase the limit"
        );
        let error = loads(&format!("-{}", "1".repeat(4301))).expect_err("digit limit");
        assert!(matches!(error, JsonError::IntDigitLimit { digits: 4301 }));
        assert!(matches!(
            loads(&"1".repeat(4300)).expect_err("outside i64"),
            JsonError::IntOutOfRange { .. }
        ));
        assert!(
            matches!(loads(&format!("{}.5", "1".repeat(4301))).expect("a float"), Value::Float(f) if f.is_infinite())
        );
    }

    #[test]
    fn loads_refuses_nesting_past_max_depth() {
        let deep = std::thread::Builder::new()
            .stack_size(256 << 20)
            .spawn(|| {
                let ok = loads(&format!(
                    "{}{}",
                    "[".repeat(MAX_DEPTH),
                    "]".repeat(MAX_DEPTH)
                ))
                .is_ok();
                let error = loads(&format!(
                    "{}{}",
                    "[".repeat(MAX_DEPTH + 1),
                    "]".repeat(MAX_DEPTH + 1)
                ))
                .expect_err("too deep")
                .into_error("x.json")
                .to_string();
                (ok, error)
            })
            .expect("a thread")
            .join()
            .expect("no panic");
        assert!(deep.0);
        assert_eq!(
            deep.1,
            "RecursionError: maximum recursion depth exceeded while decoding a JSON array from a unicode string"
        );
    }

    fn sample() -> Value {
        loads(DUMPS_SAMPLE).expect("valid sample")
    }

    const DUMPS_SAMPLE: &str = r#"{"z": 1, "a": [1.0, 1e16, 1e-7, -0.0, NaN, Infinity, -Infinity, true, false, null],
        "s": "é\u0000\b\t\n\f\r\u001f/\\\"😀 \u007f<>&'", "e": {}, "l": [], "n": {"b": [[]], "a": {"c": "x"}}}"#;

    // python3 -c "import json; v = json.loads(SAMPLE); print(json.dumps(v)); print(json.dumps(v, ensure_ascii=False))"
    // with SAMPLE the text of DUMPS_SAMPLE.
    #[test]
    fn dumps_matches_python() {
        let value = sample();
        assert_eq!(dumps(&value, DumpOptions::default()), DUMPS_DEFAULT);
        assert_eq!(
            dumps(
                &value,
                DumpOptions {
                    ensure_ascii: false,
                }
            ),
            DUMPS_UNICODE
        );
        // python3 -c "import json; print(json.dumps('café \U0001f600 \x7f'))"
        assert_eq!(
            dumps_str("café 😀 \u{7f}"),
            "\"caf\\u00e9 \\ud83d\\ude00 \\u007f\""
        );
    }

    const DUMPS_DEFAULT: &str = "{\"z\": 1, \"a\": [1.0, 1e+16, 1e-07, -0.0, NaN, Infinity, -Infinity, true, false, null], \"s\": \"\\u00e9\\u0000\\b\\t\\n\\f\\r\\u001f/\\\\\\\"\\ud83d\\ude00\\u2028\\u007f<>&'\", \"e\": {}, \"l\": [], \"n\": {\"b\": [[]], \"a\": {\"c\": \"x\"}}}";
    const DUMPS_UNICODE: &str = "{\"z\": 1, \"a\": [1.0, 1e+16, 1e-07, -0.0, NaN, Infinity, -Infinity, true, false, null], \"s\": \"\u{e9}\\u0000\\b\\t\\n\\f\\r\\u001f/\\\\\\\"\u{1f600}\u{2028}\u{7f}<>&'\", \"e\": {}, \"l\": [], \"n\": {\"b\": [[]], \"a\": {\"c\": \"x\"}}}";
}
