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
mod tests;
