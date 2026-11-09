//! Python's `re` where Rust's `regex` differs (brief H2).
//!
//! - The five patterns that use look-around (which `regex` lacks), each a hand-written function beside its pattern.
//! - Python's `\w` and `\s` (`str.isalnum()` plus `_`; `str.isspace()`), which are not Rust's Unicode classes:
//!   `translate` rewrites them in a pattern.
//! - Python's `\b` and `\B`, which `regex` spells with Rust's word class (`text::is_word` lists where it differs):
//!   `translate` and `compile` refuse them, and `PyRegex` matches a pattern holding them with Python's boundaries.
//! - Python's replacement templates (`re.sub(pattern, template, text)`): backslash escapes and `\g<0>`.
//!
//! Python's `$` (without `re.M`) also matches before a final newline; `translate` leaves it alone, so a caller whose
//! text can end in `\n` writes `\n?\z` or checks by hand. `re.match` anchors at the start only, `re.fullmatch` at both
//! ends (`compile_fullmatch`).

use std::borrow::Cow;
use std::sync::LazyLock;

use regex::Regex;

use crate::error::GenerateError;
use crate::py::json::INT_MAX_STR_DIGITS;
use crate::py::text::{is_decimal, is_word, isidentifier, repr_str};

/// The body of Python's `\w` for a character class: `str.isalnum()` (categories L and N) and `_`.
pub(crate) const WORD_CLASS: &str = r"\p{L}\p{N}_";

/// The body of Python's `\s` for a character class: `str.isspace()`.
pub(crate) const SPACE_CLASS: &str = r"\t\n\x0B\x0C\r\x1C-\x20\x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}";

/// A Python pattern in `regex` syntax: `\w`, `\W`, `\s` and `\S` become Python's classes (inside a character class
/// too); inside a class, `\b` (a backspace to Python) becomes `\x08`, and `[` (a nested class to `regex`), a first
/// `]`, `&` and `~` (set operators to `regex`) are escaped. Everything else is copied.
///
/// Panics on a `\b` or `\B` outside a class: `regex` would read it with Rust's word class, so the pattern goes through
/// `PyRegex`, which keeps Python's. The generator's patterns are constants, so this fails a test, never an input.
pub(crate) fn translate(pattern: &str) -> String {
    let (translated, boundaries) = translate_keeping_boundaries(pattern);
    assert!(
        !boundaries,
        "{pattern:?} holds \\b or \\B, whose word class regex does not share with Python: use py::re::PyRegex"
    );
    translated
}

/// `translate`, with a `\b` or `\B` outside a class kept as `regex`'s, and whether the pattern holds one.
fn translate_keeping_boundaries(pattern: &str) -> (String, bool) {
    let mut boundaries = false;
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::with_capacity(pattern.len() + 16);
    let mut in_class = false;
    let mut at = 0;
    while at < chars.len() {
        let c = chars[at];
        at += 1;
        if c == '\\' {
            match chars.get(at) {
                Some(&escape @ ('w' | 'W' | 's' | 'S')) => {
                    let body = if matches!(escape, 'w' | 'W') {
                        WORD_CLASS
                    } else {
                        SPACE_CLASS
                    };
                    let negated = matches!(escape, 'W' | 'S');
                    if in_class && !negated {
                        out.push_str(body);
                    } else {
                        out.push_str(&format!("[{}{body}]", if negated { "^" } else { "" }));
                    }
                }
                Some(&'b') if in_class => out.push_str(r"\x08"),
                Some(&other) => {
                    boundaries |= !in_class && matches!(other, 'b' | 'B');
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
            at += 1;
            continue;
        }
        if !in_class && c == '[' {
            in_class = true;
            out.push('[');
            if chars.get(at) == Some(&'^') {
                out.push('^');
                at += 1;
            }
            if chars.get(at) == Some(&']') {
                out.push_str(r"\]");
                at += 1;
            }
            continue;
        }
        if in_class {
            match c {
                '[' | '&' | '~' => {
                    out.push('\\');
                    out.push(c);
                    continue;
                }
                ']' => in_class = false,
                _ => {}
            }
        }
        out.push(c);
    }
    (out, boundaries)
}

/// `re.compile(pattern)` of a constant Python pattern, translated.
pub(crate) fn compile(pattern: &str) -> Regex {
    Regex::new(&translate(pattern)).expect("a constant pattern")
}

/// A constant Python pattern for `re.fullmatch`: translated and anchored at both ends.
pub(crate) fn compile_fullmatch(pattern: &str) -> Regex {
    Regex::new(&format!(r"\A(?:{})\z", translate(pattern))).expect("a constant pattern")
}

/// Rust's `\w` (Alphabetic, marks, Nd, connector punctuation, join controls), the class `regex`'s `\b` reads.
static RUST_WORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\w").expect("a constant class"));

/// The character `PyRegex` matches in place of `c`, when Rust's and Python's word classes disagree on it: one of the
/// same UTF-8 length that both classes see as Python sees `c`, and that every class a translated ASCII pattern can
/// name (`\w`, `\s`, `\d`, ASCII sets, `.`) takes or refuses as it does `c`. ASCII never differs.
fn boundary_stand_in(c: char) -> Option<char> {
    if c.is_ascii() {
        return None;
    }
    let python = is_word(c);
    if python == RUST_WORD.is_match(c.encode_utf8(&mut [0; 4])) {
        return None;
    }
    // A Python word character (a number of category No: `²`) stands in as a letter (Lo); a Python non-word one (a
    // mark, a connector, a join control) as punctuation or a symbol (Po, So). None is Nd, a space or a newline.
    Some(match (python, c.len_utf8()) {
        (true, 2) => '\u{AA}',
        (true, 3) => '\u{4E00}',
        (true, _) => '\u{20000}',
        (false, 2) => '\u{A7}',
        (false, 3) => '\u{2030}',
        (false, _) => '\u{1F600}',
    })
}

/// A Python pattern with Python's `\b` and `\B` (and its `\w`, `\s`): `regex`'s word boundary reads Rust's word
/// class, so a text holding a character the two classes disagree on is matched as a copy in which that character
/// stands in for one both classes see as Python sees it (`boundary_stand_in`). The stand-ins keep each character's
/// UTF-8 length, so every offset into the copy is the same offset into the text; the methods return offsets, and a
/// caller slices its own text. Only ASCII patterns (the generator's) are taken.
pub(crate) struct PyRegex {
    re: Regex,
    boundaries: bool,
}

impl PyRegex {
    fn build(pattern: &str, anchored: bool) -> Self {
        assert!(
            pattern.is_ascii(),
            "{pattern:?}: PyRegex takes ASCII patterns"
        );
        let (translated, boundaries) = translate_keeping_boundaries(pattern);
        let translated = if anchored {
            format!(r"\A(?:{translated})\z")
        } else {
            translated
        };
        Self {
            re: Regex::new(&translated).expect("a constant pattern"),
            boundaries,
        }
    }

    /// `re.compile(pattern)`.
    pub(crate) fn new(pattern: &str) -> Self {
        Self::build(pattern, false)
    }

    /// A pattern for `re.fullmatch`.
    pub(crate) fn fullmatch(pattern: &str) -> Self {
        Self::build(pattern, true)
    }

    /// The text `regex` reads: `text` itself, or its copy with the stand-ins.
    fn haystack<'t>(&self, text: &'t str) -> Cow<'t, str> {
        if !self.boundaries || !text.chars().any(|c| boundary_stand_in(c).is_some()) {
            return Cow::Borrowed(text);
        }
        Cow::Owned(
            text.chars()
                .map(|c| boundary_stand_in(c).unwrap_or(c))
                .collect(),
        )
    }

    /// `pattern.search(text) is not None` (or `fullmatch` for a `PyRegex::fullmatch`).
    pub(crate) fn is_match(&self, text: &str) -> bool {
        self.re.is_match(&self.haystack(text))
    }

    /// `pattern.search(text, pos)`: the first match at or after byte offset `start`, as a byte range of `text`.
    pub(crate) fn search_at(&self, text: &str, start: usize) -> Option<(usize, usize)> {
        self.re
            .find_at(&self.haystack(text), start)
            .map(|found| (found.start(), found.end()))
    }

    /// `pattern.finditer(text)`: each match's byte range in `text`.
    pub(crate) fn find_iter(&self, text: &str) -> Vec<(usize, usize)> {
        self.re
            .find_iter(&self.haystack(text))
            .map(|found| (found.start(), found.end()))
            .collect()
    }

    /// `pattern.finditer(text)` with its groups: per match, each group's byte range in `text` (group 0 first).
    pub(crate) fn captures_iter(&self, text: &str) -> Vec<Vec<Option<(usize, usize)>>> {
        self.re
            .captures_iter(&self.haystack(text))
            .map(|captures| {
                captures
                    .iter()
                    .map(|group| group.map(|found| (found.start(), found.end())))
                    .collect()
            })
            .collect()
    }
}

fn char_before(text: &str, at: usize) -> Option<char> {
    text[..at].chars().next_back()
}

fn char_at(text: &str, at: usize) -> Option<char> {
    text[at..].chars().next()
}

/// `facade_types.py:257` `re.sub(r'(?<!^)(?=[A-Z])', '_', name)`: `_` before every ASCII capital but a first one.
pub(crate) fn sub_underscore_before_capitals(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (at, c) in name.char_indices() {
        if at > 0 && c.is_ascii_uppercase() {
            out.push('_');
        }
        out.push(c);
    }
    out
}

/// `uniffi_types.py:96` `re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', key)`: `_` between an ASCII lower-case letter or digit
/// and an ASCII capital.
pub(crate) fn sub_underscore_at_case_rise(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    let mut previous: Option<char> = None;
    for c in key.chars() {
        if c.is_ascii_uppercase()
            && previous.is_some_and(|p| p.is_ascii_lowercase() || p.is_ascii_digit())
        {
            out.push('_');
        }
        out.push(c);
        previous = Some(c);
    }
    out
}

/// `generate.py:805` `re.findall(r'(?<![\w.])(\w+)\(', body)`: each word called as a function, not after a `.` or
/// another word character, in order (repeats kept).
pub(crate) fn findall_called_words(body: &str) -> Vec<&str> {
    let mut found = Vec::new();
    let mut at = 0;
    while let Some(c) = char_at(body, at) {
        let free_before = char_before(body, at).is_none_or(|p| !is_word(p) && p != '.');
        if !(is_word(c) && free_before) {
            at += c.len_utf8();
            continue;
        }
        // `\w+` is greedy and only `(` may follow it, so the whole run of word characters must be followed by `(`;
        // no later start inside the run passes the look-behind.
        let end = body[at..]
            .find(|ch: char| !is_word(ch))
            .map_or(body.len(), |len| at + len);
        if body[end..].starts_with('(') {
            found.push(&body[at..end]);
            at = end + 1;
        } else {
            at = end;
        }
    }
    found
}

/// `generate.py:1384` `re.search(r'(?<![\w"])invalid(?![\w"])', body) is not None`: the word `invalid` with no word
/// character or `"` on either side.
pub(crate) fn search_bare_invalid(body: &str) -> bool {
    let free = |c: Option<char>| c.is_none_or(|c| !is_word(c) && c != '"');
    body.match_indices("invalid")
        .any(|(at, word)| free(char_before(body, at)) && free(char_at(body, at + word.len())))
}

/// The leftmost non-overlapping occurrences of `needle` that `accept(start, end)` takes, as byte ranges: what a
/// regular expression made of the literal and zero-width conditions around it finds.
fn literal_matches(
    text: &str,
    needle: &str,
    accept: impl Fn(usize, usize) -> bool,
) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(offset) = text[from..].find(needle) {
        let start = from + offset;
        let end = start + needle.len();
        if accept(start, end) {
            found.push((start, end));
            from = end;
        } else {
            from = start + char_at(text, start).map_or(1, char::len_utf8);
        }
    }
    found
}

/// `generate.py:2439` `re.sub(r'&\binput\b(?!\.)', value_input, checks)`: every `&input` that ends a word and is not
/// followed by `.` becomes `value_input` (a Python replacement template).
pub(crate) fn sub_whole_input_borrow(
    checks: &str,
    value_input: &str,
) -> Result<String, GenerateError> {
    // `&\b`: `&` is no word character and `i` is one, so that boundary always holds.
    let matches = literal_matches(checks, "&input", |_, end| {
        char_at(checks, end).is_none_or(|c| !is_word(c) && c != '.')
    });
    sub_matches(checks, &matches, value_input)
}

/// `generate.py:2440` `re.sub(r'\binput\b', value_input, checks)`: every whole word `input` becomes `value_input`.
pub(crate) fn sub_input_word(checks: &str, value_input: &str) -> Result<String, GenerateError> {
    let matches = literal_matches(checks, "input", |start, end| {
        char_before(checks, start).is_none_or(|c| !is_word(c))
            && char_at(checks, end).is_none_or(|c| !is_word(c))
    });
    sub_matches(checks, &matches, value_input)
}

/// One piece of a parsed replacement template.
enum Piece {
    Literal(String),
    /// `\g<0>`: the whole match (the only group the generator's substitution patterns have).
    Match,
}

/// `re.sub(<pattern>, template, text)` given the pattern's matches: the template is parsed first (its errors come
/// even when nothing matches), and a template with no backslash is literal.
fn sub_matches(
    text: &str,
    matches: &[(usize, usize)],
    template: &str,
) -> Result<String, GenerateError> {
    let pieces = if template.contains('\\') {
        parse_template(template)?
    } else {
        vec![Piece::Literal(template.to_owned())]
    };
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for &(start, end) in matches {
        out.push_str(&text[last..start]);
        for piece in &pieces {
            match piece {
                Piece::Literal(literal) => out.push_str(literal),
                Piece::Match => out.push_str(&text[start..end]),
            }
        }
        last = end;
    }
    out.push_str(&text[last..]);
    Ok(out)
}

/// `re.PatternError(msg, pattern, pos)`: `<msg> at position <pos>`, with the line and column when the pattern holds
/// a newline.
fn pattern_error(msg: &str, pattern: &str, pos: usize) -> GenerateError {
    let mut text = format!("{msg} at position {pos}");
    if pattern.contains('\n') {
        let before: Vec<char> = pattern.chars().take(pos).collect();
        let lineno = before.iter().filter(|&&c| c == '\n').count() + 1;
        let colno = before
            .iter()
            .rposition(|&c| c == '\n')
            .map_or(pos + 1, |nl| pos - nl);
        text = format!("{text} (line {lineno}, column {colno})");
    }
    GenerateError::exception("re.PatternError", text)
}

/// Python's `re._parser.Tokenizer` over a replacement template: a token is one character, or a backslash and the
/// character after it; `next` is read one token ahead, so a trailing lone backslash fails as soon as it is next.
struct Tokenizer<'a> {
    source: &'a str,
    chars: Vec<char>,
    index: usize,
    next: Option<String>,
}

impl<'a> Tokenizer<'a> {
    fn new(source: &'a str) -> Result<Self, GenerateError> {
        let mut tokenizer = Self {
            source,
            chars: source.chars().collect(),
            index: 0,
            next: None,
        };
        tokenizer.advance()?;
        Ok(tokenizer)
    }

    /// `__next`.
    fn advance(&mut self) -> Result<(), GenerateError> {
        let Some(&c) = self.chars.get(self.index) else {
            self.next = None;
            return Ok(());
        };
        let mut token = c.to_string();
        let mut index = self.index;
        if c == '\\' {
            index += 1;
            let Some(&escaped) = self.chars.get(index) else {
                return Err(pattern_error(
                    "bad escape (end of pattern)",
                    self.source,
                    self.chars.len() - 1,
                ));
            };
            token.push(escaped);
        }
        self.index = index + 1;
        self.next = Some(token);
        Ok(())
    }

    fn get(&mut self) -> Result<Option<String>, GenerateError> {
        let this = self.next.take();
        self.advance()?;
        Ok(this)
    }

    fn next_is_one_of(&self, set: &str) -> bool {
        self.next
            .as_deref()
            .is_some_and(|next| next.chars().count() == 1 && set.contains(next))
    }

    /// `match(char)`.
    fn take(&mut self, c: char) -> Result<bool, GenerateError> {
        if self
            .next
            .as_deref()
            .is_some_and(|next| next.chars().eq([c]))
        {
            self.advance()?;
            return Ok(true);
        }
        Ok(false)
    }

    fn tell(&self) -> usize {
        self.index - self.next.as_deref().map_or(0, |next| next.chars().count())
    }

    fn error(&self, msg: &str, offset: usize) -> GenerateError {
        pattern_error(msg, self.source, self.tell() - offset)
    }

    fn getuntil(&mut self, terminator: char, name: &str) -> Result<String, GenerateError> {
        let mut result = String::new();
        loop {
            let c = self.next.take();
            self.advance()?;
            match c {
                None if result.is_empty() => return Err(self.error(&format!("missing {name}"), 0)),
                None => {
                    let len = result.chars().count();
                    return Err(
                        self.error(&format!("missing {terminator}, unterminated name"), len)
                    );
                }
                Some(c) if c.chars().eq([terminator]) => {
                    if result.is_empty() {
                        return Err(self.error(&format!("missing {name}"), 1));
                    }
                    return Ok(result);
                }
                Some(c) => result.push_str(&c),
            }
        }
    }
}

/// `addgroup(index, pos)` for a pattern with no groups: only group 0, the whole match, exists.
fn add_group(
    s: &Tokenizer<'_>,
    digits: &str,
    pos: usize,
    literal: &mut String,
    pieces: &mut Vec<Piece>,
) -> Result<(), GenerateError> {
    let index = digits.trim_start_matches('0');
    if !index.is_empty() {
        return Err(s.error(&format!("invalid group reference {index}"), pos));
    }
    pieces.push(Piece::Literal(std::mem::take(literal)));
    pieces.push(Piece::Match);
    Ok(())
}

/// `re._parser.parse_template(source, pattern)` for a pattern with no groups (the generator's two substitutions).
fn parse_template(source: &str) -> Result<Vec<Piece>, GenerateError> {
    let mut s = Tokenizer::new(source)?;
    let mut pieces = Vec::new();
    let mut literal = String::new();
    while let Some(this) = s.get()? {
        let mut chars = this.chars();
        if chars.next() != Some('\\') {
            literal.push_str(&this);
            continue;
        }
        let c = chars.next().unwrap_or('\\');
        match c {
            'g' => {
                if !s.take('<')? {
                    return Err(s.error("missing <", 0));
                }
                let name = s.getuntil('>', "group name")?;
                let len = name.chars().count();
                if !(name.chars().all(is_decimal) && name.is_ascii()) {
                    if !isidentifier(&name) {
                        return Err(s.error(
                            &format!("bad character in group name {}", repr_str(&name)),
                            len + 1,
                        ));
                    }
                    return Err(GenerateError::index(format!(
                        "unknown group name {}",
                        repr_str(&name)
                    )));
                }
                // `int(name)` first: past the digit limit Python's ValueError, before any group check (Sol's G1a
                // review, P1-5). Past MAXGROUPS Python raises the same `invalid group reference` at the same place.
                if len > INT_MAX_STR_DIGITS {
                    return Err(GenerateError::value(format!(
                        "Exceeds the limit ({INT_MAX_STR_DIGITS} digits) for integer string conversion: value has \
                         {len} digits; use sys.set_int_max_str_digits() to increase the limit"
                    )));
                }
                add_group(&s, &name, len + 1, &mut literal, &mut pieces)?;
            }
            '0' => {
                let mut digits = String::new();
                for _ in 0..2 {
                    if !s.next_is_one_of("01234567") {
                        break;
                    }
                    digits.push_str(&s.get()?.unwrap_or_default());
                }
                let value = u32::from_str_radix(&digits, 8).unwrap_or(0) & 0xFF;
                literal.push(char::from_u32(value).unwrap_or('\0'));
            }
            '1'..='9' => {
                let mut this = this.clone();
                let mut octal = false;
                if s.next_is_one_of("0123456789") {
                    this.push_str(&s.get()?.unwrap_or_default());
                    let second = this.chars().nth(2).unwrap_or(' ');
                    if c <= '7' && ('0'..='7').contains(&second) && s.next_is_one_of("01234567") {
                        this.push_str(&s.get()?.unwrap_or_default());
                        octal = true;
                        let value = u32::from_str_radix(&this[1..], 8).unwrap_or(0);
                        if value > 0o377 {
                            let msg = format!("octal escape value {this} outside of range 0-0o377");
                            return Err(s.error(&msg, this.len()));
                        }
                        literal.push(char::from_u32(value).unwrap_or('\0'));
                    }
                }
                if !octal {
                    add_group(&s, &this[1..], this.len() - 1, &mut literal, &mut pieces)?;
                }
            }
            'a' => literal.push('\u{7}'),
            'b' => literal.push('\u{8}'),
            'f' => literal.push('\u{c}'),
            'n' => literal.push('\n'),
            'r' => literal.push('\r'),
            't' => literal.push('\t'),
            'v' => literal.push('\u{b}'),
            '\\' => literal.push('\\'),
            _ if c.is_ascii_alphabetic() => return Err(s.error(&format!("bad escape {this}"), 2)),
            _ => literal.push_str(&this),
        }
    }
    pieces.push(Piece::Literal(literal));
    Ok(pieces)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Each row: python3 -c "import re; print(re.sub(r'(?<!^)(?=[A-Z])', '_', NAME))" on nelly (Python 3.14.7).
    #[test]
    fn underscore_before_capitals_matches_python() {
        let cases: &[(&str, &str)] = &[
            ("HTTPServer", "H_T_T_P_Server"),
            ("agentVerb", "agent_Verb"),
            ("A", "A"),
            ("", ""),
            ("aB", "a_B"),
            ("ABC", "A_B_C"),
            ("snake_case", "snake_case"),
            ("\u{c9}a", "\u{c9}a"),
            ("a\u{c9}B", "a\u{c9}_B"),
            ("X1Y", "X1_Y"),
            ("_A", "__A"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sub_underscore_before_capitals(input),
                *expected,
                "{input:?}"
            );
        }
    }

    // Each row: python3 -c "import re; print(re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', KEY))".
    #[test]
    fn underscore_at_case_rise_matches_python() {
        let cases: &[(&str, &str)] = &[
            ("fooBar", "foo_Bar"),
            ("foo1Bar", "foo1_Bar"),
            ("FOOBar", "FOOBar"),
            ("fooBAR", "foo_BAR"),
            ("a_B", "a_B"),
            ("a\u{c9}", "a\u{c9}"),
            ("\u{e9}B", "\u{e9}B"),
            ("", ""),
            ("A", "A"),
            ("x9Y", "x9_Y"),
            ("aBcD", "a_Bc_D"),
        ];
        for (input, expected) in cases {
            assert_eq!(sub_underscore_at_case_rise(input), *expected, "{input:?}");
        }
    }

    // Each row: python3 -c "import re; print(re.findall(r'(?<![\w.])(\w+)\(', BODY))".
    #[test]
    fn called_words_match_python() {
        let cases: &[(&str, &[&str])] = &[
            (
                "foo(bar(x)) .baz(y) a.b(c) obj.method() fn2 (x) _u8(z)",
                &["foo", "bar", "_u8"],
            ),
            ("\u{e9}(x)", &["\u{e9}"]),
            ("x.\u{e9}(y)", &[]),
            ("\u{b2}(a)", &["\u{b2}"]),
            ("abc", &[]),
            ("(x)", &[]),
            ("a(b(c(d)))", &["a", "b", "c"]),
            ("isRecord(x) && !isText(y)", &["isRecord", "isText"]),
            ("\"q\"(x)", &[]),
            ("a\u{203f}b(x)", &["b"]),
            ("ab(x)", &["ab"]),
            ("x(", &["x"]),
            ("1(2)", &["1"]),
        ];
        for (input, expected) in cases {
            assert_eq!(findall_called_words(input), *expected, "{input:?}");
        }
    }

    // Each row: python3 -c "import re; print(re.search(r'(?<![\w\"])invalid(?![\w\"])', BODY) is not None)".
    #[test]
    fn bare_invalid_matches_python() {
        let cases: &[(&str, bool)] = &[
            ("invalid", true),
            ("invalid()", true),
            ("let x = invalid;", true),
            ("\"invalid\"", false),
            ("invalids", false),
            ("_invalid", false),
            ("xinvalid", false),
            ("invalid_x", false),
            ("(invalid)", true),
            ("Err(invalid())", true),
            ("\u{e9} invalid", true),
            ("invalid\u{e9}", false),
            ("invalid\u{b2}", false),
            ("ainvalid", false),
            ("", false),
            ("invalid\"", false),
            ("x\"invalid", false),
            ("invalidinvalid invalid", true),
        ];
        for (input, expected) in cases {
            assert_eq!(search_bare_invalid(input), *expected, "{input:?}");
        }
    }

    // Each row: python3 -c "import re; print(re.sub(r'&\binput\b(?!\.)', VALUE, CHECKS)); print(re.sub(r'\binput\b', VALUE, CHECKS))".
    #[test]
    fn input_substitutions_match_python() {
        let cases: &[(&str, &str, &str, &str)] = &[
            (
                "input.validate()?; check(&input)?;",
                "text",
                "input.validate()?; check(text)?;",
                "text.validate()?; check(&text)?;",
            ),
            ("&input", "spec", "spec", "&spec"),
            (
                "&input.x &input_x &inputs &input",
                "v",
                "&input.x &input_x &inputs v",
                "&v.x &input_x &inputs &v",
            ),
            (
                "(input) input_x xinput input",
                "t",
                "(input) input_x xinput input",
                "(t) input_x xinput t",
            ),
            ("&input, &input", "a", "a, a", "&a, &a"),
            (
                "\u{e9}input input\u{b2} input\u{203f} input",
                "q",
                "\u{e9}input input\u{b2} input\u{203f} input",
                "\u{e9}input input\u{b2} q\u{203f} q",
            ),
            ("", "x", "", ""),
            ("&&input", "y", "&y", "&&y"),
        ];
        for (checks, value, borrow, word) in cases {
            assert_eq!(
                sub_whole_input_borrow(checks, value).expect("a template"),
                *borrow,
                "{checks:?}"
            );
            assert_eq!(
                sub_input_word(checks, value).expect("a template"),
                *word,
                "{checks:?}"
            );
        }
    }

    // Each row: python3 -c "import re; print(re.sub(r'&\binput\b(?!\.)', TEMPLATE, 'a &input b'))", or the
    // traceback's last line.
    #[test]
    fn templates_match_python() {
        let cases: &[(&str, &str)] = &[
            ("v", "OK a v b"),
            ("\\\\", "OK a \\ b"),
            ("\\n", "OK a \u{a} b"),
            ("\\q", "ERR re.PatternError: bad escape \\q at position 0"),
            (
                "\\",
                "ERR re.PatternError: bad escape (end of pattern) at position 0",
            ),
            (
                "x\\",
                "ERR re.PatternError: bad escape (end of pattern) at position 1",
            ),
            ("\\g<0>", "OK a &input b"),
            ("[\\g<0>]", "OK a [&input] b"),
            (
                "\\g<1>",
                "ERR re.PatternError: invalid group reference 1 at position 3",
            ),
            ("\\g<a>", "ERR IndexError: unknown group name 'a'"),
            (
                "\\g<1a>",
                "ERR re.PatternError: bad character in group name '1a' at position 3",
            ),
            (
                "\\g<>",
                "ERR re.PatternError: missing group name at position 3",
            ),
            (
                "\\g<0",
                "ERR re.PatternError: missing >, unterminated name at position 3",
            ),
            ("\\g", "ERR re.PatternError: missing < at position 2"),
            ("\\g0", "ERR re.PatternError: missing < at position 2"),
            (
                "\\1",
                "ERR re.PatternError: invalid group reference 1 at position 1",
            ),
            (
                "\\12",
                "ERR re.PatternError: invalid group reference 12 at position 1",
            ),
            ("\\0", "OK a \u{0} b"),
            ("\\07", "OK a \u{7} b"),
            ("\\077", "OK a ? b"),
            ("\\08", "OK a \u{0}8 b"),
            ("\\177", "OK a \u{7f} b"),
            (
                "\\400",
                "ERR re.PatternError: octal escape value \\400 outside of range 0-0o377 at position 0",
            ),
            ("\\377", "OK a \u{ff} b"),
            ("\\&", "OK a \\& b"),
            ("\\.", "OK a \\. b"),
            (
                "\\a\\b\\f\\r\\t\\v",
                "OK a \u{7}\u{8}\u{c}\u{d}\u{9}\u{b} b",
            ),
            (
                "a\u{a}b\\q",
                "ERR re.PatternError: bad escape \\q at position 3 (line 2, column 2)",
            ),
            ("\\g<00>", "OK a &input b"),
            (
                "\\g<\u{ff11}>",
                "ERR re.PatternError: bad character in group name '\u{ff11}' at position 3",
            ),
            ("\\g<\u{e9}>", "ERR IndexError: unknown group name '\u{e9}'"),
            ("\\\u{e9}", "OK a \\\u{e9} b"),
            (
                "\\q\\",
                "ERR re.PatternError: bad escape (end of pattern) at position 2",
            ),
            (
                "\\g<0\\>>",
                "ERR re.PatternError: bad character in group name '0\\\\>' at position 3",
            ),
            (
                "x\u{a}y\\1",
                "ERR re.PatternError: invalid group reference 1 at position 4 (line 2, column 3)",
            ),
            (
                "\\9",
                "ERR re.PatternError: invalid group reference 9 at position 1",
            ),
            (
                "\\19",
                "ERR re.PatternError: invalid group reference 19 at position 1",
            ),
            (
                "\\g<99999999999>",
                "ERR re.PatternError: invalid group reference 99999999999 at position 3",
            ),
            (
                "\\g<a b>",
                "ERR re.PatternError: bad character in group name 'a b' at position 3",
            ),
        ];
        for (template, expected) in cases {
            let got = match sub_whole_input_borrow("a &input b", template) {
                Ok(text) => format!("OK {text}"),
                Err(error) => format!("ERR {error}"),
            };
            assert_eq!(got, *expected, "{template:?}");
        }
    }

    // Each row: python3 -c "import re; print(re.fullmatch(PATTERN, TEXT) is not None)"; the Rust side translates the
    // pattern.
    #[test]
    fn translated_classes_match_python() {
        let cases: &[(&str, &str, bool)] = &[
            ("\\w+", "abc", true),
            ("\\w+", "a\u{b2}", true),
            ("\\w+", "\u{e1}", true),
            ("\\w+", "a\u{203f}", false),
            ("[\\w.]+", "a.b", true),
            ("[^\\w]", "\u{e9}", false),
            ("[^\\w]", "\u{203f}", true),
            ("\\s+", "\u{1c}\u{1d}", true),
            ("\\s", "\u{180e}", false),
            ("\\S+", "ab", true),
            ("\\W", "\u{b2}", false),
            ("[\\s,]+", " ,\u{1f}", true),
            ("\\d+", "\u{661}\u{662}", true),
            ("\\d", "\u{b2}", false),
            ("[A-Za-z_]\\w*", "ZWNJ\u{200c}", false),
            ("[\\W]", "_", false),
            ("[^\\s]+", "a b", false),
        ];
        for (pattern, text, expected) in cases {
            assert_eq!(
                compile_fullmatch(pattern).is_match(text),
                *expected,
                "{pattern:?} {text:?}"
            );
        }
        assert_eq!(translate(r"[^\w:]"), format!("[^{WORD_CLASS}:]"));
        assert_eq!(translate(r"a\.b\d$"), r"a\.b\d$");
        assert_eq!(translate(r"[[&]"), r"[\[\&]");
    }

    // Each row: [m.span() for m in re.finditer(PATTERN, TEXT)] on nelly (Python 3.14.7), as UTF-8 byte offsets
    // (Sol's G1a review, P1-6): Python's `\b` beside a combining mark, `²`, `‿`, ZWJ and U+0903.
    type Spans = &'static [(usize, usize)];

    #[test]
    fn python_boundaries_match_python() {
        let cases: &[(&str, &str, Spans)] = &[
            ("a\\b", "a\u{301}", &[(0, 1)]),
            ("a\\b", "a\u{b2}", &[]),
            ("a\\B", "a\u{301}", &[]),
            ("a\\B", "a\u{b2}", &[(0, 1)]),
            ("\\b([A-Z]\\w*)\\b", "A\u{301}", &[(0, 1)]),
            ("\\b([A-Z]\\w*)\\b", "A\u{b2} B", &[(0, 3), (4, 5)]),
            (
                "\\b([A-Z]\\w*)\\b",
                "x Foo\u{203f}Bar Baz\u{b2} Qux\u{200d} \u{903}Zed",
                &[(2, 5), (8, 11), (12, 17), (18, 21), (28, 31)],
            ),
            (
                "\\b(?:struct|enum)\\s+([A-Za-z_]\\w*)",
                "pub struct Foo\u{301}; enum\u{b2} Bar; struct\u{2028}Baz",
                &[(4, 14), (30, 42)],
            ),
            (
                "\\bfn\\s+deserialize\\b",
                "fn  deserialize\u{301}(",
                &[(0, 15)],
            ),
            ("\\bfn\\s+deserialize\\b", "fn deserialize\u{b2}", &[]),
            (
                "\\binput\\b",
                "\u{e9}input input\u{b2} input\u{203f} (input)",
                &[(16, 21), (26, 31)],
            ),
            (
                "(?m)^[ \\t]*impl\\b[^{;]*?\\b(?:serde::)?Serialize\\s+for\\s+([A-Za-z_]\\w*)",
                "impl Serialize for Foo\u{301} {}\u{a}impl\u{b2} Serialize for Bar {}\u{a}impl<T> serde::Serialize for Baz<T> {",
                &[(0, 22), (56, 88)],
            ),
            ("\\b", "\u{1d165}x\u{1f100}y", &[(4, 4), (10, 10)]),
            ("[\\b]x", "\u{8}x", &[(0, 2)]),
        ];
        for (pattern, text, expected) in cases {
            assert_eq!(
                PyRegex::new(pattern).find_iter(text),
                *expected,
                "{pattern:?} {text:?}"
            );
        }
        let words = PyRegex::new(r"\b([A-Z]\w*)\b");
        let text = "A\u{b2} B";
        let found: Vec<&str> = words
            .captures_iter(text)
            .iter()
            .filter_map(|groups| groups[1].map(|(start, end)| &text[start..end]))
            .collect();
        assert_eq!(found, ["A\u{b2}", "B"]);
        assert!(PyRegex::fullmatch(r"\w+\b").is_match("a\u{b2}"));
        assert_eq!(
            PyRegex::new(r"\bx").search_at("x \u{301}x x", 1),
            Some((4, 5))
        );
    }

    #[test]
    #[should_panic(expected = "use py::re::PyRegex")]
    fn translate_refuses_boundaries() {
        let _ = translate(r"\bfn\b");
    }

    // python3 -c "import re; re.sub(r'\binput\b', r'\g<' + '0' * 4301 + '>', 'input')": the traceback's last line;
    // with 4,300 zeros it prints `input`.
    #[test]
    fn template_group_numbers_keep_python_s_digit_limit() {
        let error = sub_input_word("input", &format!(r"\g<{}>", "0".repeat(4301)))
            .expect_err("digit limit");
        assert_eq!(
            error.to_string(),
            "ValueError: Exceeds the limit (4300 digits) for integer string conversion: value has 4301 digits; use \
             sys.set_int_max_str_digits() to increase the limit"
        );
        let error = sub_input_word("input", &format!(r"\g<{}>", "9".repeat(4301)))
            .expect_err("digit limit");
        assert!(
            error
                .to_string()
                .starts_with("ValueError: Exceeds the limit")
        );
        assert_eq!(
            sub_input_word("input", &format!(r"\g<{}>", "0".repeat(4300))).expect("group 0"),
            "input"
        );
    }
}
