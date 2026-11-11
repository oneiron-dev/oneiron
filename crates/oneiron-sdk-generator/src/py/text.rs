//! Python's `str` methods with Python's Unicode rules: only the ones the generator calls.
//!
//! The character classes are Unicode properties read through `regex` (whose tables, like CPython 3.14.7's, are
//! Unicode 16.0.0). The case mappings are Rust's `char::to_uppercase`/`to_lowercase` (the same full mappings,
//! UnicodeData plus SpecialCasing's unconditional rows), held to Unicode 16.0.0: Rust 1.96's tables are Unicode 17,
//! which maps 28 characters 16.0 leaves unassigned, so a mapping that starts or ends at a character `regex` (16.0)
//! calls unassigned is no mapping. Python's title-case table and its final-sigma rule are written out here.
//! When the port was made, every property and mapping was checked against CPython 3.14.7's for every code point.

use std::ffi::OsStr;
use std::sync::LazyLock;

use regex::Regex;

fn class(pattern: &str) -> Regex {
    Regex::new(pattern).expect("a constant character class")
}

fn class_has(re: &Regex, c: char) -> bool {
    re.is_match(c.encode_utf8(&mut [0; 4]))
}

/// `str.isalnum()`: the letters and numbers (general categories L and N; CPython's isalpha, isdecimal, isdigit and
/// isnumeric together are exactly those on 3.14.7).
static ALNUM: LazyLock<Regex> = LazyLock::new(|| class(r"[\p{L}\p{N}]"));
/// `str.isdecimal()`: general category Nd.
static DECIMAL: LazyLock<Regex> = LazyLock::new(|| class(r"\p{Nd}"));
/// Not `str.isprintable()`: categories Cc, Cf, Co, Cn, Zl, Zp, Zs (Cs, the surrogates, cannot occur in a Rust `str`).
static NOT_PRINTABLE: LazyLock<Regex> =
    LazyLock::new(|| class(r"[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Zs}]"));
static CASED: LazyLock<Regex> = LazyLock::new(|| class(r"\p{Cased}"));
static CASE_IGNORABLE: LazyLock<Regex> = LazyLock::new(|| class(r"\p{Case_Ignorable}"));
static XID_START: LazyLock<Regex> = LazyLock::new(|| class(r"\p{XID_Start}"));
static XID_CONTINUE: LazyLock<Regex> = LazyLock::new(|| class(r"\p{XID_Continue}"));
/// General category Cn in Unicode 16.0.0: what CPython 3.14.7 maps to itself.
static UNASSIGNED: LazyLock<Regex> = LazyLock::new(|| class(r"\p{Cn}"));

fn is_unassigned(c: char) -> bool {
    !c.is_ascii() && class_has(&UNASSIGNED, c)
}

/// One character's full case mapping, held to Unicode 16.0.0 (see the module comment).
fn push_case_mapping<I: Iterator<Item = char> + Clone>(out: &mut String, c: char, mapped: I) {
    if is_unassigned(c) || mapped.clone().any(is_unassigned) {
        out.push(c);
    } else {
        out.extend(mapped);
    }
}

/// `c.isspace()`, and the regular expression `\s` on a `str` pattern: CPython's `Py_UNICODE_ISSPACE`, which also
/// takes U+001C-U+001F (Rust's `char::is_whitespace` does not, and takes no U+180E either way).
pub(crate) fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n'
            | '\u{0B}'
            | '\u{0C}'
            | '\r'
            | '\u{1C}'..='\u{20}'
            | '\u{85}'
            | '\u{A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
    )
}

/// `c.isalnum()`.
pub(crate) fn is_alnum(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric()
    } else {
        class_has(&ALNUM, c)
    }
}

/// The regular expression `\w` on a `str` pattern: `c.isalnum() or c == '_'`. Rust's Unicode `\w` differs: it also
/// takes combining marks, every connector punctuation (U+203F), ZWNJ/ZWJ and the Other_Alphabetic marks, and it
/// misses the numbers of category No (`²`, `½`).
pub(crate) fn is_word(c: char) -> bool {
    c == '_' || is_alnum(c)
}

/// `c.isdecimal()` (and the regular expression `\d`).
pub(crate) fn is_decimal(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_digit()
    } else {
        class_has(&DECIMAL, c)
    }
}

/// `c.isprintable()`: everything but categories C and Z, the ASCII space excepted.
pub(crate) fn is_printable(c: char) -> bool {
    if c.is_ascii() {
        (' '..='~').contains(&c)
    } else {
        !class_has(&NOT_PRINTABLE, c)
    }
}

/// The derived property Cased (CPython's `_PyUnicode_IsCased`).
pub(crate) fn is_cased(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphabetic()
    } else {
        class_has(&CASED, c)
    }
}

/// The derived property Case_Ignorable (CPython's `_PyUnicode_IsCaseIgnorable`).
pub(crate) fn is_case_ignorable(c: char) -> bool {
    if c.is_ascii() {
        matches!(c, '\'' | '.' | ':' | '^' | '`')
    } else {
        class_has(&CASE_IGNORABLE, c)
    }
}

/// `s.isidentifier()`: XID_Start (or `_`) then XID_Continue, with no normalisation.
pub(crate) fn isidentifier(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || class_has(&XID_START, first)) && chars.all(|c| class_has(&XID_CONTINUE, c))
}

/// The characters whose full title-case mapping is not their uppercase one, printed on nelly (Python 3.14.7) by
/// `python3 -c "print([(hex(c), chr(c).title()) for c in range(0x110000) if chr(c).title() != chr(c).upper()])"`.
const TITLE_NOT_UPPER: &[(char, &str)] = &[
    ('\u{00DF}', "\u{0053}\u{0073}"),
    ('\u{01C4}', "\u{01C5}"),
    ('\u{01C5}', "\u{01C5}"),
    ('\u{01C6}', "\u{01C5}"),
    ('\u{01C7}', "\u{01C8}"),
    ('\u{01C8}', "\u{01C8}"),
    ('\u{01C9}', "\u{01C8}"),
    ('\u{01CA}', "\u{01CB}"),
    ('\u{01CB}', "\u{01CB}"),
    ('\u{01CC}', "\u{01CB}"),
    ('\u{01F1}', "\u{01F2}"),
    ('\u{01F2}', "\u{01F2}"),
    ('\u{01F3}', "\u{01F2}"),
    ('\u{0587}', "\u{0535}\u{0582}"),
    ('\u{10D0}', "\u{10D0}"),
    ('\u{10D1}', "\u{10D1}"),
    ('\u{10D2}', "\u{10D2}"),
    ('\u{10D3}', "\u{10D3}"),
    ('\u{10D4}', "\u{10D4}"),
    ('\u{10D5}', "\u{10D5}"),
    ('\u{10D6}', "\u{10D6}"),
    ('\u{10D7}', "\u{10D7}"),
    ('\u{10D8}', "\u{10D8}"),
    ('\u{10D9}', "\u{10D9}"),
    ('\u{10DA}', "\u{10DA}"),
    ('\u{10DB}', "\u{10DB}"),
    ('\u{10DC}', "\u{10DC}"),
    ('\u{10DD}', "\u{10DD}"),
    ('\u{10DE}', "\u{10DE}"),
    ('\u{10DF}', "\u{10DF}"),
    ('\u{10E0}', "\u{10E0}"),
    ('\u{10E1}', "\u{10E1}"),
    ('\u{10E2}', "\u{10E2}"),
    ('\u{10E3}', "\u{10E3}"),
    ('\u{10E4}', "\u{10E4}"),
    ('\u{10E5}', "\u{10E5}"),
    ('\u{10E6}', "\u{10E6}"),
    ('\u{10E7}', "\u{10E7}"),
    ('\u{10E8}', "\u{10E8}"),
    ('\u{10E9}', "\u{10E9}"),
    ('\u{10EA}', "\u{10EA}"),
    ('\u{10EB}', "\u{10EB}"),
    ('\u{10EC}', "\u{10EC}"),
    ('\u{10ED}', "\u{10ED}"),
    ('\u{10EE}', "\u{10EE}"),
    ('\u{10EF}', "\u{10EF}"),
    ('\u{10F0}', "\u{10F0}"),
    ('\u{10F1}', "\u{10F1}"),
    ('\u{10F2}', "\u{10F2}"),
    ('\u{10F3}', "\u{10F3}"),
    ('\u{10F4}', "\u{10F4}"),
    ('\u{10F5}', "\u{10F5}"),
    ('\u{10F6}', "\u{10F6}"),
    ('\u{10F7}', "\u{10F7}"),
    ('\u{10F8}', "\u{10F8}"),
    ('\u{10F9}', "\u{10F9}"),
    ('\u{10FA}', "\u{10FA}"),
    ('\u{10FD}', "\u{10FD}"),
    ('\u{10FE}', "\u{10FE}"),
    ('\u{10FF}', "\u{10FF}"),
    ('\u{1F80}', "\u{1F88}"),
    ('\u{1F81}', "\u{1F89}"),
    ('\u{1F82}', "\u{1F8A}"),
    ('\u{1F83}', "\u{1F8B}"),
    ('\u{1F84}', "\u{1F8C}"),
    ('\u{1F85}', "\u{1F8D}"),
    ('\u{1F86}', "\u{1F8E}"),
    ('\u{1F87}', "\u{1F8F}"),
    ('\u{1F88}', "\u{1F88}"),
    ('\u{1F89}', "\u{1F89}"),
    ('\u{1F8A}', "\u{1F8A}"),
    ('\u{1F8B}', "\u{1F8B}"),
    ('\u{1F8C}', "\u{1F8C}"),
    ('\u{1F8D}', "\u{1F8D}"),
    ('\u{1F8E}', "\u{1F8E}"),
    ('\u{1F8F}', "\u{1F8F}"),
    ('\u{1F90}', "\u{1F98}"),
    ('\u{1F91}', "\u{1F99}"),
    ('\u{1F92}', "\u{1F9A}"),
    ('\u{1F93}', "\u{1F9B}"),
    ('\u{1F94}', "\u{1F9C}"),
    ('\u{1F95}', "\u{1F9D}"),
    ('\u{1F96}', "\u{1F9E}"),
    ('\u{1F97}', "\u{1F9F}"),
    ('\u{1F98}', "\u{1F98}"),
    ('\u{1F99}', "\u{1F99}"),
    ('\u{1F9A}', "\u{1F9A}"),
    ('\u{1F9B}', "\u{1F9B}"),
    ('\u{1F9C}', "\u{1F9C}"),
    ('\u{1F9D}', "\u{1F9D}"),
    ('\u{1F9E}', "\u{1F9E}"),
    ('\u{1F9F}', "\u{1F9F}"),
    ('\u{1FA0}', "\u{1FA8}"),
    ('\u{1FA1}', "\u{1FA9}"),
    ('\u{1FA2}', "\u{1FAA}"),
    ('\u{1FA3}', "\u{1FAB}"),
    ('\u{1FA4}', "\u{1FAC}"),
    ('\u{1FA5}', "\u{1FAD}"),
    ('\u{1FA6}', "\u{1FAE}"),
    ('\u{1FA7}', "\u{1FAF}"),
    ('\u{1FA8}', "\u{1FA8}"),
    ('\u{1FA9}', "\u{1FA9}"),
    ('\u{1FAA}', "\u{1FAA}"),
    ('\u{1FAB}', "\u{1FAB}"),
    ('\u{1FAC}', "\u{1FAC}"),
    ('\u{1FAD}', "\u{1FAD}"),
    ('\u{1FAE}', "\u{1FAE}"),
    ('\u{1FAF}', "\u{1FAF}"),
    ('\u{1FB2}', "\u{1FBA}\u{0345}"),
    ('\u{1FB3}', "\u{1FBC}"),
    ('\u{1FB4}', "\u{0386}\u{0345}"),
    ('\u{1FB7}', "\u{0391}\u{0342}\u{0345}"),
    ('\u{1FBC}', "\u{1FBC}"),
    ('\u{1FC2}', "\u{1FCA}\u{0345}"),
    ('\u{1FC3}', "\u{1FCC}"),
    ('\u{1FC4}', "\u{0389}\u{0345}"),
    ('\u{1FC7}', "\u{0397}\u{0342}\u{0345}"),
    ('\u{1FCC}', "\u{1FCC}"),
    ('\u{1FF2}', "\u{1FFA}\u{0345}"),
    ('\u{1FF3}', "\u{1FFC}"),
    ('\u{1FF4}', "\u{038F}\u{0345}"),
    ('\u{1FF7}', "\u{03A9}\u{0342}\u{0345}"),
    ('\u{1FFC}', "\u{1FFC}"),
    ('\u{FB00}', "\u{0046}\u{0066}"),
    ('\u{FB01}', "\u{0046}\u{0069}"),
    ('\u{FB02}', "\u{0046}\u{006C}"),
    ('\u{FB03}', "\u{0046}\u{0066}\u{0069}"),
    ('\u{FB04}', "\u{0046}\u{0066}\u{006C}"),
    ('\u{FB05}', "\u{0053}\u{0074}"),
    ('\u{FB06}', "\u{0053}\u{0074}"),
    ('\u{FB13}', "\u{0544}\u{0576}"),
    ('\u{FB14}', "\u{0544}\u{0565}"),
    ('\u{FB15}', "\u{0544}\u{056B}"),
    ('\u{FB16}', "\u{054E}\u{0576}"),
    ('\u{FB17}', "\u{0544}\u{056D}"),
];

fn push_title(out: &mut String, c: char) {
    match TITLE_NOT_UPPER.binary_search_by_key(&c, |&(from, _)| from) {
        Ok(at) => out.push_str(TITLE_NOT_UPPER[at].1),
        Err(_) => push_case_mapping(out, c, c.to_uppercase()),
    }
}

/// CPython's `handle_capital_sigma`: U+03A3 lowers to final `ς` after a cased letter (case-ignorable ones skipped)
/// that no cased letter follows (case-ignorable ones skipped again), else to `σ`.
fn lower_sigma(chars: &[char], at: usize) -> char {
    let before = chars[..at].iter().rev().find(|&&c| !is_case_ignorable(c));
    let mut is_final = before.is_some_and(|&c| is_cased(c));
    if is_final && at + 1 < chars.len() {
        let after = chars[at + 1..].iter().find(|&&c| !is_case_ignorable(c));
        is_final = after.is_none_or(|&c| !is_cased(c));
    }
    if is_final { '\u{3C2}' } else { '\u{3C3}' }
}

/// CPython's `lower_ucs4`: one character of `str.lower()`.
fn push_lower(out: &mut String, chars: &[char], at: usize) {
    match chars[at] {
        '\u{3A3}' => out.push(lower_sigma(chars, at)),
        c => push_case_mapping(out, c, c.to_lowercase()),
    }
}

/// `s.title()`: a cased character after a cased one lowers, any other one takes its title case; `v2beta` is `V2Beta`,
/// `a_1b` is `A_1B`, `they're` is `They'Re` (brief H3).
pub(crate) fn title(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut previous_is_cased = false;
    for (at, &c) in chars.iter().enumerate() {
        if previous_is_cased {
            push_lower(&mut out, &chars, at);
        } else {
            push_title(&mut out, c);
        }
        previous_is_cased = is_cased(c);
    }
    out
}

/// `s.upper()`: full mappings, so `ß` is `SS`.
pub(crate) fn upper(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        push_case_mapping(&mut out, c, c.to_uppercase());
    }
    out
}

/// `s.lower()`: full mappings and the final-sigma rule; `İ` is `i̇`.
pub(crate) fn lower(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    for at in 0..chars.len() {
        push_lower(&mut out, &chars, at);
    }
    out
}

/// `s.strip()`: Python's whitespace, not Rust's (`\x1c` strips, U+180E does not).
pub(crate) fn strip(s: &str) -> &str {
    s.trim_matches(is_space)
}

/// `s.lstrip()`.
pub(crate) fn lstrip(s: &str) -> &str {
    s.trim_start_matches(is_space)
}

fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\u{0B}'
            | '\u{0C}'
            | '\u{1C}'
            | '\u{1D}'
            | '\u{1E}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// `s.splitlines()`: Python's line boundaries (`\v`, `\f`, U+001C-U+001E, U+0085, U+2028 and U+2029 as well as
/// `\n`, `\r` and `\r\n`), the ends dropped, no empty last line.
pub(crate) fn splitlines(s: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = s.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if !is_line_break(c) {
            continue;
        }
        lines.push(&s[start..at]);
        start = at + c.len_utf8();
        if c == '\r' && chars.peek().is_some_and(|&(_, next)| next == '\n') {
            chars.next();
            start += 1;
        }
    }
    if start < s.len() {
        lines.push(&s[start..]);
    }
    lines
}

fn push_repr_char(out: &mut String, c: char, quote: char) {
    match c {
        _ if c == quote || c == '\\' => {
            out.push('\\');
            out.push(c);
        }
        '\t' => out.push_str("\\t"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        _ if c < ' ' || c == '\u{7F}' => out.push_str(&format!("\\x{:02x}", u32::from(c))),
        _ if c.is_ascii() || is_printable(c) => out.push(c),
        _ if u32::from(c) <= 0xFF => out.push_str(&format!("\\x{:02x}", u32::from(c))),
        _ if u32::from(c) <= 0xFFFF => out.push_str(&format!("\\u{:04x}", u32::from(c))),
        _ => out.push_str(&format!("\\U{:08x}", u32::from(c))),
    }
}

fn repr_quote(s: &str) -> char {
    if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    }
}

/// `repr(s)` of a `str`: single quotes unless the text holds `'` and no `"`; `\t`, `\n`, `\r`, `\xhh`, `\uhhhh`,
/// `\Uhhhhhhhh` for what is not printable (brief H4).
pub(crate) fn repr_str(s: &str) -> String {
    let quote = repr_quote(s);
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        push_repr_char(&mut out, c, quote);
    }
    out.push(quote);
    out
}

/// `repr(t)` of a tuple of strings: `('a', 'b')`, `('a',)`.
pub(crate) fn repr_str_tuple(items: &[&str]) -> String {
    let inner: Vec<String> = items.iter().map(|item| repr_str(item)).collect();
    if inner.len() == 1 {
        format!("({},)", inner[0])
    } else {
        format!("({})", inner.join(", "))
    }
}

/// `repr(str(path))` of an OS path: a byte that is not UTF-8 is the surrogate `os.fsdecode` gives it (`\udcff`).
pub(crate) fn repr_os_str(os: &OsStr) -> String {
    let bytes = os.as_encoded_bytes();
    let valid: String = bytes.utf8_chunks().map(|chunk| chunk.valid()).collect();
    let quote = repr_quote(&valid);
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push(quote);
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            push_repr_char(&mut out, c, quote);
        }
        for byte in chunk.invalid() {
            out.push_str(&format!("\\udc{byte:02x}"));
        }
    }
    out.push(quote);
    out
}

/// `str(name)` of an OS file name as Python prints it on stderr: a byte that is not UTF-8 is the surrogate
/// `os.fsdecode` gives it, written `\udcff` by stderr's `backslashreplace`.
pub(crate) fn display_os_str(os: &OsStr) -> String {
    let mut out = String::new();
    for chunk in os.as_encoded_bytes().utf8_chunks() {
        out.push_str(chunk.valid());
        for byte in chunk.invalid() {
            out.push_str(&format!("\\udc{byte:02x}"));
        }
    }
    out
}

/// The code points Python's `str` of an OS file name holds (a byte that is not UTF-8 as its surrogate), which is
/// what `sorted()` of the names compares.
pub(crate) fn os_str_code_points(os: &OsStr) -> Vec<u32> {
    let mut out = Vec::new();
    for chunk in os.as_encoded_bytes().utf8_chunks() {
        out.extend(chunk.valid().chars().map(u32::from));
        out.extend(chunk.invalid().iter().map(|&byte| 0xDC00 + u32::from(byte)));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every table below was printed on nelly (Python 3.14.7) by
    // python3 -c "for s in INPUTS: print((s, s.METHOD()))" with the method the test names.

    #[test]
    fn title_matches_python() {
        let cases: &[(&str, &str)] = &[
            ("v2beta", "V2Beta"),
            ("html5parser", "Html5Parser"),
            ("a_1b", "A_1B"),
            ("fooBAR", "Foobar"),
            ("they're", "They'Re"),
            ("\u{1f3}", "\u{1f2}"),
            ("\u{df}", "Ss"),
            ("\u{fb01}x", "Fix"),
            ("hello world", "Hello World"),
            ("HELLO_WORLD", "Hello_World"),
            ("agent_verb", "Agent_Verb"),
            ("x2y", "X2Y"),
            ("1abc", "1Abc"),
            ("_private", "_Private"),
            ("\u{3a3}\u{391}\u{3a3}", "\u{3a3}\u{3b1}\u{3c2}"),
            ("\u{3b1}\u{3a3}", "\u{391}\u{3c2}"),
            ("a\u{3a3} b", "A\u{3c2} B"),
            ("\u{1c6}ungla", "\u{1c5}ungla"),
            ("\u{130}stanbul", "\u{130}stanbul"),
            ("\u{e9}clair", "\u{c9}clair"),
            ("\u{149}", "\u{2bc}N"),
            ("\u{1c7}", "\u{1c8}"),
            ("\u{1fb3}", "\u{1fbc}"),
            ("\u{10d9}\u{10d0}", "\u{10d9}\u{10d0}"),
            ("", ""),
            ("123", "123"),
            ("a1b2c3", "A1B2C3"),
            ("ABC", "Abc"),
            ("aBc dEf", "Abc Def"),
            ("\u{fc}ber_stra\u{df}e", "\u{dc}ber_Stra\u{df}e"),
            ("vault.recall", "Vault.Recall"),
            ("u8", "U8"),
            ("i64", "I64"),
            ("\u{2b0}a", "\u{2b0}a"),
            ("a\u{345}b", "A\u{345}b"),
            ("\u{2160}x", "\u{2160}x"),
            ("x\u{2160}y", "X\u{2170}y"),
        ];
        for (input, expected) in cases {
            assert_eq!(title(input), *expected, "{input:?}");
        }
    }

    #[test]
    fn upper_matches_python() {
        let cases: &[(&str, &str)] = &[
            ("\u{df}", "SS"),
            ("\u{149}", "\u{2bc}N"),
            ("\u{fb01}", "FI"),
            ("abc", "ABC"),
            ("\u{130}", "\u{130}"),
            ("\u{1c5}", "\u{1c4}"),
            ("\u{1fb3}", "\u{391}\u{399}"),
            ("stra\u{df}e", "STRASSE"),
            ("vault_recall_limit_default", "VAULT_RECALL_LIMIT_DEFAULT"),
            ("\u{131}", "I"),
        ];
        for (input, expected) in cases {
            assert_eq!(upper(input), *expected, "{input:?}");
        }
    }

    #[test]
    fn lower_matches_python() {
        let cases: &[(&str, &str)] = &[
            ("\u{130}", "i\u{307}"),
            ("\u{3a3}\u{391}\u{3a3}", "\u{3c3}\u{3b1}\u{3c2}"),
            ("\u{391}\u{3a3} \u{392}", "\u{3b1}\u{3c2} \u{3b2}"),
            ("\u{3a3}", "\u{3c3}"),
            ("a\u{3a3}", "a\u{3c2}"),
            ("ABC", "abc"),
            ("\u{1c5}", "\u{1c6}"),
            ("\u{3a3}a", "\u{3c3}a"),
            ("A\u{3a3}.", "a\u{3c2}."),
            ("A\u{3a3}'b", "a\u{3c3}'b"),
            ("A'\u{3a3}", "a'\u{3c2}"),
            ("A\u{3a3}'", "a\u{3c2}'"),
            ("1\u{3a3}", "1\u{3c3}"),
            ("A\u{3a3}\u{301}", "a\u{3c2}\u{301}"),
        ];
        for (input, expected) in cases {
            assert_eq!(lower(input), *expected, "{input:?}");
        }
    }

    #[test]
    fn strip_matches_python() {
        let cases: &[(&str, &str)] = &[
            (" \u{9}\u{a} x \u{1c}\u{85}\u{2028}", "x"),
            ("\u{a0}x\u{3000}", "x"),
            ("x\u{200b}", "x\u{200b}"),
            ("\u{feff}x", "\u{feff}x"),
            ("", ""),
            ("  ", ""),
        ];
        for (input, expected) in cases {
            assert_eq!(strip(input), *expected, "{input:?}");
        }
        let cases: &[(&str, &str)] = &[(" \u{9} x ", "x "), ("\u{2029}x", "x")];
        for (input, expected) in cases {
            assert_eq!(lstrip(input), *expected, "{input:?}");
        }
    }

    #[test]
    fn splitlines_matches_python() {
        let cases: &[(&str, &[&str])] = &[
            (
                "a\u{a}b\u{d}\u{a}c\u{d}d\u{b}e\u{c}f\u{1c}g\u{1d}h\u{1e}i\u{85}j\u{2028}k\u{2029}l",
                &["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"],
            ),
            ("", &[]),
            ("\u{a}", &[""]),
            ("a\u{a}", &["a"]),
            ("a\u{d}\u{a}\u{d}\u{a}", &["a", ""]),
            ("\u{d}", &[""]),
            ("a\u{a}\u{a}b", &["a", "", "b"]),
            ("x", &["x"]),
        ];
        for (input, expected) in cases {
            assert_eq!(splitlines(input), *expected, "{input:?}");
        }
    }

    #[test]
    fn isidentifier_matches_python() {
        let cases: &[(&str, bool)] = &[
            ("a", true),
            ("_", true),
            ("1a", false),
            ("a1", true),
            ("\u{e9}", true),
            ("\u{b2}", false),
            ("a\u{b2}", false),
            ("a\u{301}", true),
            ("\u{301}a", false),
            ("", false),
            ("class", true),
            ("a-b", false),
            ("\u{2115}", true),
            ("\u{2118}x", true),
            ("a\u{b7}b", true),
            ("\u{2160}", true),
            ("a\u{200c}", true),
            ("\u{309b}", false),
            ("x\u{309b}", false),
        ];
        for (input, expected) in cases {
            assert_eq!(isidentifier(input), *expected, "{input:?}");
        }
    }

    fn one_char(s: &str) -> char {
        let mut chars = s.chars();
        let c = chars.next().expect("one character");
        assert!(chars.next().is_none(), "{s:?}");
        c
    }

    #[test]
    fn character_classes_match_python() {
        let cases: &[(&str, bool)] = &[
            ("a", true),
            ("_", false),
            ("\u{b2}", true),
            ("\u{bd}", true),
            ("\u{216b}", true),
            ("\u{301}", false),
            ("\u{203f}", false),
            ("\u{200c}", false),
            ("\u{e9}", true),
            ("\u{661}", true),
            ("\u{4e00}", true),
            (" ", false),
            ("\u{903}", false),
            ("\u{345}", false),
            ("\u{2b0}", true),
            ("\u{1d7ce}", true),
            ("\u{3007}", true),
            ("\u{0}", false),
        ];
        for (input, expected) in cases {
            assert_eq!(is_alnum(one_char(input)), *expected, "isalnum {input:?}");
            assert_eq!(
                is_word(one_char(input)),
                *expected || *input == "_",
                "word {input:?}"
            );
        }
        let cases: &[(&str, bool)] = &[
            ("\u{1c}", true),
            ("\u{1f}", true),
            ("\u{85}", true),
            ("\u{a0}", true),
            ("\u{200b}", false),
            ("\u{2028}", true),
            ("\u{feff}", false),
            ("\u{b}", true),
            (" ", true),
            ("a", false),
            ("\u{180e}", false),
            ("\u{3000}", true),
        ];
        for (input, expected) in cases {
            assert_eq!(is_space(one_char(input)), *expected, "isspace {input:?}");
        }
        let cases: &[(&str, bool)] = &[
            ("\u{ad}", false),
            ("\u{2028}", false),
            ("\u{a0}", false),
            ("\u{e0001}", false),
            ("\u{e000}", false),
            ("\u{10ffff}", false),
            ("\u{378}", false),
            ("\u{e9}", true),
            (" ", true),
            ("\u{7f}", false),
            ("\u{200b}", false),
            ("\u{301}", true),
            ("a", true),
        ];
        for (input, expected) in cases {
            assert_eq!(
                is_printable(one_char(input)),
                *expected,
                "isprintable {input:?}"
            );
        }
    }

    #[test]
    fn repr_matches_python() {
        let cases: &[(&str, &str)] = &[
            ("a'b", "\"a'b\""),
            ("a\"b", "'a\"b'"),
            ("a'b\"c", "'a\\'b\"c'"),
            ("\u{e9}", "'\u{e9}'"),
            ("\u{0}", "'\\x00'"),
            ("\u{2028}", "'\\u2028'"),
            ("\u{7f}", "'\\x7f'"),
            ("\u{80}", "'\\x80'"),
            ("\u{a0}", "'\\xa0'"),
            ("\u{ad}", "'\\xad'"),
            ("\u{1f600}", "'\u{1f600}'"),
            ("\u{e0001}", "'\\U000e0001'"),
            ("\u{9}\u{a}\u{d}\\", "'\\t\\n\\r\\\\'"),
            ("", "''"),
            ("'", "\"'\""),
            ("\"", "'\"'"),
            ("\u{1f}\u{b}", "'\\x1f\\x0b'"),
            ("\u{e000}", "'\\ue000'"),
            ("\u{10ffff}", "'\\U0010ffff'"),
            ("caf\u{e9} \u{4e00}", "'caf\u{e9} \u{4e00}'"),
        ];
        for (input, expected) in cases {
            assert_eq!(repr_str(input), *expected, "{input:?}");
        }
        // python3 -c "print(('Get', 'Hydrate'), ('x',), ())"
        assert_eq!(repr_str_tuple(&["Get", "Hydrate"]), "('Get', 'Hydrate')");
        assert_eq!(repr_str_tuple(&["x"]), "('x',)");
        assert_eq!(repr_str_tuple(&[]), "()");
    }

    #[cfg(unix)]
    #[test]
    fn os_names_keep_python_surrogates() {
        use std::os::unix::ffi::OsStrExt;
        // python3 -c "import os; n = os.fsdecode(b'a\xff\xc3.json'); print(repr(n), n.encode('utf-8', 'backslashreplace'))"
        let name = OsStr::from_bytes(b"a\xff\xc3.json");
        assert_eq!(repr_os_str(name), "'a\\udcff\\udcc3.json'");
        assert_eq!(display_os_str(name), "a\\udcff\\udcc3.json");
        assert_eq!(
            os_str_code_points(OsStr::from_bytes(b"\xffa")),
            vec![0xDCFF, u32::from('a')]
        );
        assert_eq!(repr_os_str(OsStr::new("it's")), "\"it's\"");
    }
}
