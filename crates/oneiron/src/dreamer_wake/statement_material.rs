//! A text's statement material (ARCH-0026 RD-26): one BLAKE3 digest per
//! sentence with words in it, read the same way wherever material is
//! compared. The projector's surprise check reads a turn's material through
//! it, and an Arc's gate (FIX 7509 P8) its sittings' summary lines.
//!
//! Each sentence's whitespace tokens are lowercased, with formatting
//! punctuation trimmed from their edges. Normalisation never changes a
//! number: signs, currency, units, percent and a leading decimal point stay
//! in their tokens. Each digest carries the evidence class the words were
//! said in, so the assistant saying something never stands in for the user
//! saying it. A paraphrase is new material; only the same words are held.

use std::collections::BTreeSet;

use crate::claim::ClaimSource;

/// Punctuation that only formats a token: trimmed from its edges. A sign,
/// a currency symbol, a unit or a percent is part of what the token says,
/// and so is a number's leading `.` or `,` before a digit.
const FORMATTING: &[char] = &[
    '"', '\'', '“', '”', '‘', '’', '«', '»', '「', '」', '『', '』', '.', ',', '!', '?', ':', ';',
    '(', ')', '[', ']', '*', '_', '`', '…', '、', '。', '！', '？',
];
/// Tokens that only mark a list item or a quote where a sentence starts.
const BULLETS: &[&str] = &["-", "–", "—", "•", "·", ">", "+"];

/// The statement digests of a text said in `class`: one per sentence with
/// words in it. A sentence ends at a line break, a CJK full stop, or `.`,
/// `!` or `?` before whitespace or the end, so a decimal point never splits
/// one.
pub(crate) fn statements(text: &str, class: Option<ClaimSource>) -> BTreeSet<[u8; 32]> {
    let mut out = BTreeSet::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((at, ch)) = chars.next() {
        let ends = match ch {
            '\n' | '。' | '！' | '？' => true,
            '.' | '!' | '?' => chars.peek().is_none_or(|(_, next)| next.is_whitespace()),
            _ => false,
        };
        if ends {
            out.extend(statement(&text[start..at], class));
            start = at + ch.len_utf8();
        }
    }
    out.extend(statement(&text[start..], class));
    out
}

fn statement(sentence: &str, class: Option<ClaimSource>) -> Option<[u8; 32]> {
    let tokens: Vec<String> = sentence
        .split_whitespace()
        .skip_while(|token| BULLETS.contains(token))
        .map(|token| trim_token(token).to_lowercase())
        .filter(|token| !token.is_empty())
        .collect();
    if tokens.is_empty() {
        return None;
    }
    let class = class.map_or("", ClaimSource::as_str);
    let mut hash = blake3::Hasher::new();
    hash.update(b"oneiron:dreamer-projector:statement:v3");
    hash.update(&(class.len() as u64).to_be_bytes());
    hash.update(class.as_bytes());
    hash.update(tokens.join(" ").as_bytes());
    Some(*hash.finalize().as_bytes())
}

/// A token without its formatting punctuation. A token with a digit keeps
/// a leading `.` or `,` that opens a number: `.5` is not `5`.
fn trim_token(token: &str) -> &str {
    let token = token.trim_end_matches(FORMATTING);
    if !token.chars().any(|ch| ch.is_ascii_digit()) {
        return token.trim_start_matches(FORMATTING);
    }
    let mut rest = token;
    while let Some(first) = rest.chars().next() {
        let after = &rest[first.len_utf8()..];
        let opens_number =
            matches!(first, '.' | ',') && after.starts_with(|ch: char| ch.is_ascii_digit());
        if !FORMATTING.contains(&first) || opens_number {
            break;
        }
        rest = after;
    }
    rest
}
