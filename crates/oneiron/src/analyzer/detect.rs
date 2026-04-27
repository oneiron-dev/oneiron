//! Language detection + `LanguageHint` resolution.
//!
//! Per-run resolution chain (applied by the composer, cheapest first):
//!   1. script-class inference for unambiguous scripts (Hiragana/Katakana → Ja,
//!      Hangul → Ko, Hebrew → He, Thai → Th, Lao → Lo, Khmer → Km, Myanmar → My)
//!   2. explicit hint passed through `AnalyzerContext`
//!   3. `detect_with_whichlang` over the run's own bytes (first 512)
//!   4. `None` — caller falls back to DualHanFallback (Han-only runs) or
//!      Portable (everything else)
//!
//! whichlang does not cover Hindi in the `LanguageHint` v1 variant set; it
//! maps to `None` here and falls through to the caller's Portable path.

use whichlang::{Lang, detect_language as whichlang_detect};

use super::script::ScriptClass;
use super::token::LanguageHint;

pub const DETECT_WINDOW_BYTES: usize = 512;

/// Minimum byte count before whichlang is trusted on pure-ASCII Latin input.
/// whichlang 0.1.1 misroutes short pure-ASCII (`"running"` → Ita,
/// `"runs"` → Deu) because it is a bare byte-n-gram argmax with no
/// confidence signal. Below this threshold we short-circuit to English to
/// preserve symmetry between short English queries and English docs.
const MIN_WHICHLANG_ASCII_BYTES: usize = 64;
/// Minimum distinct ASCII letter tokens before whichlang is trusted on
/// pure-ASCII. Catches the low-entropy failure case (`"apple "` ×20)
/// that byte count alone lets through — 120 bytes of repeated `"apple "`
/// still surfaces as `Fra` empirically.
const MIN_WHICHLANG_ASCII_UNIQUE_WORDS: usize = 3;

/// Resolve a `LanguageHint` from free-form text.
///
/// Pure-ASCII Latin that is short (< `MIN_WHICHLANG_ASCII_BYTES` bytes)
/// or low-entropy (< `MIN_WHICHLANG_ASCII_UNIQUE_WORDS` unique letter
/// tokens) short-circuits to [`LanguageHint::En`] because whichlang
/// misclassifies such inputs; longer, diverser pure-ASCII routes through
/// whichlang and can resolve to Spanish/Portuguese/etc. correctly on the
/// index side. Queries are usually short and thus continue to resolve to
/// English; callers indexing accent-less non-English Latin who want
/// symmetric stem recall must pass an explicit
/// [`AnalyzerContext::with_language`](super::token::AnalyzerContext::with_language)
/// on the query side as well. A confidence-aware detector will obsolete
/// this heuristic (tracked as a follow-up).
pub fn detect_with_whichlang(text: &str) -> Option<LanguageHint> {
    if text.is_empty() {
        return None;
    }
    let window = truncate_at_char_boundary(text, DETECT_WINDOW_BYTES);
    if is_pure_ascii_latin(window)
        && (window.len() < MIN_WHICHLANG_ASCII_BYTES
            || unique_ascii_letter_tokens(window) < MIN_WHICHLANG_ASCII_UNIQUE_WORDS)
    {
        return Some(LanguageHint::En);
    }
    map_whichlang_lang(whichlang_detect(window))
}

fn is_pure_ascii_latin(text: &str) -> bool {
    let mut has_letter = false;
    for b in text.bytes() {
        if !b.is_ascii() {
            return false;
        }
        if b.is_ascii_alphabetic() {
            has_letter = true;
        }
    }
    has_letter
}

/// Count distinct ASCII letter-runs in `text`, case-insensitive.
///
/// Input is bounded by the caller's 512-byte detection window, so the
/// `Vec` backing the uniqueness check never exceeds ~50 entries.
fn unique_ascii_letter_tokens(text: &str) -> usize {
    let mut seen: Vec<&str> = Vec::new();
    let mut start: Option<usize> = None;
    for (i, b) in text.bytes().enumerate() {
        let is_letter = b.is_ascii_alphabetic();
        match (start, is_letter) {
            (None, true) => start = Some(i),
            (Some(s), false) => {
                push_unique(&mut seen, &text[s..i]);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        push_unique(&mut seen, &text[s..]);
    }
    seen.len()
}

fn push_unique<'a>(seen: &mut Vec<&'a str>, word: &'a str) {
    if !seen.iter().any(|w| w.eq_ignore_ascii_case(word)) {
        seen.push(word);
    }
}

pub fn map_whichlang_lang(lang: Lang) -> Option<LanguageHint> {
    match lang {
        Lang::Ara => Some(LanguageHint::Ar),
        Lang::Cmn => Some(LanguageHint::Zh),
        Lang::Deu => Some(LanguageHint::De),
        Lang::Eng => Some(LanguageHint::En),
        Lang::Fra => Some(LanguageHint::Fr),
        Lang::Hin => None,
        Lang::Ita => Some(LanguageHint::It),
        Lang::Jpn => Some(LanguageHint::Ja),
        Lang::Kor => Some(LanguageHint::Ko),
        Lang::Nld => Some(LanguageHint::Nl),
        Lang::Por => Some(LanguageHint::Pt),
        Lang::Rus => Some(LanguageHint::Ru),
        Lang::Spa => Some(LanguageHint::Es),
        Lang::Swe => Some(LanguageHint::Sv),
        Lang::Tur => Some(LanguageHint::Tr),
        Lang::Vie => Some(LanguageHint::Vi),
    }
}

pub fn infer_from_script(class: ScriptClass) -> Option<LanguageHint> {
    match class {
        ScriptClass::Greek => Some(LanguageHint::El),
        ScriptClass::Hiragana | ScriptClass::Katakana => Some(LanguageHint::Ja),
        ScriptClass::Hangul => Some(LanguageHint::Ko),
        ScriptClass::Hebrew => Some(LanguageHint::He),
        ScriptClass::Thai => Some(LanguageHint::Th),
        ScriptClass::Lao => Some(LanguageHint::Lo),
        ScriptClass::Khmer => Some(LanguageHint::Km),
        ScriptClass::Myanmar => Some(LanguageHint::My),
        _ => None,
    }
}

fn truncate_at_char_boundary(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_from_script_covers_unambiguous_scripts() {
        assert_eq!(
            infer_from_script(ScriptClass::Hiragana),
            Some(LanguageHint::Ja)
        );
        assert_eq!(
            infer_from_script(ScriptClass::Katakana),
            Some(LanguageHint::Ja)
        );
        assert_eq!(
            infer_from_script(ScriptClass::Hangul),
            Some(LanguageHint::Ko)
        );
        assert_eq!(
            infer_from_script(ScriptClass::Hebrew),
            Some(LanguageHint::He)
        );
        assert_eq!(infer_from_script(ScriptClass::Thai), Some(LanguageHint::Th));
        assert_eq!(infer_from_script(ScriptClass::Lao), Some(LanguageHint::Lo));
        assert_eq!(
            infer_from_script(ScriptClass::Khmer),
            Some(LanguageHint::Km)
        );
        assert_eq!(
            infer_from_script(ScriptClass::Myanmar),
            Some(LanguageHint::My)
        );
        assert_eq!(
            infer_from_script(ScriptClass::Greek),
            Some(LanguageHint::El)
        );
    }

    #[test]
    fn infer_from_script_returns_none_for_ambiguous_scripts() {
        assert_eq!(infer_from_script(ScriptClass::Latin), None);
        assert_eq!(infer_from_script(ScriptClass::Han), None);
        assert_eq!(infer_from_script(ScriptClass::Cyrillic), None);
        assert_eq!(infer_from_script(ScriptClass::Common), None);
    }

    #[test]
    fn han_only_routes_to_whichlang() {
        assert_eq!(
            detect_with_whichlang("我喜欢学习中文"),
            Some(LanguageHint::Zh)
        );
    }

    #[test]
    fn spanish_latin_routes_via_whichlang() {
        let text = "El gato está durmiendo en la silla con el perro blanco";
        assert_eq!(detect_with_whichlang(text), Some(LanguageHint::Es));
    }

    #[test]
    fn empty_text_returns_none() {
        assert_eq!(detect_with_whichlang(""), None);
    }

    #[test]
    fn hindi_maps_to_none() {
        assert_eq!(map_whichlang_lang(Lang::Hin), None);
    }

    #[test]
    fn pure_ascii_latin_defaults_to_english() {
        assert_eq!(detect_with_whichlang("running"), Some(LanguageHint::En));
        assert_eq!(detect_with_whichlang("runs"), Some(LanguageHint::En));
        assert_eq!(
            detect_with_whichlang(&"apple ".repeat(20)),
            Some(LanguageHint::En)
        );
        let prose = "she runs every morning before work near the riverbank";
        assert_eq!(detect_with_whichlang(prose), Some(LanguageHint::En));
    }

    #[test]
    fn non_ascii_latin_still_uses_whichlang() {
        let hint = detect_with_whichlang("está durmiendo en la silla");
        assert_eq!(hint, Some(LanguageHint::Es));
    }

    #[test]
    fn detect_window_truncates_at_char_boundary() {
        let text = "とう".repeat(1000);
        let out = truncate_at_char_boundary(&text, DETECT_WINDOW_BYTES);
        assert!(out.len() <= DETECT_WINDOW_BYTES);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn pure_common_input_does_not_panic() {
        let _ = detect_with_whichlang("   !?? ...");
    }

    #[test]
    fn long_accentless_spanish_resolves_to_spanish() {
        // ≥ 64 bytes AND ≥ 3 unique letter tokens — passes the length gate,
        // whichlang routes accent-less Spanish to `Spa`.
        let text = "el gato blanco come manzanas rojas en el jardin grande con su amigo pequeno";
        assert!(text.len() >= MIN_WHICHLANG_ASCII_BYTES);
        assert_eq!(detect_with_whichlang(text), Some(LanguageHint::Es));
    }

    #[test]
    fn short_accentless_spanish_falls_back_to_english() {
        // Residual asymmetry accepted for this PR: short non-English Latin
        // queries resolve to English via the length-gated short-circuit.
        // The follow-up confidence-aware detector will lift this.
        assert_eq!(detect_with_whichlang("hablando"), Some(LanguageHint::En));
    }

    #[test]
    fn low_entropy_long_ascii_stays_english() {
        // 120 bytes but 1 unique token — unique-word gate blocks whichlang
        // from misrouting repeated `"apple "` as `Fra`.
        let text = "apple ".repeat(20);
        assert_eq!(detect_with_whichlang(&text), Some(LanguageHint::En));
    }

    #[test]
    fn ascii_short_circuit_uses_window_not_full_text() {
        let text = format!("{}é", "a".repeat(DETECT_WINDOW_BYTES));
        assert_eq!(detect_with_whichlang(&text), Some(LanguageHint::En));
    }

    #[test]
    fn unique_ascii_letter_tokens_counts_distinct_casefolded_words() {
        assert_eq!(unique_ascii_letter_tokens("the the THE"), 1);
        assert_eq!(unique_ascii_letter_tokens("apple pear apple"), 2);
        assert_eq!(unique_ascii_letter_tokens("one two three"), 3);
        assert_eq!(unique_ascii_letter_tokens(""), 0);
        assert_eq!(unique_ascii_letter_tokens("   "), 0);
    }
}
