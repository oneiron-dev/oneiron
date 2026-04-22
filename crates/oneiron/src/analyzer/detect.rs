//! Language detection + `LanguageHint` resolution.
//!
//! Resolution chain (per plan §1.2, cheapest first):
//!   1. explicit hint passed through `AnalyzerContext`
//!   2. script-class inference for unambiguous scripts (Hiragana/Katakana → Ja,
//!      Hangul → Ko, Hebrew → He, Thai → Th, Lao → Lo, Khmer → Km, Myanmar → My)
//!   3. whichlang classifier over the first 512 bytes of the input
//!   4. `None` — caller falls back to DualHanFallback (Han-only runs) or
//!      Portable (everything else)
//!
//! `PerDocCache` memoizes the resolution so a single document with multiple
//! text fields runs whichlang at most once.
//!
//! whichlang does not cover Hindi in the `LanguageHint` v1 variant set; it
//! maps to `None` here and falls through to the caller's Portable path.

use whichlang::{Lang, detect_language as whichlang_detect};

use super::script::{ScriptClass, ScriptRun};
use super::token::LanguageHint;

pub const DETECT_WINDOW_BYTES: usize = 512;

pub fn detect_with_whichlang(text: &str) -> Option<LanguageHint> {
    if text.is_empty() {
        return None;
    }
    // Pure-ASCII Latin text short-circuits to English. whichlang is a
    // byte-n-gram classifier whose top-1 output is unstable on short or
    // low-entropy pure-ASCII inputs — `running` alone surfaces as `Ita`,
    // `"apple "` repeated surfaces as `Fra`. Asymmetric detection between
    // index (long doc) and query (short phrase) would write French stems
    // for a doc and probe English stems from the query, defeating the
    // `Stem` channel (see `latin::analyze`). Non-ASCII Latin (Spanish
    // `está`, German `straße`) still routes through whichlang and reaches
    // the correct Snowball algorithm.
    if is_pure_ascii_latin(text) {
        return Some(LanguageHint::En);
    }
    let window = truncate_at_char_boundary(text, DETECT_WINDOW_BYTES);
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

pub fn resolve(
    explicit: Option<LanguageHint>,
    runs: &[ScriptRun],
    text: &str,
) -> Option<LanguageHint> {
    if let Some(hint) = explicit {
        return Some(hint);
    }
    for run in runs {
        if let Some(hint) = infer_from_script(run.script) {
            return Some(hint);
        }
    }
    detect_with_whichlang(text)
}

/// Per-document language cache used by the composer to avoid re-running
/// whichlang on every field of a multi-field document.
#[derive(Debug, Default)]
pub struct PerDocCache {
    resolved: Option<Option<LanguageHint>>,
}

impl PerDocCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn resolve(
        &mut self,
        explicit: Option<LanguageHint>,
        runs: &[ScriptRun],
        text: &str,
    ) -> Option<LanguageHint> {
        if let Some(cached) = self.resolved {
            return cached;
        }
        let resolved = resolve(explicit, runs, text);
        self.resolved = Some(resolved);
        resolved
    }

    pub fn invalidate(&mut self) {
        self.resolved = None;
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
    use crate::analyzer::script::ScriptRunSplitter;

    #[test]
    fn explicit_hint_short_circuits_chain() {
        let runs = ScriptRunSplitter::new().runs("東京大学");
        let hint = resolve(Some(LanguageHint::Zh), &runs, "東京大学");
        assert_eq!(hint, Some(LanguageHint::Zh));
    }

    #[test]
    fn hiragana_infers_japanese() {
        let runs = ScriptRunSplitter::new().runs("とうきょう");
        assert_eq!(resolve(None, &runs, "とうきょう"), Some(LanguageHint::Ja));
    }

    #[test]
    fn katakana_infers_japanese() {
        let runs = ScriptRunSplitter::new().runs("トウキョウ");
        assert_eq!(resolve(None, &runs, "トウキョウ"), Some(LanguageHint::Ja));
    }

    #[test]
    fn hangul_infers_korean() {
        let runs = ScriptRunSplitter::new().runs("안녕하세요");
        assert_eq!(resolve(None, &runs, "안녕하세요"), Some(LanguageHint::Ko));
    }

    #[test]
    fn hebrew_infers_hebrew() {
        let text = "שלום עולם";
        let runs = ScriptRunSplitter::new().runs(text);
        assert_eq!(resolve(None, &runs, text), Some(LanguageHint::He));
    }

    #[test]
    fn thai_infers_thai() {
        let text = "สวัสดี";
        let runs = ScriptRunSplitter::new().runs(text);
        assert_eq!(resolve(None, &runs, text), Some(LanguageHint::Th));
    }

    #[test]
    fn han_only_falls_through_to_whichlang() {
        let text = "我喜欢学习中文";
        let runs = ScriptRunSplitter::new().runs(text);
        let hint = resolve(None, &runs, text);
        assert_eq!(hint, Some(LanguageHint::Zh));
    }

    #[test]
    fn spanish_latin_routes_via_whichlang() {
        let text = "El gato está durmiendo en la silla con el perro blanco";
        let runs = ScriptRunSplitter::new().runs(text);
        let hint = resolve(None, &runs, text);
        assert_eq!(hint, Some(LanguageHint::Es));
    }

    #[test]
    fn empty_text_returns_none() {
        assert_eq!(detect_with_whichlang(""), None);
        assert_eq!(resolve(None, &[], ""), None);
    }

    #[test]
    fn hindi_maps_to_none() {
        assert_eq!(map_whichlang_lang(Lang::Hin), None);
    }

    #[test]
    fn pure_ascii_latin_defaults_to_english() {
        assert_eq!(detect_with_whichlang("running"), Some(LanguageHint::En));
        assert_eq!(detect_with_whichlang("runs"), Some(LanguageHint::En));
        assert_eq!(detect_with_whichlang(&"apple ".repeat(20)), Some(LanguageHint::En));
        let prose = "she runs every morning before work near the riverbank";
        assert_eq!(detect_with_whichlang(prose), Some(LanguageHint::En));
    }

    #[test]
    fn non_ascii_latin_still_uses_whichlang() {
        let hint = detect_with_whichlang("está durmiendo en la silla");
        assert_eq!(hint, Some(LanguageHint::Es));
    }

    #[test]
    fn per_doc_cache_memoizes_resolution() {
        let text = "El gato está durmiendo en la silla";
        let runs = ScriptRunSplitter::new().runs(text);
        let mut cache = PerDocCache::new();
        let first = cache.resolve(None, &runs, text);
        let second = cache.resolve(None, &[], "");
        assert_eq!(first, second);
        assert_eq!(first, Some(LanguageHint::Es));
    }

    #[test]
    fn per_doc_cache_invalidate_reruns() {
        let mut cache = PerDocCache::new();
        assert_eq!(cache.resolve(Some(LanguageHint::Ja), &[], ""), Some(LanguageHint::Ja));
        cache.invalidate();
        assert_eq!(cache.resolve(Some(LanguageHint::Ko), &[], ""), Some(LanguageHint::Ko));
    }

    #[test]
    fn detect_window_truncates_at_char_boundary() {
        let text = "とう".repeat(1000);
        let out = truncate_at_char_boundary(&text, DETECT_WINDOW_BYTES);
        assert!(out.len() <= DETECT_WINDOW_BYTES);
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
    }

    #[test]
    fn pure_common_input_falls_through_to_whichlang_without_panic() {
        let text = "   !?? ...";
        let runs = ScriptRunSplitter::new().runs(text);
        let _ = resolve(None, &runs, text);
    }

    #[test]
    fn leading_common_does_not_force_inference() {
        let text = "   안녕하세요";
        let runs = ScriptRunSplitter::new().runs(text);
        let hint = resolve(None, &runs, text);
        assert_eq!(hint, Some(LanguageHint::Ko));
    }
}
