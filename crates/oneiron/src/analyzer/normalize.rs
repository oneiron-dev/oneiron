//! Pre-tokenization normalization helpers.
//!
//! ICU4X provides the canonical implementations; kana folding is a small
//! hand-rolled mapping (U+30A1..U+30F6 → U+3041..U+3096) because ICU4X does
//! not offer a standalone katakana→hiragana transform.
//!
//! Scripts outside the hand-rolled table (Zawgyi / Khmer COENG) are out of
//! scope for v1 — see plan §14 and follow-up tickets ONE-361 / ONE-362.

use std::borrow::Cow;

use icu_casemap::CaseMapper;
use icu_normalizer::ComposingNormalizer;

use super::manifest::NormalizationPolicy;

pub fn nfkc(input: &str) -> Cow<'_, str> {
    ComposingNormalizer::new_nfkc().normalize(input)
}

pub fn casefold(input: &str) -> Cow<'_, str> {
    CaseMapper::new().fold_string(input)
}

pub fn kana_fold(input: &str) -> Cow<'_, str> {
    if !input.chars().any(is_katakana_in_fold_range) {
        return Cow::Borrowed(input);
    }
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if is_katakana_in_fold_range(c) {
            let folded =
                char::from_u32((c as u32) - 0x60).expect("shift stays inside hiragana block");
            out.push(folded);
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
}

pub fn apply_pretokenize<'a>(input: &'a str, policy: &NormalizationPolicy) -> Cow<'a, str> {
    let mut current: Cow<'a, str> = Cow::Borrowed(input);
    if policy.nfkc {
        current = match nfkc(&current) {
            Cow::Borrowed(_) => current,
            Cow::Owned(s) => Cow::Owned(s),
        };
    }
    if policy.casefold {
        current = match casefold(&current) {
            Cow::Borrowed(_) => current,
            Cow::Owned(s) => Cow::Owned(s),
        };
    }
    current
}

pub fn kana_fold_overlay<'a>(input: &'a str, policy: &NormalizationPolicy) -> Option<Cow<'a, str>> {
    if !policy.kana_fold {
        return None;
    }
    match kana_fold(input) {
        Cow::Borrowed(_) => None,
        owned @ Cow::Owned(_) => Some(owned),
    }
}

fn is_katakana_in_fold_range(c: char) -> bool {
    matches!(c as u32, 0x30A1..=0x30F6)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nfkc_folds_fullwidth_ascii() {
        assert_eq!(nfkc("ＡＢＣ"), "ABC");
    }

    #[test]
    fn nfkc_folds_halfwidth_katakana() {
        assert_eq!(nfkc("ｶﾀｶﾅ"), "カタカナ");
    }

    #[test]
    fn nfkc_composes_ligatures() {
        assert_eq!(nfkc("ﬁ"), "fi");
    }

    #[test]
    fn casefold_lowers_ascii_and_german_ss() {
        assert_eq!(casefold("HELLO"), "hello");
        assert_eq!(casefold("Straße"), "strasse");
    }

    #[test]
    fn kana_fold_maps_katakana_to_hiragana() {
        assert_eq!(kana_fold("トウキョウ"), "とうきょう");
    }

    #[test]
    fn kana_fold_leaves_hiragana_unchanged() {
        let input = "とうきょう";
        let out = kana_fold(input);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, input);
    }

    #[test]
    fn kana_fold_leaves_latin_unchanged() {
        let input = "hello world";
        let out = kana_fold(input);
        assert!(matches!(out, Cow::Borrowed(_)));
        assert_eq!(&*out, input);
    }

    #[test]
    fn apply_pretokenize_chains_nfkc_then_casefold() {
        let policy = NormalizationPolicy::default();
        let out = apply_pretokenize("ＨＥＬＬＯ", &policy);
        assert_eq!(&*out, "hello");
    }

    #[test]
    fn apply_pretokenize_respects_disabled_flags() {
        let policy = NormalizationPolicy {
            nfkc: false,
            casefold: false,
            kana_fold: false,
        };
        let out = apply_pretokenize("ＨＥＬＬＯ", &policy);
        assert_eq!(&*out, "ＨＥＬＬＯ");
    }

    #[test]
    fn kana_fold_overlay_returns_none_when_disabled() {
        let policy = NormalizationPolicy {
            nfkc: false,
            casefold: false,
            kana_fold: false,
        };
        assert!(kana_fold_overlay("トウキョウ", &policy).is_none());
    }

    #[test]
    fn kana_fold_overlay_returns_none_when_no_change() {
        let policy = NormalizationPolicy::default();
        assert!(kana_fold_overlay("hello", &policy).is_none());
        assert!(kana_fold_overlay("とうきょう", &policy).is_none());
    }

    #[test]
    fn kana_fold_overlay_returns_change() {
        let policy = NormalizationPolicy::default();
        let out = kana_fold_overlay("トウキョウ", &policy).unwrap();
        assert_eq!(&*out, "とうきょう");
    }
}
