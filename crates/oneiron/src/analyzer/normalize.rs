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
use unicode_segmentation::UnicodeSegmentation;

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

/// Result of applying NFKC + casefold to an input, with enough metadata to
/// remap a byte offset on the normalized side back to the original.
///
/// Normalization is applied grapheme-by-grapheme so combining-mark
/// recomposition inside a cluster (e.g. halfwidth `ｶ` + `ﾞ` → `ガ`) still
/// fires, while the offset-remap step keeps token offsets pointing at the
/// *original* UTF-8 per plan §3.3.
#[derive(Debug)]
pub struct NormalizedText<'a> {
    inner: Inner<'a>,
}

#[derive(Debug)]
enum Inner<'a> {
    Unchanged(&'a str),
    Owned {
        text: String,
        /// Sorted `(norm_byte, orig_byte)` boundaries at every grapheme
        /// transition, including `(0, 0)` and `(text.len(), input.len())`.
        boundaries: Vec<(u32, u32)>,
    },
}

impl<'a> NormalizedText<'a> {
    fn unchanged(input: &'a str) -> Self {
        Self {
            inner: Inner::Unchanged(input),
        }
    }

    pub fn as_str(&self) -> &str {
        match &self.inner {
            Inner::Unchanged(s) => s,
            Inner::Owned { text, .. } => text.as_str(),
        }
    }

    pub fn is_unchanged(&self) -> bool {
        matches!(self.inner, Inner::Unchanged(_))
    }

    /// Translate a byte offset in the normalized text back to the original.
    ///
    /// Falls back to the preceding grapheme boundary if `norm_off` lands
    /// mid-grapheme. Word-aware segmenters (`unicode_word_indices`, ICU4X,
    /// Sudachi/jieba/Lindera) respect grapheme boundaries, so the fallback
    /// only matters for pathological inputs.
    pub fn remap(&self, norm_off: u32) -> u32 {
        match &self.inner {
            Inner::Unchanged(_) => norm_off,
            Inner::Owned { boundaries, .. } => {
                match boundaries.binary_search_by_key(&norm_off, |&(n, _)| n) {
                    Ok(i) => boundaries[i].1,
                    Err(i) => boundaries[i.saturating_sub(1)].1,
                }
            }
        }
    }
}

/// Apply the pre-tokenization stage of `policy` (NFKC + default casefold)
/// to `input`, producing a [`NormalizedText`]. Returns `Unchanged` whenever
/// the policy is off or the transform is a no-op.
pub fn normalize_with_offset_map<'a>(
    input: &'a str,
    policy: &NormalizationPolicy,
) -> NormalizedText<'a> {
    if (!policy.nfkc && !policy.casefold) || input.is_empty() {
        return NormalizedText::unchanged(input);
    }

    // All-ASCII-lowercase bytes are a fixpoint of NFKC + default casefold;
    // skip the grapheme walk that would otherwise dominate the latency of
    // typical English indexing.
    if input
        .bytes()
        .all(|b| b.is_ascii() && !b.is_ascii_uppercase())
    {
        return NormalizedText::unchanged(input);
    }

    // Build the ICU handles once; constructing them per grapheme would
    // dominate the cost of a long-document normalization pass.
    let normalizer = policy.nfkc.then(ComposingNormalizer::new_nfkc);
    let case_mapper = policy.casefold.then(CaseMapper::new);

    let mut out = String::with_capacity(input.len());
    let mut boundaries: Vec<(u32, u32)> = Vec::with_capacity(input.len() / 3 + 2);
    boundaries.push((0, 0));
    let mut changed = false;

    for (orig_start, grapheme) in input.grapheme_indices(true) {
        let mut chunk: Cow<'_, str> = Cow::Borrowed(grapheme);
        if let Some(n) = normalizer.as_ref()
            && let Cow::Owned(s) = n.normalize(&chunk)
        {
            chunk = Cow::Owned(s);
            changed = true;
        }
        if let Some(c) = case_mapper.as_ref()
            && let Cow::Owned(s) = c.fold_string(&chunk)
        {
            chunk = Cow::Owned(s);
            changed = true;
        }
        out.push_str(&chunk);
        let orig_end = (orig_start + grapheme.len()) as u32;
        boundaries.push((out.len() as u32, orig_end));
    }

    if !changed {
        return NormalizedText::unchanged(input);
    }

    NormalizedText {
        inner: Inner::Owned {
            text: out,
            boundaries,
        },
    }
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

    #[test]
    fn normalize_with_offset_map_unchanged_for_plain_ascii() {
        let policy = NormalizationPolicy::default();
        let out = normalize_with_offset_map("hello world", &policy);
        assert!(out.is_unchanged());
        assert_eq!(out.as_str(), "hello world");
    }

    #[test]
    fn normalize_with_offset_map_folds_fullwidth_and_remaps() {
        let policy = NormalizationPolicy::default();
        let out = normalize_with_offset_map("ＡＢＣ", &policy);
        assert_eq!(out.as_str(), "abc");
        // Each fullwidth char is 3 bytes UTF-8; normalized bytes are 1 each.
        assert_eq!(out.remap(0), 0);
        assert_eq!(out.remap(1), 3);
        assert_eq!(out.remap(2), 6);
        assert_eq!(out.remap(3), 9);
    }

    #[test]
    fn normalize_with_offset_map_merges_halfwidth_dakuten() {
        // `ｶﾞ` (halfwidth ka + halfwidth dakuten) is a single grapheme
        // cluster; NFKC must recompose it into `ガ`.
        let policy = NormalizationPolicy::default();
        let out = normalize_with_offset_map("ｶﾞ", &policy);
        assert_eq!(out.as_str(), "ガ");
        assert_eq!(out.remap(0), 0);
        // `ガ` is 3 bytes in UTF-8; the original `ｶﾞ` is 6.
        assert_eq!(out.remap(3), 6);
    }

    #[test]
    fn normalize_with_offset_map_respects_disabled_policy() {
        let policy = NormalizationPolicy {
            nfkc: false,
            casefold: false,
            kana_fold: false,
        };
        let out = normalize_with_offset_map("ＡＢＣ", &policy);
        assert!(out.is_unchanged());
        assert_eq!(out.as_str(), "ＡＢＣ");
    }
}
