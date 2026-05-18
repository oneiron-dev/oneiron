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

    /// Translate a token's start byte offset back to the original.
    ///
    /// Rounds DOWN to the preceding grapheme boundary on a mid-grapheme
    /// offset — pairs with [`Self::remap_end`] which rounds UP, so a token
    /// emitted on an interior NFKC-expanded grapheme (e.g. `㍻`→`平成`)
    /// gets pinned to the full original grapheme rather than collapsing
    /// to a zero-width span.
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

    /// Translate a token's end byte offset back to the original, rounding
    /// UP to the next grapheme boundary on a mid-grapheme offset.
    ///
    /// Without rounding-up, NFKC expansions like `㍻` (3 bytes, 1 grapheme)
    /// → `平成` (6 bytes, 2 graphemes) would collapse the first emitted
    /// CJK token's `byte_end=3` to original `0` (preceding boundary),
    /// violating the public `Token` invariant `byte_start < byte_end`.
    pub fn remap_end(&self, norm_off: u32) -> u32 {
        match &self.inner {
            Inner::Unchanged(_) => norm_off,
            Inner::Owned { boundaries, .. } => {
                match boundaries.binary_search_by_key(&norm_off, |&(n, _)| n) {
                    Ok(i) => boundaries[i].1,
                    Err(i) => boundaries
                        .get(i)
                        .or_else(|| boundaries.last())
                        .map(|&(_, o)| o)
                        .unwrap_or(0),
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

    /// `kana_fold_overlay` returns `None` in two distinct scenarios.
    ///
    /// Variants:
    /// - `disabled_policy_with_katakana_input`: policy disables `kana_fold`,
    ///   so even katakana input that would normally fold returns `None`.
    /// - `default_policy_with_ascii_no_change`: default policy enabled, but
    ///   ASCII input has no katakana to fold — returns `None`.
    /// - `default_policy_with_hiragana_no_change`: default policy enabled,
    ///   already-hiragana input is unchanged — returns `None`.
    #[test]
    fn kana_fold_overlay_none_cases() {
        let disabled = NormalizationPolicy {
            nfkc: false,
            casefold: false,
            kana_fold: false,
        };
        let default_policy = NormalizationPolicy::default();

        let cases: Vec<(&str, &NormalizationPolicy, &str)> = vec![
            (
                "disabled_policy_with_katakana_input",
                &disabled,
                "トウキョウ",
            ),
            (
                "default_policy_with_ascii_no_change",
                &default_policy,
                "hello",
            ),
            (
                "default_policy_with_hiragana_no_change",
                &default_policy,
                "とうきょう",
            ),
        ];

        for (case_name, policy, input) in cases {
            assert!(
                kana_fold_overlay(input, policy).is_none(),
                "case {case_name}: expected None, got Some"
            );
        }
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
    fn remap_end_rounds_up_through_nfkc_expansion() {
        // `㍻` (U+337B, 3 bytes, 1 grapheme) → `平成` (6 bytes, 2 graphemes).
        // boundaries = [(0,0), (6,3)] — interior offsets must NOT collapse
        // a token's byte_end to 0 (preceding boundary). `remap_end` rounds
        // UP to the next boundary so the token stays pinned to the
        // original 3-byte grapheme.
        let policy = NormalizationPolicy::default();
        let out = normalize_with_offset_map("㍻", &policy);
        assert_eq!(out.as_str(), "平成");
        // Two normalized tokens at 0..3 (`平`) and 3..6 (`成`) must both
        // map to the original 0..3 span.
        assert_eq!(out.remap(0), 0);
        assert_eq!(out.remap_end(3), 3);
        assert_eq!(out.remap(3), 0);
        assert_eq!(out.remap_end(6), 3);
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
