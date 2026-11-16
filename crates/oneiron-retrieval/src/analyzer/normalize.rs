//! Pre-tokenization normalization helpers.
//!
//! ICU4X provides the canonical implementations; kana folding is a small
//! hand-rolled mapping (U+30A1..U+30F6 → U+3041..U+3096) because ICU4X does
//! not offer a standalone katakana→hiragana transform.
//!
//! Khmer syllables are put in UTN #61 order before NFKC ([`super::khmer`],
//! ONE-COENG). Myanmar Zawgyi detection and conversion (ONE-ZAWGYI) is still
//! a follow-up (ARCH-0031 `#deferred`).

use std::borrow::Cow;

use icu_casemap::CaseMapper;
use icu_normalizer::ComposingNormalizer;
use unicode_segmentation::UnicodeSegmentation;

use super::khmer::{self, SyllableScanner};
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

/// Result of applying Khmer canonical order, NFKC and casefold to an input,
/// with enough metadata to remap a byte offset on the normalized side back
/// to the original.
///
/// Normalization is applied grapheme-by-grapheme so combining-mark
/// recomposition inside a cluster (e.g. halfwidth `ｶ` + `ﾞ` → `ガ`) still
/// fires, while the offset-remap step keeps token offsets pointing at the
/// *original* UTF-8 per plan §3.3. A Khmer syllable that runs across
/// graphemes (the consonant after COENG starts a new one) is one unit, so a
/// token inside a reordered syllable maps back to the whole syllable.
#[derive(Debug)]
pub struct NormalizedText<'a> {
    inner: Inner<'a>,
}

#[derive(Debug)]
enum Inner<'a> {
    Unchanged(&'a str),
    Owned {
        text: String,
        /// Sorted `(norm_byte, orig_byte)` boundaries at every unit
        /// transition (a grapheme, or the graphemes of one Khmer syllable),
        /// including `(0, 0)` and `(text.len(), input.len())`.
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
                        .map_or(0, |&(_, o)| o),
                }
            }
        }
    }
}

/// Apply the pre-tokenization stage of `policy` (Khmer canonical order, then
/// NFKC + default casefold) to `input`, producing a [`NormalizedText`].
/// Returns `Unchanged` whenever the policy is off or the transform is a
/// no-op.
pub fn normalize_with_offset_map<'a>(
    input: &'a str,
    policy: &NormalizationPolicy,
) -> NormalizedText<'a> {
    if (!policy.nfkc && !policy.casefold && !policy.khmer_coeng) || input.is_empty() {
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
    let khmer_coeng = policy.khmer_coeng;
    let mut syllables = khmer_coeng.then(SyllableScanner::default);

    // One unit is one grapheme, or the graphemes one Khmer syllable spans.
    let mut unit_start = 0;
    let mut unit_end = 0;
    let mut normalize_unit = |start: usize, end: usize, out: &mut String| {
        let unit = &input[start..end];
        let mut chunk: Cow<'_, str> = if khmer_coeng {
            khmer::canonical_order(unit)
        } else {
            Cow::Borrowed(unit)
        };
        if matches!(chunk, Cow::Owned(_)) {
            changed = true;
        }
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
        boundaries.push((out.len() as u32, end as u32));
    };
    for (orig_start, grapheme) in input.grapheme_indices(true) {
        let joins = syllables
            .as_mut()
            .is_some_and(|scanner| scanner.joins_previous(grapheme));
        if !joins && unit_end > unit_start {
            normalize_unit(unit_start, unit_end, &mut out);
            unit_start = orig_start;
        }
        unit_end = orig_start + grapheme.len();
    }
    if unit_end > unit_start {
        normalize_unit(unit_start, unit_end, &mut out);
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
    fn a_reordered_khmer_syllable_maps_back_to_its_whole_span() {
        // ស្ត្រី typed COENG RO first: six chars, 18 bytes, one syllable over
        // three graphemes. The canonical form is as long, so only the
        // boundaries show that the syllable is one unit.
        let typed = "\u{179F}\u{17D2}\u{179A}\u{17D2}\u{178F}\u{17B8} ok";
        let canonical = "\u{179F}\u{17D2}\u{178F}\u{17D2}\u{179A}\u{17B8} ok";
        let policy = NormalizationPolicy::default();
        let out = normalize_with_offset_map(typed, &policy);
        assert_eq!(out.as_str(), canonical);
        assert_eq!(out.remap(0), 0);
        assert_eq!(out.remap(3), 0);
        assert_eq!(out.remap_end(3), 18);
        assert_eq!(out.remap_end(18), 18);
        assert_eq!(out.remap(19), 19);
    }

    #[test]
    fn khmer_order_is_off_without_its_flag() {
        let typed = "\u{179F}\u{17D2}\u{179A}\u{17D2}\u{178F}\u{17B8}";
        let policy = NormalizationPolicy {
            khmer_coeng: false,
            ..NormalizationPolicy::default()
        };
        let out = normalize_with_offset_map(typed, &policy);
        assert!(out.is_unchanged());
        assert_eq!(out.as_str(), typed);
    }
}
