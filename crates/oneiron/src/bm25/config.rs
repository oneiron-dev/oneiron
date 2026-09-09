//! Rank-profile config: field/channel params, formula, recency, defaults.
use crate::analyzer::AnalyzerChannel;

// === Rank profile configuration ===

/// Per-channel length normalization policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FieldLengthPolicy {
    /// Denominator uses `(1 - b) + b * len_f / avgdl_f`, i.e. classical
    /// BM25 length norm.
    CountLengthIncrement,
    /// No length norm — denominator is `1.0`. Useful for overlay channels
    /// whose token counts are mechanical (diacritic folds, kana folds)
    /// and should not drag long docs down.
    NoNorm,
}

impl FieldLengthPolicy {
    pub(crate) fn manifest_tag(self) -> &'static str {
        match self {
            FieldLengthPolicy::CountLengthIncrement => "count_length_increment",
            FieldLengthPolicy::NoNorm => "no_norm",
        }
    }
}

/// Per-field (channel) BM25F parameters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct FieldConfig {
    pub weight: f64,
    pub b: f64,
    pub length_policy: FieldLengthPolicy,
}

impl FieldConfig {
    pub(super) const fn disabled() -> Self {
        Self {
            weight: 0.0,
            b: 0.0,
            length_policy: FieldLengthPolicy::NoNorm,
        }
    }
}

/// BM25 scoring variant (ARCH-0031 / ARCH-0019 D3).
///
/// `Okapi` is the contract default. `Plus` is the BM25+ lower-bound
/// variant per Lv & Zhai 2011: it adds `idf · delta` to every matching
/// term's contribution (the contract opt-in value is `delta: 1.0`).
/// The formula is scoring-only — switching it never requires a reindex.
/// `delta` must be finite and strictly positive; it is validated
/// fail-closed when a [`crate::config::Bm25RankProfile`] is used and rejected
/// with [`crate::Error::InvalidRankProfile`] otherwise.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum Bm25Formula {
    /// Classical Okapi BM25 saturation (contract default).
    Okapi,
    /// BM25+ with a constant per-term lower bound (Lv & Zhai 2011).
    Plus {
        /// Constant added to the saturated TF term, scaled by `idf`.
        /// Must be finite and `> 0.0`; the contract opt-in is `1.0`.
        delta: f64,
    },
}

/// Global BM25F configuration. `fields` is indexed by channel — only
/// channels with non-zero weight contribute to scoring. Rank profile is a
/// scoring-only parameter (plan §4.2) — changing it does **not** require
/// a reindex, so this config lives outside the on-disk manifest.
#[derive(Debug, Clone)]
pub(crate) struct Bm25Config {
    pub(crate) k1: f64,
    pub(crate) formula: Bm25Formula,
    /// Per-channel config, indexed by [`AnalyzerChannel::field_id`]. The
    /// array has one slot per reserved channel, so adding a new channel
    /// in [`AnalyzerChannel`] requires extending this.
    pub(crate) fields: [FieldConfig; BM25_FIELD_COUNT],
}

/// Query-time recency blend for BM25F keyword ranking.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Bm25RecencyConfig {
    pub(crate) half_life_days: f64,
    pub(crate) boost: f64,
    pub(crate) now_secs: u64,
}

impl Bm25RecencyConfig {
    pub(super) fn is_enabled(self) -> bool {
        self.half_life_days.is_finite()
            && self.half_life_days > 0.0
            && self.boost.is_finite()
            && self.boost > 0.0
    }
}

/// One slot per reserved [`AnalyzerChannel`]. A new channel whose
/// `field_id()` falls outside `0..BM25_FIELD_COUNT` would silently
/// out-of-bounds index `Bm25Config::fields`; the const block below ties
/// this constant to the highest-id channel so adding a variant without
/// growing the array breaks the build.
pub(super) const BM25_FIELD_COUNT: usize = AnalyzerChannel::ALL_RESERVED.len();

const _: () = {
    // The reserved-channel set is `Surface, Stem, NormalizedOverlay,
    // CjkNgram, Shingle, Synonym, Phonetic`. `Phonetic` carries the
    // highest `field_id` (6), so this assert fires whenever a future
    // variant pushes the highest id past `BM25_FIELD_COUNT - 1`.
    assert!(
        AnalyzerChannel::Phonetic.field_id() as usize == BM25_FIELD_COUNT - 1,
        "Bm25Config::fields must grow when AnalyzerChannel gains a higher-id variant"
    );
};

impl Bm25Config {
    pub(crate) fn field(&self, channel: AnalyzerChannel) -> FieldConfig {
        self.fields[channel.field_id() as usize]
    }
}

impl Default for Bm25Config {
    fn default() -> Self {
        // Plan §1.3 default rank profile. Weights and `b` are research-band
        // starting values; ONE-318 bench tuning will replace them with
        // empirically-derived numbers.
        let mut fields = [FieldConfig::disabled(); BM25_FIELD_COUNT];
        fields[AnalyzerChannel::Surface.field_id() as usize] = FieldConfig {
            weight: 1.00,
            b: 0.75,
            length_policy: FieldLengthPolicy::CountLengthIncrement,
        };
        fields[AnalyzerChannel::Stem.field_id() as usize] = FieldConfig {
            weight: 0.35,
            b: 0.65,
            length_policy: FieldLengthPolicy::CountLengthIncrement,
        };
        fields[AnalyzerChannel::NormalizedOverlay.field_id() as usize] = FieldConfig {
            weight: 0.55,
            b: 0.00,
            length_policy: FieldLengthPolicy::NoNorm,
        };
        fields[AnalyzerChannel::CjkNgram.field_id() as usize] = FieldConfig {
            weight: 0.45,
            b: 0.30,
            length_policy: FieldLengthPolicy::CountLengthIncrement,
        };
        // Shingle / Synonym / Phonetic remain disabled; v1 analyzers do
        // not emit on these channels but the storage round-trips them.
        Self {
            k1: 1.2,
            formula: Bm25Formula::Okapi,
            fields,
        }
    }
}
