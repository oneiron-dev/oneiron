//! Rank-profile config: field/channel params, formula, recency, defaults.
use oneiron_base::analyzer::AnalyzerChannel;

// === Rank profile configuration ===

/// Per-channel length normalization policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldLengthPolicy {
    /// Denominator uses `(1 - b) + b * len_f / avgdl_f`, i.e. classical
    /// BM25 length norm.
    CountLengthIncrement,
    /// No length norm — denominator is `1.0`. Useful for overlay channels
    /// whose token counts are mechanical (diacritic folds, kana folds)
    /// and should not drag long docs down.
    NoNorm,
}

impl FieldLengthPolicy {
    pub fn manifest_tag(self) -> &'static str {
        match self {
            FieldLengthPolicy::CountLengthIncrement => "count_length_increment",
            FieldLengthPolicy::NoNorm => "no_norm",
        }
    }
}

/// Per-field (channel) BM25F parameters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FieldConfig {
    pub weight: f64,
    pub b: f64,
    pub length_policy: FieldLengthPolicy,
}

impl FieldConfig {
    pub const fn disabled() -> Self {
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
/// with [`StoreError::InvalidRankProfile`](oneiron_contracts::error::StoreError::InvalidRankProfile) otherwise.
#[derive(Debug, Clone, Copy, PartialEq)]
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
pub struct Bm25Config {
    pub k1: f64,
    pub formula: Bm25Formula,
    /// Per-channel config, indexed by [`AnalyzerChannel::field_id`]. The
    /// array has one slot per reserved channel, so adding a new channel
    /// in [`AnalyzerChannel`] requires extending this.
    pub fields: [FieldConfig; BM25_FIELD_COUNT],
}

/// Query-time recency blend for BM25F keyword ranking. Each row ages by
/// its entity type's half-life in the default pipeline's table
/// (`pipeline::retrieval_recency_half_life_days_for_type`), so a
/// keyword search and a pipeline run age a row alike (FIX 7781).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm25RecencyConfig {
    pub boost: f64,
    pub now_secs: u64,
}

/// Direct keyword search keeps its pre-learned-blend recency boost (FIX 12009).
const DIRECT_SEARCH_RECENCY_BOOST: f64 = 0.35;

impl Bm25RecencyConfig {
    /// The blend a direct keyword search runs by default (ARCH-0031
    /// `recencyBlend: "enabled-by-default"`): the fixed 0.35 boost, aged from
    /// `now_secs`, independent of the learned blend's recency share.
    pub fn table_default(now_secs: u64) -> Self {
        Self {
            boost: DIRECT_SEARCH_RECENCY_BOOST,
            now_secs,
        }
    }

    pub fn is_enabled(self) -> bool {
        self.boost.is_finite() && self.boost > 0.0
    }
}

/// One slot per reserved [`AnalyzerChannel`]. A new channel whose
/// `field_id()` falls outside `0..BM25_FIELD_COUNT` would silently
/// out-of-bounds index `Bm25Config::fields`; the const block below ties
/// this constant to the highest-id channel so adding a variant without
/// growing the array breaks the build.
pub const BM25_FIELD_COUNT: usize = AnalyzerChannel::ALL_RESERVED.len();

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
    pub fn field(&self, channel: AnalyzerChannel) -> FieldConfig {
        self.fields[channel.field_id() as usize]
    }

    /// The parameters the text field id `fid` scores under: its channel's,
    /// the weight scaled by the NOTE field's own when it is one (FIX 7789);
    /// `None` for an id no build writes.
    pub fn field_for_id(&self, fid: u16) -> Option<FieldConfig> {
        let (field, channel) = text_field_of_id(fid)?;
        let mut config = self.field(channel);
        if let Some(field) = field {
            config.weight *= field.weight();
        }
        Some(config)
    }
}

/// A NOTE's semantic text fields (ARCH-0032 #bm25f, FIX 7789). Each indexes
/// beside the analyzer channels under ids of its own
/// ([`text_field_id`]), with its own length statistics, and weighs its
/// channels' term frequencies by its own weight before the one saturation.
/// Every other text is pooled by channel, as before.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NoteTextField {
    Title,
    Tags,
    TargetNames,
    Body,
}

impl NoteTextField {
    pub const ALL: [Self; 4] = [Self::Title, Self::Tags, Self::TargetNames, Self::Body];

    /// The index-source field name a NOTE's text index publishes this
    /// field under. No other writer names a field so.
    pub const fn source_name(self) -> &'static str {
        match self {
            Self::Title => "note.title",
            Self::Tags => "note.tags",
            Self::TargetNames => "note.target_names",
            Self::Body => "note.body",
        }
    }

    /// The field an index-source field name publishes, when it is one.
    pub fn from_source_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|field| field.source_name() == name)
    }

    /// The ruled weight (ARCH-0032 #bm25f): title 2.0, tags 1.6, target
    /// names 1.4, body 1.0.
    pub const fn weight(self) -> f64 {
        match self {
            Self::Title => 2.0,
            Self::Tags => 1.6,
            Self::TargetNames => 1.4,
            Self::Body => 1.0,
        }
    }

    const fn slot(self) -> u16 {
        match self {
            Self::Title => 1,
            Self::Tags => 2,
            Self::TargetNames => 3,
            Self::Body => 4,
        }
    }

    const fn from_slot(slot: u16) -> Option<Self> {
        match slot {
            1 => Some(Self::Title),
            2 => Some(Self::Tags),
            3 => Some(Self::TargetNames),
            4 => Some(Self::Body),
            _ => None,
        }
    }
}

/// The text field id a token of `channel` indexes under: the channel's own
/// id for pooled text (`field` none), so every other kind's rows read as
/// they always have, and `(slot << 8) | channel` in a NOTE field.
pub const fn text_field_id(field: Option<NoteTextField>, channel: AnalyzerChannel) -> u16 {
    match field {
        None => channel.field_id(),
        Some(field) => (field.slot() << 8) | channel.field_id(),
    }
}

/// The NOTE field (none for pooled text) and the channel a text field id
/// names; `None` for an id no build writes.
pub fn text_field_of_id(fid: u16) -> Option<(Option<NoteTextField>, AnalyzerChannel)> {
    let channel = AnalyzerChannel::from_field_id(fid & 0xff)?;
    let field = match fid >> 8 {
        0 => None,
        slot => Some(NoteTextField::from_slot(slot)?),
    };
    Some((field, channel))
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
