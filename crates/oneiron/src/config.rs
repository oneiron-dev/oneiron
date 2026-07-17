//! Caller-facing runtime configuration: `VaultConfig` + `HnswConfig` + `TextAnalyzerConfig` + `TextIndexOptions` + `Bm25RankProfile`.

use std::path::PathBuf;

/// HNSW configuration values.
///
/// The distance metric and index structure are fixed by the storage contract
/// and persisted as compatibility tags, not exposed as runtime tuning knobs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct HnswConfig {
    /// Maximum neighbors per node in layer 0.
    pub m_max_0: usize,
    /// Beam width used during graph construction.
    pub ef_construction: usize,
    /// Beam width used during search. Search-time only; not part of persisted
    /// HNSW compatibility metadata.
    pub ef_search: usize,
}

impl Default for HnswConfig {
    fn default() -> Self {
        Self {
            m_max_0: 64,
            ef_construction: 200,
            ef_search: 128,
        }
    }
}

/// Vault runtime configuration.
///
/// The struct is `#[non_exhaustive]`, so downstream callers cannot build it
/// with a struct literal. Use one of the presets (`VaultConfig::device()`
/// or `VaultConfig::server()`, or `VaultConfig::default()` which aliases
/// `device()`) and mutate fields as needed:
///
/// ```
/// # use oneiron::VaultConfig;
/// let mut cfg = VaultConfig::default();
/// cfg.dimensions = 768;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VaultConfig {
    /// Embedding vector dimension.
    pub dimensions: usize,
    /// MRL fast-lane prefix length (ONE-EMBED E3). When `Some(fd)`, the NSW
    /// graph is built and traversed over the first `fd` vector components
    /// and queries may be either full-length or `fd`-length; top candidates
    /// are exact-rescored against full-dim rows unless skip-rescore is set.
    /// Must satisfy `1 <= fd < dimensions`. `None` = full-dim graph (the
    /// previous behavior). The concrete value (256/384) is the bake-off's
    /// output — this stays config, never a compiled constant.
    ///
    /// Recall tradeoff: the funnel trades recall for traversal speed.
    /// Candidate selection happens in the prefix space, and the rescore is
    /// exact only over the retrieved beam — a vector distant in the prefix
    /// but near in full dimensions can fall outside the beam and be missed
    /// entirely. Recall is bounded by the beam width
    /// (`hnsw.ef_search.max(limit)`) and rises with `ef_search`.
    ///
    /// Turning `fast_dims` on (or changing it) for an existing POPULATED
    /// vault is a graph-shape change and is not supported online: the open
    /// fails with [`crate::Error::HnswConfigChanged`]. Re-create the vault,
    /// or ride EMB-4's `begin_embedding_migration` re-embed once that lands.
    pub fast_dims: Option<u16>,
    /// Embedding model identifier used for vector compatibility checks.
    ///
    /// `None` is allowed only for genuinely vector-less vaults. Once vector
    /// or HNSW data exists, opening the vault requires `Some` with the same
    /// model identifier stored on disk, and vector writes require a stamped
    /// model identity before the first vector is committed.
    pub embedding_model: Option<String>,
    /// LMDB map size in bytes.
    pub map_size: usize,
    /// Maximum LMDB reader slots.
    pub max_readers: u32,
    /// HNSW tuning configuration.
    pub hnsw: HnswConfig,
    /// Text analyzer configuration (plan ONE-317 §2.3).
    pub text_analyzer: TextAnalyzerConfig,
    /// Roots probed at open time for per-language dictionaries
    /// (`<path>/ja/system.dic`, `<path>/ko/system.dic`,
    /// `<path>/zh/jieba.dict.utf8`). First-found wins per-language; missing
    /// dicts silently downgrade the affected language to Portable mode.
    ///
    /// **Security.** Every path here is opened and (for Sudachi/jieba)
    /// read in full at `Vault::open`. Callers MUST only include paths they
    /// trust — e.g. the iOS app bundle's `Resources/` directory, or a
    /// packager-controlled cache directory. Do NOT pass user-uploaded
    /// directories, network mounts, or world-writable locations: a hostile
    /// dict file can drive Sudachi / jieba / Lindera into unexpected
    /// behavior, and the dict-bytes hash is then baked into the LMDB
    /// analyzer manifest, silently pinning the vault to that dict.
    pub dict_search_paths: Vec<PathBuf>,
    /// Skip the text-index manifest handshake at [`crate::Vault::open`] so the
    /// caller can reach [`crate::MaintenanceBuilder::clear_text_index`]
    /// after a dict swap or BM25 field-schema change. Without this escape
    /// hatch, [`crate::Error::IncompatibleAnalyzer`] and
    /// [`crate::Error::Bm25FieldSchemaChanged`] trap the user before any
    /// `Vault` exists to call `.maintain()` on.
    ///
    /// Only use this to immediately run `clear_text_index`. On a populated
    /// vault, [`crate::Vault::open`] marks the text index untrusted and
    /// [`crate::Vault::search_text`] (and the pipeline / context_pack
    /// callers that go through the same internal trust gate)
    /// returns [`crate::Error::CorruptedIndex`] until the clear commits.
    pub skip_text_index_manifest_check: bool,
}

/// Text analyzer configuration. Kept minimal in v1 — the full analyzer
/// manifest (normalization policy, per-channel schema, lang modes) is
/// computed from dict discovery at open time and stored in the vault's
/// on-disk manifest. Fields here cover caller-controllable knobs only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TextAnalyzerConfig {}

/// Per-call overrides for `BatchBuilder::text`. Reserved; v1 ignores all
/// fields but the struct is public so downstream can adopt without a
/// minor-version bump later.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct TextIndexOptions {
    /// Explicit language hint for this batch of text fields. Overrides
    /// `whichlang` detection on Latin/Cyrillic/Greek runs and the
    /// DualHanFallback decision on Han runs. Unambiguous-script runs
    /// (Hiragana, Katakana, Hangul, Hebrew, Thai, Lao, Khmer, Myanmar)
    /// route by their own script class regardless of this hint — the
    /// script is the stronger signal.
    pub language_hint: Option<crate::analyzer::LanguageHint>,
}

/// Scoring-only BM25F rank profile (ARCH-0031 §bm25f, ARCH-0019 D3).
///
/// Selects the BM25 scoring formula — [`Bm25Formula::Okapi`] (default) vs
/// [`Bm25Formula::Plus`]`{ delta }` — and overrides per-channel `weight`
/// / `b` for the four v1 analyzer channels (`Surface`, `Stem`,
/// `NormalizedOverlay`, `CjkNgram`). `k1` stays pinned at the contract's
/// global `1.2` and is not configurable.
///
/// The profile is applied at query time only. It never participates in
/// the on-disk analyzer manifest or the BM25F field-schema hash, so
/// changing it never requires a reindex (ARCH-0031: "Weights are
/// scoring-only — changing them doesn't require reindex").
///
/// A channel override with `weight == 0.0` excludes that channel from
/// scoring entirely. Overrides accumulate; the last override per channel
/// wins. Validation is fail-closed at the point of use
/// ([`crate::Vault::search_text_with_profile`] /
/// [`crate::PipelineBuilder::rank_profile`]): non-finite or negative
/// weights, `b` outside `[0.0, 1.0]`, a non-finite or non-positive
/// BM25+ `delta`, and overrides on reserved channels (`Shingle`,
/// `Synonym`, `Phonetic` — never emitted in v1) are rejected with
/// [`crate::Error::InvalidRankProfile`].
///
/// [`Bm25Formula::Okapi`]: crate::Bm25Formula::Okapi
/// [`Bm25Formula::Plus`]: crate::Bm25Formula::Plus
#[derive(Debug, Clone, PartialEq)]
#[must_use = "a rank profile only affects scoring when passed to a query"]
pub struct Bm25RankProfile {
    formula: crate::bm25::Bm25Formula,
    weight_overrides: Vec<(crate::analyzer::AnalyzerChannel, f64)>,
    b_overrides: Vec<(crate::analyzer::AnalyzerChannel, f64)>,
}

impl Default for Bm25RankProfile {
    /// The contract default profile: Okapi formula, no channel overrides
    /// (Surface 1.00/0.75, Stem 0.35/0.65, NormalizedOverlay 0.55/0.00,
    /// CjkNgram 0.45/0.30 per the ARCH-0031 channel table).
    fn default() -> Self {
        Self {
            formula: crate::bm25::Bm25Formula::Okapi,
            weight_overrides: Vec::new(),
            b_overrides: Vec::new(),
        }
    }
}

impl Bm25RankProfile {
    /// Selects the BM25 scoring formula. `Okapi` is the contract default;
    /// `Plus { delta }` is the BM25+ option (`delta` must be finite and
    /// `> 0.0`; the contract opt-in value is `delta: 1.0`).
    pub fn with_formula(mut self, formula: crate::bm25::Bm25Formula) -> Self {
        self.formula = formula;
        self
    }

    /// Overrides the scoring weight of one of the four v1 channels.
    /// `0.0` excludes the channel from scoring. Must be finite and
    /// `>= 0.0`; validated fail-closed at query time.
    pub fn with_channel_weight(
        mut self,
        channel: crate::analyzer::AnalyzerChannel,
        weight: f64,
    ) -> Self {
        self.weight_overrides.push((channel, weight));
        self
    }

    /// Overrides the BM25 length-norm `b` of one of the four v1 channels.
    /// Must be finite and within `[0.0, 1.0]`; validated fail-closed at
    /// query time. Note `NormalizedOverlay` scores under the `NoNorm`
    /// length policy, so its `b` is inert by contract.
    pub fn with_channel_b(mut self, channel: crate::analyzer::AnalyzerChannel, b: f64) -> Self {
        self.b_overrides.push((channel, b));
        self
    }

    /// Validates the profile and lowers it onto the internal scoring
    /// config. Fail-closed: any invalid parameter is a typed
    /// [`Error::InvalidRankProfile`], never a clamp or a silent skip.
    pub(crate) fn to_bm25_config(&self) -> Result<crate::bm25::Bm25Config, crate::error::Error> {
        use crate::analyzer::AnalyzerChannel;
        use crate::bm25::{Bm25Config, Bm25Formula};
        use crate::error::Error;

        fn scored_slot(
            channel: AnalyzerChannel,
            parameter: &'static str,
        ) -> Result<usize, crate::error::Error> {
            // Only the four v1 channels are scoreable; reserved channels
            // are never emitted, so an override there is a caller bug.
            if !AnalyzerChannel::ALL_V1.contains(&channel) {
                return Err(Error::InvalidRankProfile {
                    parameter,
                    value: f64::from(channel.field_id()),
                });
            }
            Ok(channel.field_id() as usize)
        }

        if let Bm25Formula::Plus { delta } = self.formula
            && (!delta.is_finite() || delta <= 0.0)
        {
            return Err(Error::InvalidRankProfile {
                parameter: "formula.delta",
                value: delta,
            });
        }

        let mut config = Bm25Config {
            formula: self.formula,
            ..Bm25Config::default()
        };

        for &(channel, weight) in &self.weight_overrides {
            let slot = scored_slot(channel, "weight.reserved_channel")?;
            if !weight.is_finite() || weight < 0.0 {
                return Err(Error::InvalidRankProfile {
                    parameter: "channel.weight",
                    value: weight,
                });
            }
            config.fields[slot].weight = weight;
        }

        for &(channel, b) in &self.b_overrides {
            let slot = scored_slot(channel, "b.reserved_channel")?;
            if !b.is_finite() || !(0.0..=1.0).contains(&b) {
                return Err(Error::InvalidRankProfile {
                    parameter: "channel.b",
                    value: b,
                });
            }
            config.fields[slot].b = b;
        }

        Ok(config)
    }
}

impl Default for VaultConfig {
    /// Aliases `VaultConfig::device()` — the common default. Call
    /// `VaultConfig::server()` explicitly if you want the server preset.
    fn default() -> Self {
        Self::device()
    }
}

impl VaultConfig {
    /// Returns a device-optimized preset.
    #[must_use]
    pub fn device() -> Self {
        Self {
            dimensions: 1024,
            fast_dims: None,
            embedding_model: None,
            map_size: 1 << 30,
            max_readers: 126,
            hnsw: HnswConfig::default(),
            text_analyzer: TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            skip_text_index_manifest_check: false,
        }
    }

    /// Returns a server-optimized preset.
    #[must_use]
    pub fn server() -> Self {
        Self {
            dimensions: 4096,
            fast_dims: None,
            embedding_model: None,
            map_size: 1 << 33,
            max_readers: 126,
            hnsw: HnswConfig::default(),
            text_analyzer: TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            skip_text_index_manifest_check: false,
        }
    }
}
