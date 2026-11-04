//! Caller-facing runtime configuration: `VaultConfig` + `HnswConfig` + `TextAnalyzerConfig` + `TextIndexOptions` + `Bm25RankProfile`.

pub mod bm25;
pub mod community_graph;
pub mod context_spec;
pub mod retrieval_affect;
pub mod tagging;
pub use oneiron_base::config::failure_signals;

use std::path::PathBuf;

pub use oneiron_base::config::{
    DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES, HostingPrivacyPosture, PPR_VAD_ALPHA_DEFAULT,
    PPR_VAD_ALPHA_MAX, PPR_VAD_ALPHA_SWEEP, PprCommunityConfig, READER_SLOTS, TextAnalyzerConfig,
    TextIndexOptions, VaultDataKeyCustody, VaultPrivacyConfig, VectorEvidenceFloors,
    validate_ppr_community, validate_ppr_vad_alpha,
};
use oneiron_contracts::error::StoreError;

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
/// `device()`) and mutate fields as needed.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct VaultConfig {
    pub failure_signals: failure_signals::FailureSignalConfig,
    /// Injected engine clock and id source; each opened store gets its own floor.
    pub store_clock: crate::store_clock::StoreClock,
    /// Stored-edge VAD salience for PPR. Validated at query time in `0..=0.4`.
    /// Nonzero use requires the pinned BEAM recall and latency gate.
    pub ppr_vad_alpha: f32,
    /// Affect-weighted retrieval availability (OF-423): arousal-stretched
    /// aging, the critical/aroused sensitivity floor and emotion congruence.
    /// Every dial defaults off; validated when a run starts.
    pub affect_retrieval: crate::config::retrieval_affect::AffectRetrievalPolicy,
    /// Default-off community prior for Uniform (`expand_ppr`) retrieval only.
    pub ppr_community: PprCommunityConfig,
    /// Capture retrieval-run telemetry for ordinary searches. Disabled by default;
    /// enable explicitly for diagnostics or eval. This is a runtime setting,
    /// independent of the store's write-failure fuse.
    pub retrieval_telemetry_capture: bool,
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
    /// fails with [`StoreError::HnswConfigChanged`]. Re-create the vault,
    /// or ride EMB-4's `begin_embedding_migration` re-embed once that lands.
    pub fast_dims: Option<u16>,
    /// Embedding model identifier used for vector compatibility checks.
    ///
    /// `None` is allowed only for genuinely vector-less vaults. Once vector
    /// or HNSW data exists, opening the vault requires `Some` with the same
    /// model identifier stored on disk, and vector writes require a stamped
    /// model identity before the first vector is committed.
    pub embedding_model: Option<String>,
    /// How the host's embedder turns the model's output into stored vectors:
    /// an opaque descriptor of every setting that moves them under the same
    /// model. Pinned beside the model at open; a different descriptor is
    /// refused (`EmbeddingTransformChanged`), and a vault that has none
    /// adopts it. `None` checks nothing.
    pub embedding_transform: Option<String>,
    /// Where vector evidence starts in this vault's embedding space
    /// ([`VectorEvidenceFloors`]), as the host's embedder states it. Opening
    /// a vault refuses floors outside [`VectorEvidenceFloors::validate`]. A
    /// host that learns its provider's floors only once it is admitted sets
    /// them on the open vault (`Vault::set_vector_evidence`).
    pub vector_evidence: VectorEvidenceFloors,
    /// How long a call-mode recall may take before it answers with the best
    /// results ready (retrieval hub #call-mode). Defaults to
    /// `memory::DEFAULT_CALL_MODE_DEADLINE`, the ARCH-0042
    /// #call-mode-budget bar; a request's `deadline_ms` overrides it. Opening
    /// a vault refuses one outside 1 ms to
    /// `memory::caps::MAX_RECALL_DEADLINE_MS`.
    pub call_mode_deadline: std::time::Duration,
    /// Arms the tagging marker (ARCH-0036, serving the tagger): a base witness
    /// commits one marker per touched turn inside its own transaction, keyed
    /// by the turn and this tagger checkpoint, and the answer each marker
    /// settles on is saved as the turn's tags in its mode. `None` commits
    /// none.
    pub tagging: Option<crate::config::tagging::TaggingMarkerConfig>,
    /// LMDB map size in bytes.
    pub map_size: usize,
    /// Maximum LMDB reader slots. Both presets ask for [`READER_SLOTS`],
    /// which says why every opener of one vault asks for the same.
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
    /// Host display names that classify a stored TURN speaker as the
    /// assistant during dreamer consolidation, beside the generic
    /// `assistant | agent | ai | model` set. Each entry is matched after
    /// trimming and ASCII lowercasing. Empty by default: the assistant's
    /// voice name belongs to the host, never to the engine.
    pub assistant_display_names: Vec<String>,
    /// Skip the text-index manifest handshake at `Vault::open` so the
    /// caller can reach `maintain::MaintenanceBuilder::clear_text_index`
    /// after a dict swap or BM25 field-schema change. Without this escape
    /// hatch, [`StoreError::IncompatibleAnalyzer`] and
    /// [`StoreError::Bm25FieldSchemaChanged`] trap the user before any
    /// `Vault` exists to call `.maintain()` on.
    ///
    /// Only use this to immediately run `clear_text_index`. On a populated
    /// vault, `Vault::open` marks the text index untrusted and
    /// `Vault::search_text` (and the pipeline / context_pack
    /// callers that go through the same internal trust gate)
    /// returns `Error::CorruptedIndex` until the clear commits.
    pub skip_text_index_manifest_check: bool,
    /// Master kill-switch for entering off-record sessions. When disabled,
    /// enter fails closed before a registry entry or overlay is created.
    pub off_record_enabled: bool,
    /// Hard in-memory byte budget applied to each off-record session overlay.
    ///
    /// This budget is per-session and independent: nothing in the engine caps
    /// the number of concurrent off-record sessions, so aggregate overlay
    /// memory grows linearly with the concurrent session count and is NOT
    /// bounded by `DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES` (or this value)
    /// alone. Hosts that admit many simultaneous sessions must cap concurrency
    /// themselves to bound total overlay memory.
    pub off_record_overlay_budget_bytes: usize,
    /// What each engine `[limits]` row is set to (OF-520): work past one is
    /// served, and the port the host installed is asked whether everything is
    /// okay (`Vault::set_limit_ask`).
    pub limits: oneiron_contracts::limit_ask::EngineLimits,
    /// Deployment privacy posture and the key custody paired with it.
    ///
    /// Defaults to self-host/local with an owner-held local key for every
    /// preset, so an embedded caller never opts into hosting by accident.
    /// Hosted deployments set this explicitly and supply an opaque
    /// host-managed KMS key reference; the pairing is validated by every
    /// opener before the storage environment is mapped.
    pub privacy: VaultPrivacyConfig,
    /// What kind of machine this install is, as its host declares it (FIX
    /// 3349; CALLS: MACHINE_DEVICE_CLASS_SOURCE). This install's machine
    /// enrolment carries it and the owner approves it there; it is never read
    /// off the operating system. A phone holds no sealed copy of the vault.
    /// Both presets declare a computer; a phone's host sets
    /// `authority::MachineDeviceClass::Phone`.
    pub machine_device_class: oneiron_authority::authority::MachineDeviceClass,
    /// The maximum tier (OF-570): the page seal every LMDB page of the vault
    /// is sealed under. `None` opens a plain vault; a sealed one opens only
    /// with its seal (`world_keys::unlock_page_seal`), and a new one
    /// is created sealed with `world_keys::new_page_seal`.
    pub page_seal: Option<crate::vault_page_seal::VaultPageSeal>,
    /// Whether this vault's checkpoints carry its host-order legal holds,
    /// sealed to its host's recipient (FIX 6598): only a host sets one,
    /// from the recipient its supervisor delivered, never from the owner's
    /// settings. Both presets seal none, a self-hosted vault's way.
    pub checkpoint_host_holds: crate::checkpoint_host_recipient::HostHoldsSealing,
}

/// Scoring-only BM25F rank profile (ARCH-0031 §bm25f, ARCH-0019 D3).
///
/// Selects the BM25 scoring formula — [`Bm25Formula::Okapi`](crate::config::bm25::Bm25Formula::Okapi)
/// (default) vs [`Bm25Formula::Plus`](crate::config::bm25::Bm25Formula::Plus)`{ delta }` — and
/// overrides per-channel `weight` / `b` for the four v1 analyzer channels
/// (`Surface`, `Stem`, `NormalizedOverlay`, `CjkNgram`). `k1` stays pinned at the
/// contract's global `1.2` and is not configurable.
///
/// The profile is applied at query time only. It never participates in
/// the on-disk analyzer manifest or the BM25F field-schema hash, so
/// changing it never requires a reindex (ARCH-0031: "Weights are
/// scoring-only — changing them doesn't require reindex").
///
/// A channel override with `weight == 0.0` excludes that channel from
/// scoring entirely. Overrides accumulate; the last override per channel
/// wins. Validation is fail-closed at the point of use
/// (`Vault::search_text_with_profile` /
/// `PipelineBuilder::rank_profile`): non-finite or negative
/// weights, `b` outside `[0.0, 1.0]`, a non-finite or non-positive
/// BM25+ `delta`, and overrides on reserved channels (`Shingle`,
/// `Synonym`, `Phonetic` — never emitted in v1) are rejected with
/// [`StoreError::InvalidRankProfile`].
#[derive(Debug, Clone, PartialEq)]
#[must_use = "a rank profile only affects scoring when passed to a query"]
pub struct Bm25RankProfile {
    formula: crate::config::bm25::Bm25Formula,
    weight_overrides: Vec<(oneiron_base::analyzer::AnalyzerChannel, f64)>,
    b_overrides: Vec<(oneiron_base::analyzer::AnalyzerChannel, f64)>,
}

impl Default for Bm25RankProfile {
    /// The contract default profile: Okapi formula, no channel overrides
    /// (Surface 1.00/0.75, Stem 0.35/0.65, NormalizedOverlay 0.55/0.00,
    /// CjkNgram 0.45/0.30 per the ARCH-0031 channel table).
    fn default() -> Self {
        Self {
            formula: crate::config::bm25::Bm25Formula::Okapi,
            weight_overrides: Vec::new(),
            b_overrides: Vec::new(),
        }
    }
}

impl Bm25RankProfile {
    /// Selects the BM25 scoring formula. `Okapi` is the contract default;
    /// `Plus { delta }` is the BM25+ option (`delta` must be finite and
    /// `> 0.0`; the contract opt-in value is `delta: 1.0`).
    pub fn with_formula(mut self, formula: crate::config::bm25::Bm25Formula) -> Self {
        self.formula = formula;
        self
    }

    /// Overrides the scoring weight of one of the four v1 channels.
    /// `0.0` excludes the channel from scoring. Must be finite and
    /// `>= 0.0`; validated fail-closed at query time.
    pub fn with_channel_weight(
        mut self,
        channel: oneiron_base::analyzer::AnalyzerChannel,
        weight: f64,
    ) -> Self {
        self.weight_overrides.push((channel, weight));
        self
    }

    /// Overrides the BM25 length-norm `b` of one of the four v1 channels.
    /// Must be finite and within `[0.0, 1.0]`; validated fail-closed at
    /// query time. Note `NormalizedOverlay` scores under the `NoNorm`
    /// length policy, so its `b` is inert by contract.
    pub fn with_channel_b(
        mut self,
        channel: oneiron_base::analyzer::AnalyzerChannel,
        b: f64,
    ) -> Self {
        self.b_overrides.push((channel, b));
        self
    }

    /// Validates the profile and lowers it onto the internal scoring
    /// config. Fail-closed: any invalid parameter is a typed
    /// [`StoreError::InvalidRankProfile`], never a clamp or a silent skip.
    pub fn to_bm25_config(
        &self,
    ) -> Result<crate::config::bm25::Bm25Config, oneiron_contracts::error::Error> {
        use crate::config::bm25::{Bm25Config, Bm25Formula};
        use oneiron_base::analyzer::AnalyzerChannel;
        use oneiron_contracts::error::Error;

        fn scored_slot(
            channel: AnalyzerChannel,
            parameter: &'static str,
        ) -> Result<usize, oneiron_contracts::error::Error> {
            // Only the four v1 channels are scoreable; reserved channels
            // are never emitted, so an override there is a caller bug.
            if !AnalyzerChannel::ALL_V1.contains(&channel) {
                return Err(Error::Store(StoreError::InvalidRankProfile {
                    parameter,
                    value: f64::from(channel.field_id()),
                }));
            }
            Ok(channel.field_id() as usize)
        }

        if let Bm25Formula::Plus { delta } = self.formula
            && (!delta.is_finite() || delta <= 0.0)
        {
            return Err(Error::Store(StoreError::InvalidRankProfile {
                parameter: "formula.delta",
                value: delta,
            }));
        }

        let mut config = Bm25Config {
            formula: self.formula,
            ..Bm25Config::default()
        };

        for &(channel, weight) in &self.weight_overrides {
            let slot = scored_slot(channel, "weight.reserved_channel")?;
            if !weight.is_finite() || weight < 0.0 {
                return Err(Error::Store(StoreError::InvalidRankProfile {
                    parameter: "channel.weight",
                    value: weight,
                }));
            }
            config.fields[slot].weight = weight;
        }

        for &(channel, b) in &self.b_overrides {
            let slot = scored_slot(channel, "b.reserved_channel")?;
            if !b.is_finite() || !(0.0..=1.0).contains(&b) {
                return Err(Error::Store(StoreError::InvalidRankProfile {
                    parameter: "channel.b",
                    value: b,
                }));
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
            failure_signals: failure_signals::FailureSignalConfig::default(),
            store_clock: crate::store_clock::StoreClock::default(),
            ppr_vad_alpha: PPR_VAD_ALPHA_DEFAULT,
            affect_retrieval: crate::config::retrieval_affect::AffectRetrievalPolicy::default(),
            ppr_community: PprCommunityConfig::default(),
            retrieval_telemetry_capture: false,
            dimensions: 1024,
            fast_dims: None,
            embedding_model: None,
            embedding_transform: None,
            vector_evidence: VectorEvidenceFloors::default(),
            call_mode_deadline: oneiron_base::request_limits::DEFAULT_CALL_MODE_DEADLINE,
            tagging: None,
            privacy: VaultPrivacyConfig::default(),
            map_size: 1 << 30,
            max_readers: READER_SLOTS,
            hnsw: HnswConfig::default(),
            text_analyzer: TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            assistant_display_names: Vec::new(),
            skip_text_index_manifest_check: false,
            off_record_enabled: true,
            off_record_overlay_budget_bytes: DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES,
            limits: oneiron_contracts::limit_ask::EngineLimits::default(),
            machine_device_class: oneiron_authority::authority::MachineDeviceClass::Computer,
            page_seal: None,
            checkpoint_host_holds: crate::checkpoint_host_recipient::HostHoldsSealing::NotHosted,
        }
    }

    /// Returns a server-optimized preset.
    #[must_use]
    pub fn server() -> Self {
        Self {
            failure_signals: failure_signals::FailureSignalConfig::default(),
            store_clock: crate::store_clock::StoreClock::default(),
            ppr_vad_alpha: PPR_VAD_ALPHA_DEFAULT,
            affect_retrieval: crate::config::retrieval_affect::AffectRetrievalPolicy::default(),
            ppr_community: PprCommunityConfig::default(),
            retrieval_telemetry_capture: false,
            dimensions: 4096,
            fast_dims: None,
            embedding_model: None,
            embedding_transform: None,
            vector_evidence: VectorEvidenceFloors::default(),
            call_mode_deadline: oneiron_base::request_limits::DEFAULT_CALL_MODE_DEADLINE,
            tagging: None,
            // The server preset is still self-host/local by default: running a
            // server does not by itself mean a third party hosts the vault.
            privacy: VaultPrivacyConfig::default(),
            map_size: 1 << 33,
            max_readers: READER_SLOTS,
            hnsw: HnswConfig::default(),
            text_analyzer: TextAnalyzerConfig::default(),
            dict_search_paths: Vec::new(),
            assistant_display_names: Vec::new(),
            skip_text_index_manifest_check: false,
            off_record_enabled: true,
            off_record_overlay_budget_bytes: DEFAULT_OFF_RECORD_OVERLAY_BUDGET_BYTES,
            limits: oneiron_contracts::limit_ask::EngineLimits::default(),
            machine_device_class: oneiron_authority::authority::MachineDeviceClass::Computer,
            page_seal: None,
            checkpoint_host_holds: crate::checkpoint_host_recipient::HostHoldsSealing::NotHosted,
        }
    }

    /// This config, its checkpoints' host-order legal holds sealed to
    /// `recipient`, the one its host's supervisor pinned and delivered (FIX
    /// 6598); `None` where a host carries the vault and delivered none, which
    /// each checkpoint's receipt says is unavailable and never refuses.
    #[must_use]
    pub fn with_checkpoint_host_holds_recipient(
        mut self,
        recipient: Option<crate::checkpoint_host_recipient::HostHoldsRecipient>,
    ) -> Self {
        self.checkpoint_host_holds = match recipient {
            Some(recipient) => {
                crate::checkpoint_host_recipient::HostHoldsSealing::To(Box::new(recipient))
            }
            None => crate::checkpoint_host_recipient::HostHoldsSealing::RecipientMissing,
        };
        self
    }
}
