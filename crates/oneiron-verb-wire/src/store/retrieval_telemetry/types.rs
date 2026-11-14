//! Moved from `crates/oneiron/src/store/retrieval_telemetry/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use oneiron_base::error::Result;
pub use oneiron_contracts::retrieval_telemetry::RetrievalBlendSignal;
pub use oneiron_contracts::retrieval_telemetry::RetrievalBlendWeights;
pub use oneiron_contracts::retrieval_telemetry::RetrievalScoreComponent;
pub use oneiron_contracts::retrieval_telemetry::RetrievalSignal;
use serde::Deserialize;
use serde::Serialize;

pub const RETRIEVAL_TELEMETRY_VERSION: u8 = 0;

pub const RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION: u8 = 2;

pub const RETRIEVAL_BLEND_BOOTSTRAP_SOURCE: &str = "ret010b.bootstrap";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalAction {
    Pipeline,
    ContextPack,
    VaultSearch,
    GraphFsCoreutils,
    /// EMB-5 speculative fire over an ASR partial. Only speculative fires
    /// carry this tag (the end-of-utterance full-quality pass logs as
    /// `Pipeline`) — that is what makes wasted-retrieval budget measurable.
    Speculative,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalBlendWeightDataWindow {
    pub run_count: u32,
    pub outcome_count: u32,
    pub candidate_count: u32,
    pub started_at_min: Option<u64>,
    pub started_at_max: Option<u64>,
    pub outcome_updated_at_min: Option<u64>,
    pub outcome_updated_at_max: Option<u64>,
}

/// One owner-pinned blend weight. A pinned signal's normalized share stays at
/// `value`; learned updates may move only the unpinned remainder.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyPin {
    pub signal: RetrievalBlendSignal,
    pub value: f32,
}

/// The stored owner pins over the retrieval blend weights.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyPins {
    #[serde(default)]
    pub pins: Vec<RetrievalPolicyPin>,
}

impl RetrievalPolicyPins {
    #[must_use]
    pub fn value_for(&self, signal: RetrievalBlendSignal) -> Option<f32> {
        self.pins
            .iter()
            .find(|pin| pin.signal == signal)
            .map(|pin| pin.value)
    }

    pub fn validate(&self) -> Result<()> {
        let invalid = |reason: &str| Error::InvalidConfig(reason.to_owned());
        let mut total = 0.0_f32;
        for (index, pin) in self.pins.iter().enumerate() {
            if !pin.value.is_finite() || !(0.0..=1.0).contains(&pin.value) {
                return Err(invalid("retrieval policy pin value must be within 0..=1"));
            }
            if self.pins[..index]
                .iter()
                .any(|earlier| earlier.signal == pin.signal)
            {
                return Err(invalid("retrieval policy pins name each signal once"));
            }
            total += pin.value;
        }
        if total > 1.0 + f32::EPSILON {
            return Err(invalid("retrieval policy pins may not exceed total mass 1"));
        }
        if self.pins.len() == 5 && (total - 1.0).abs() > 1e-6 {
            return Err(invalid(
                "retrieval policy pins over every signal must sum to 1",
            ));
        }
        Ok(())
    }

    /// The weights with every pin held at its declared share and the
    /// unpinned signals scaled proportionally over the remaining mass.
    pub fn apply(&self, weights: RetrievalBlendWeights) -> Result<RetrievalBlendWeights> {
        self.validate()?;
        if self.pins.is_empty() {
            return weights.normalized();
        }
        let signals = [
            RetrievalBlendSignal::Recency,
            RetrievalBlendSignal::Salience,
            RetrievalBlendSignal::Confidence,
            RetrievalBlendSignal::Gravity,
            RetrievalBlendSignal::Relevance,
        ];
        let pinned_total: f32 = self.pins.iter().map(|pin| pin.value).sum();
        let remainder = (1.0 - pinned_total).max(0.0);
        let unpinned_total: f32 = signals
            .iter()
            .filter(|signal| self.value_for(**signal).is_none())
            .map(|signal| weights.weight(*signal))
            .sum();
        let unpinned_count = signals
            .iter()
            .filter(|signal| self.value_for(**signal).is_none())
            .count();
        let value = |signal: RetrievalBlendSignal| -> f32 {
            if let Some(pinned) = self.value_for(signal) {
                return pinned;
            }
            if unpinned_total > f32::EPSILON {
                weights.weight(signal) / unpinned_total * remainder
            } else if unpinned_count > 0 {
                remainder / unpinned_count as f32
            } else {
                0.0
            }
        };
        RetrievalBlendWeights::new(
            value(RetrievalBlendSignal::Recency),
            value(RetrievalBlendSignal::Salience),
            value(RetrievalBlendSignal::Confidence),
            value(RetrievalBlendSignal::Gravity),
            value(RetrievalBlendSignal::Relevance),
        )
        .normalized()
    }

    /// Whether `weights` already holds every pin at its declared share.
    #[must_use]
    pub fn respects(&self, weights: RetrievalBlendWeights) -> bool {
        self.pins
            .iter()
            .all(|pin| (weights.weight(pin.signal) - pin.value).abs() <= 1e-6)
    }
}

/// Where one served blend weight came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalWeightOrigin {
    Bootstrap,
    Learned,
    OwnerPin,
}

/// One blend weight with its origin, as the policy receipts report it.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalWeightRow {
    pub signal: RetrievalBlendSignal,
    pub weight: f32,
    pub origin: RetrievalWeightOrigin,
    pub pinned: bool,
}

/// The per-signal receipt rows for a weight set under the given pins.
#[must_use]
pub fn retrieval_weight_rows(
    weights: RetrievalBlendWeights,
    pins: &RetrievalPolicyPins,
    unpinned_origin: RetrievalWeightOrigin,
) -> Vec<RetrievalWeightRow> {
    [
        RetrievalBlendSignal::Recency,
        RetrievalBlendSignal::Salience,
        RetrievalBlendSignal::Confidence,
        RetrievalBlendSignal::Gravity,
        RetrievalBlendSignal::Relevance,
    ]
    .into_iter()
    .map(|signal| {
        let pinned = pins.value_for(signal).is_some();
        RetrievalWeightRow {
            signal,
            weight: weights.weight(signal),
            origin: if pinned {
                RetrievalWeightOrigin::OwnerPin
            } else {
                unpinned_origin
            },
            pinned,
        }
    })
    .collect()
}

/// The held-out gate's answer for a candidate weight set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalPolicyVerdict {
    /// The candidate did no worse than the active weights on held-out runs.
    NotWorse,
    /// The candidate scored below the active weights on held-out runs.
    Regression,
    /// Too little gated evidence to judge; the candidate stays an offer.
    Insufficient,
}

/// Held-out scoring of a candidate against the active weights. The score is
/// the gated reward (accuracy shaped by latency and hop cost) the held-out
/// runs credit to each weight set, so the delta is the accuracy/cost tradeoff.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyHeldOut {
    pub candidate_score: f64,
    pub active_score: f64,
    pub reward_count: u32,
    pub verdict: RetrievalPolicyVerdict,
}

/// A trained but not yet admitted retrieval-policy candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyCandidate {
    pub weights: RetrievalBlendWeights,
    pub rows: Vec<RetrievalWeightRow>,
    pub data_window: RetrievalBlendWeightDataWindow,
    /// Digest of the exact training/evaluation manifest this candidate was
    /// trained and judged on; admission requires the same manifest.
    pub manifest_digest: String,
    pub held_out: RetrievalPolicyHeldOut,
    pub training_reward_count: u32,
    /// Outcome rows without gate-attributed reward evidence never train or
    /// judge an update; this counts the ones the scan passed over.
    pub ungated_outcomes_skipped: u32,
    pub algorithm: String,
}

/// A held-out evaluation of caller-supplied candidate weights.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalPolicyEvaluation {
    pub candidate_weights: RetrievalBlendWeights,
    pub active_weights: RetrievalBlendWeights,
    pub rows: Vec<RetrievalWeightRow>,
    pub manifest_digest: String,
    pub held_out: RetrievalPolicyHeldOut,
    pub pins_respected: bool,
    pub ungated_outcomes_skipped: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalScoreBreakdown {
    pub result_id: [u8; 16],
    pub final_rank: u32,
    pub final_score: f32,
    pub components: Vec<RetrievalScoreComponent>,
    /// ONE-1402 read-side decay attribution: the exact access multiplier
    /// the run applied to this entity's fused score (post-override,
    /// post-floor; `1.0` for non-claims and gate-skipped candidates), so a
    /// consumer can reconstruct the pre-decay scale as `final_score / f`
    /// when `Some(f)` and `f > 0`.
    ///
    /// `None` means NOT APPLICABLE — a per-channel or fused-stage row and
    /// direct vault-search breakdowns, where no multiplication happened —
    /// or a row written by a binary that predates the field. It is
    /// deliberately distinct from `Some(1.0)`, which means decay ran and
    /// resolved to neutral.
    ///
    /// Wire-compatible in both directions: `None` skips the key, so a row
    /// encodes to the exact legacy four-key shape and legacy bytes decode
    /// back to `None`. Decay is still not a [`RetrievalSignal`]: this is
    /// an observation of the multiplier, never a blend component and never
    /// a rank.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_factor: Option<f32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalTraceStage {
    PerChannel,
    Fused,
    Blended,
    Reranked,
    Final,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalTraceChannelRecord {
    pub stage: RetrievalTraceStage,
    pub signal: RetrievalSignal,
    pub candidates: Vec<RetrievalScoreBreakdown>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalTraceStageRecord {
    pub stage: RetrievalTraceStage,
    pub candidates: Vec<RetrievalScoreBreakdown>,
}

/// Keyed replay key for a content-addressed [`RetrievalTrace`].
///
/// The hash is stored as the raw 32-byte digest, not hex. The retrieval
/// pipeline digests its inputs with the same domain-separated SHA-256 style as
/// the gate policy frontier hash: length-prefixed UTF-8 strings/bytes,
/// little-endian integers, one-byte booleans, and IEEE-754 `to_bits()` bytes
/// for floats. It then keys that digest with BLAKE3 under the vault's own
/// random key, so equal inputs give equal hashes on one vault only, and a
/// reader of the telemetry cannot test a guessed query against it.
pub type RetrievalTraceForkHash = [u8; 32];

/// Opt-in per-stage retrieval trace.
///
/// `fork_hash` is the content-addressed replay key for fork-and-diff eval. Its
/// canonical input snapshot is: query inputs for all enabled retrieval channels,
/// normalized retrieval config and flags, the BM25 rank-profile snapshot, the
/// pinned recency half-life table, the active retrieval-blend weight table,
/// an explicitly supplied replay clock whenever present — read-side decay
/// scores from the run's resolved clock on EVERY retrieval, so an explicit
/// clock is time-dependent scoring input unconditionally, not only for
/// recency/temporal runs — the caller-supplied read-side access-factor
/// override map canonicalized as a presence flag plus entries sorted by
/// `EntityId`, and the candidate set canonicalized as sorted, deduplicated
/// `EntityId` bytes. Implicit wall-clock seconds are not hashed. Legacy traces
/// missing the field decode to the all-zero sentinel, which is treated as
/// unknown and is not indexed. The trace remains typed msgpack-native;
/// JSONL/parquet export belongs outside the engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalTrace {
    #[serde(default)]
    pub fork_hash: RetrievalTraceForkHash,
    pub per_channel: Vec<RetrievalTraceChannelRecord>,
    pub fused: RetrievalTraceStageRecord,
    pub blended: RetrievalTraceStageRecord,
    pub reranked: RetrievalTraceStageRecord,
    #[serde(rename = "final")]
    pub final_stage: RetrievalTraceStageRecord,
    /// How many of each ranked channel's best scores set its fusion scale
    /// (`fusion::FUSION_LIST_LENGTH` when the run was traced). Traces from
    /// before it decode as 0, unknown.
    #[serde(default)]
    pub fusion_list_length: u32,
}
