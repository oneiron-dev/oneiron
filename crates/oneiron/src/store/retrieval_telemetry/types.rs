//! Retrieval-telemetry record, trace, signal, and blend-weight types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::pipeline::Signal;
use crate::retrieval_quality::{
    ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality, RetrievalQualityReport,
};

use super::blend_tuning::validate_retrieval_blend_weights;
use super::run_store::RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT;

pub(super) const RETRIEVAL_TELEMETRY_VERSION: u8 = 0;

pub(in crate::store) const RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION: u8 = 1;

pub(in crate::store) const RETRIEVAL_BLEND_TUNER_ALGORITHM: &str =
    "ret010d.reward_weighted_bandit.v1";

const RETRIEVAL_BLEND_BOOTSTRAP_SOURCE: &str = "ret010b.bootstrap";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RetrievalRunId {
    pub(super) bytes: [u8; 16],
}

impl RetrievalRunId {
    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    #[must_use]
    pub fn as_bytes(self) -> [u8; 16] {
        self.bytes
    }

    #[must_use]
    #[allow(
        dead_code,
        reason = "no P4a path reconstructs a run id from raw bytes; on the ONE-1728 seg-4 \
                  post-merge delete-list unless ONE-1730's promote replay claims it"
    )]
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        bytes_to_hex_lower(&self.bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalSignal {
    Vector,
    Text,
    Phonetic,
    Temporal,
    Ppr,
    Recency,
    Salience,
    Confidence,
    Gravity,
    /// RET-010 host-injected reranker component. Never a channel and never
    /// a blend signal: the blend weight table must not train on reranker
    /// output.
    Rerank,
    Hyde,
    /// HyDE retry subquery channel, retained only in retrieval traces.
    HydeRetry,
}

impl RetrievalSignal {
    #[must_use]
    pub fn as_blend_signal(self) -> Option<RetrievalBlendSignal> {
        match self {
            Self::Recency => Some(RetrievalBlendSignal::Recency),
            Self::Salience => Some(RetrievalBlendSignal::Salience),
            Self::Confidence => Some(RetrievalBlendSignal::Confidence),
            Self::Gravity => Some(RetrievalBlendSignal::Gravity),
            Self::Vector
            | Self::Text
            | Self::Phonetic
            | Self::Temporal
            | Self::Ppr
            | Self::Rerank
            | Self::Hyde
            | Self::HydeRetry => None,
        }
    }
}

impl From<Signal> for RetrievalSignal {
    fn from(signal: Signal) -> Self {
        match signal {
            Signal::Vector => Self::Vector,
            Signal::Text => Self::Text,
            Signal::Phonetic => Self::Phonetic,
            Signal::Temporal => Self::Temporal,
            Signal::Ppr => Self::Ppr,
            Signal::Hyde => Self::Hyde,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalBlendSignal {
    Recency,
    Salience,
    Confidence,
    Gravity,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RetrievalBlendWeights {
    pub recency: f32,
    pub salience: f32,
    pub confidence: f32,
    pub gravity: f32,
}

impl RetrievalBlendWeights {
    #[must_use]
    pub const fn bootstrap() -> Self {
        Self {
            recency: 0.35,
            salience: 0.30,
            confidence: 0.20,
            gravity: 0.15,
        }
    }

    #[must_use]
    pub const fn new(recency: f32, salience: f32, confidence: f32, gravity: f32) -> Self {
        Self {
            recency,
            salience,
            confidence,
            gravity,
        }
    }

    #[must_use]
    pub fn weight(self, signal: RetrievalBlendSignal) -> f32 {
        match signal {
            RetrievalBlendSignal::Recency => self.recency,
            RetrievalBlendSignal::Salience => self.salience,
            RetrievalBlendSignal::Confidence => self.confidence,
            RetrievalBlendSignal::Gravity => self.gravity,
        }
    }

    pub(crate) fn normalized(self) -> Result<Self> {
        validate_retrieval_blend_weights(self).map_err(Error::InvalidConfig)?;
        let sum = self.sum();
        Ok(Self {
            recency: self.recency / sum,
            salience: self.salience / sum,
            confidence: self.confidence / sum,
            gravity: self.gravity / sum,
        })
    }

    pub(super) fn sum(self) -> f32 {
        self.recency + self.salience + self.confidence + self.gravity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RetrievalBlendWeightDataWindow {
    pub run_count: u32,
    pub outcome_count: u32,
    pub candidate_count: u32,
    pub started_at_min: Option<u64>,
    pub started_at_max: Option<u64>,
    pub outcome_updated_at_min: Option<u64>,
    pub outcome_updated_at_max: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalBlendWeightTableEntry {
    pub version: u8,
    pub weights: RetrievalBlendWeights,
    pub tuned_at: u64,
    pub provenance: BTreeMap<String, String>,
    pub data_window: RetrievalBlendWeightDataWindow,
}

impl RetrievalBlendWeightTableEntry {
    #[must_use]
    pub fn bootstrap() -> Self {
        let mut provenance = BTreeMap::new();
        provenance.insert(
            "source".to_owned(),
            RETRIEVAL_BLEND_BOOTSTRAP_SOURCE.to_owned(),
        );
        provenance.insert("algorithm".to_owned(), "ret010b.bootstrap.v1".to_owned());
        Self {
            version: RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION,
            weights: RetrievalBlendWeights::bootstrap(),
            tuned_at: 0,
            provenance,
            data_window: RetrievalBlendWeightDataWindow::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetrievalBlendTuningConfig {
    pub max_runs: usize,
    pub learning_rate: f32,
    pub min_reward_count: usize,
}

impl Default for RetrievalBlendTuningConfig {
    fn default() -> Self {
        Self {
            max_runs: RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT,
            learning_rate: 0.05,
            min_reward_count: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalScoreComponent {
    pub signal: RetrievalSignal,
    pub rank: u32,
    pub score: f32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalTraceStage {
    PerChannel,
    Fused,
    Blended,
    Reranked,
    Final,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalTraceChannelRecord {
    pub stage: RetrievalTraceStage,
    pub signal: RetrievalSignal,
    pub candidates: Vec<RetrievalScoreBreakdown>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalTraceStageRecord {
    pub stage: RetrievalTraceStage,
    pub candidates: Vec<RetrievalScoreBreakdown>,
}

/// SHA-256 replay key for a content-addressed [`RetrievalTrace`].
///
/// The hash is stored as the raw 32-byte digest, not hex. It is computed by
/// the retrieval pipeline with the same domain-separated SHA-256 style as the
/// gate policy frontier hash: length-prefixed UTF-8 strings/bytes, little-endian
/// integers, one-byte booleans, and IEEE-754 `to_bits()` bytes for floats.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalTrace {
    #[serde(default)]
    pub fork_hash: RetrievalTraceForkHash,
    pub per_channel: Vec<RetrievalTraceChannelRecord>,
    pub fused: RetrievalTraceStageRecord,
    pub blended: RetrievalTraceStageRecord,
    pub reranked: RetrievalTraceStageRecord,
    #[serde(rename = "final")]
    pub final_stage: RetrievalTraceStageRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalRunRecord {
    pub version: u8,
    pub run_id: RetrievalRunId,
    pub action: RetrievalAction,
    pub started_at: u64,
    pub elapsed_us: u64,
    pub signals: Vec<RetrievalSignal>,
    pub result_ids: Vec<[u8; 16]>,
    pub score_breakdown: Vec<RetrievalScoreBreakdown>,
    pub total_in_scope: usize,
    pub claims_suppressed: usize,
    pub empty_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace: Option<RetrievalTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality: Option<RetrievalQuality>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degradation: Vec<RetrievalDegradation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_adjustment: Option<ConfidenceAdjustment>,
}

impl RetrievalRunRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        run_id: RetrievalRunId,
        action: RetrievalAction,
        started_at: u64,
        elapsed_us: u64,
        signals: Vec<RetrievalSignal>,
        score_breakdown: Vec<RetrievalScoreBreakdown>,
        total_in_scope: usize,
        claims_suppressed: usize,
        empty_reason: Option<String>,
    ) -> Self {
        let result_ids = score_breakdown
            .iter()
            .map(|entry| entry.result_id)
            .collect();
        Self {
            version: RETRIEVAL_TELEMETRY_VERSION,
            run_id,
            action,
            started_at,
            elapsed_us,
            signals,
            result_ids,
            score_breakdown,
            total_in_scope,
            claims_suppressed,
            empty_reason,
            trace: None,
            quality: None,
            degradation: Vec::new(),
            confidence_adjustment: None,
        }
    }

    pub(crate) fn with_quality(mut self, report: &RetrievalQualityReport) -> Self {
        self.quality = Some(report.quality);
        self.degradation = report.degradation.clone();
        self.confidence_adjustment = Some(report.confidence_adjustment);
        self
    }

    pub(crate) fn with_trace(mut self, trace: Option<RetrievalTrace>) -> Self {
        self.trace = trace;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalOutcome {
    pub run_id: RetrievalRunId,
    pub key: String,
    pub reward: Option<f32>,
    pub accepted: Option<bool>,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrievalOutcomeRecord {
    pub version: u8,
    pub run_id: RetrievalRunId,
    pub key: String,
    pub reward: Option<f32>,
    pub accepted: Option<bool>,
    pub metadata: BTreeMap<String, String>,
    pub updated_at: u64,
}
