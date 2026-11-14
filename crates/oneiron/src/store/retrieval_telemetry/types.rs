//! Core half of `store::retrieval_telemetry::types`: its store-layer items live in `oneiron_store::retrieval_telemetry::types` and are
//! re-exported here; the items below stay in the engine.

use super::run_store::RETRIEVAL_RUNS_CAPACITY_HINT_LIMIT;
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::retrieval_quality::{
    ConfidenceAdjustment, RetrievalDegradation, RetrievalQuality, RetrievalQualityReport,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;
// The signal and blend-weight vocabulary is defined in `oneiron-contracts` (retrieval's
// fusion scores with it); `From<Signal>` stays here with the pipeline's channel enum.
pub use oneiron_contracts::retrieval_telemetry::{
    RetrievalBlendSignal, RetrievalBlendWeights, RetrievalScoreComponent, RetrievalSignal,
};

#[doc(hidden)]
use oneiron_verb_wire::store::retrieval_telemetry::types::RETRIEVAL_BLEND_BOOTSTRAP_SOURCE;
#[doc(hidden)]
pub(in crate::store) use oneiron_verb_wire::store::retrieval_telemetry::types::RETRIEVAL_BLEND_WEIGHT_TABLE_VERSION;
#[doc(hidden)]
pub(super) use oneiron_verb_wire::store::retrieval_telemetry::types::RETRIEVAL_TELEMETRY_VERSION;
#[doc(hidden)]
pub use oneiron_verb_wire::store::retrieval_telemetry::types::{
    RetrievalAction, RetrievalBlendWeightDataWindow, RetrievalPolicyCandidate,
    RetrievalPolicyEvaluation, RetrievalPolicyHeldOut, RetrievalPolicyPin, RetrievalPolicyPins,
    RetrievalPolicyVerdict, RetrievalScoreBreakdown, RetrievalTrace, RetrievalTraceChannelRecord,
    RetrievalTraceForkHash, RetrievalTraceStage, RetrievalTraceStageRecord, RetrievalWeightOrigin,
    RetrievalWeightRow, retrieval_weight_rows,
};

pub(in crate::store) const RETRIEVAL_BLEND_TUNER_ALGORITHM: &str =
    "oneiron.retrieval.blend_tuner.v2";

/// Gated training rewards a tuning pass needs, when its caller sets no
/// `min_reward_count`, before a not-worse held-out verdict may admit the
/// candidate. A smaller trial cannot establish not-worse sufficiency, so the
/// declared update keeps it as an offer and the nightly pass writes no blend
/// weight table (ARCH-0037 #tune-retrieval-gaps: "Update keeps regression or
/// insufficient evidence as an offer"). Every fifth run is held out, so with
/// one usable label per run the floor also leaves about five held-out runs to
/// judge on. The owner's explicit
/// `min_reward_count` may lower it.
pub(crate) const RETRIEVAL_BLEND_TUNING_DEFAULT_MIN_REWARD_COUNT: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
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
    pub(crate) fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        bytes_to_hex_lower(&self.bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
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
            min_reward_count: RETRIEVAL_BLEND_TUNING_DEFAULT_MIN_REWARD_COUNT,
        }
    }
}

impl RetrievalBlendWeightTableEntry {
    /// This active entry's receipt rows under the current pins.
    #[must_use]
    pub fn weight_rows(&self, pins: &RetrievalPolicyPins) -> Vec<RetrievalWeightRow> {
        let origin = if self.provenance.get("source").map(String::as_str)
            == Some(RETRIEVAL_BLEND_BOOTSTRAP_SOURCE)
        {
            RetrievalWeightOrigin::Bootstrap
        } else {
            RetrievalWeightOrigin::Learned
        };
        retrieval_weight_rows(self.weights, pins, origin)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalRunRecord {
    pub version: u8,
    pub run_id: RetrievalRunId,
    pub action: RetrievalAction,
    pub started_at: u64,
    pub elapsed_us: u64,
    #[serde(default)]
    pub state: super::state::RetrievalState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_trace: Option<crate::store::retrieval_policy::RetrievalPolicyTrace>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_inputs: Option<super::state::RetrievalReplayInputs>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn: Option<super::state::RetrievalTurn>,
    /// Id of the query expander whose expansion actually ran for this record
    /// (FIX 4451, L05 YES 11:05): the `HydeExpander::id` label of the SAME
    /// expander that produced the run's expansion. None stays honest for
    /// runs with no attributable expansion; a configured-but-unused expander
    /// is never stamped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_expander_id: Option<String>,
    /// The host-bound leased attempt whose dispatcher requested this retrieval.
    /// None means no such binding was captured; this is not read authority.
    pub dispatch_attempt: Option<AttemptId>,
    /// Witness of the run's two actual typed policy reads (FIX 7315): the
    /// manifest ref both the claim-aging and retrieval-weights reads agreed
    /// on, byte-exact, when weights were present. Both witness fields are
    /// Some only together; any absence or mismatch keeps both None. This
    /// witnesses only those two priors, not sole cause, composed policy,
    /// criticality, authority or scope.
    pub policy_manifest_ref: Option<String>,
    /// Body digest the run's two actual typed policy reads agreed on (FIX
    /// 7315): the blake3 hex of the SAME manifest body both reads decoded.
    /// See [`Self::policy_manifest_ref`].
    pub policy_manifest_body_hash: Option<String>,
    /// Stable `Reranker::id` label of the scorer actually applied for this
    /// recorded attempt, NOT a validated model revision or checkpoint hash.
    pub reranker_id: Option<String>,
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
    #[schemars(with = "Option<f32>")]
    pub confidence_adjustment: Option<ConfidenceAdjustment>,
}

/// What a finished context-pack retrieval run publishes: the caller's scope
/// count and the surfaced ids, atomically.
///
/// The four finalize seams — the `Store` door, its in-transaction session
/// sibling, the shared staging body and the room-side wrapper — all carry
/// exactly this payload, so threading it as one value keeps them from
/// drifting a field apart.
pub(crate) struct RetrievalRunFinalize<'a> {
    pub(crate) run_id: RetrievalRunId,
    pub(crate) elapsed_us: u64,
    pub(crate) total_in_scope: usize,
    pub(crate) claims_suppressed: usize,
    pub(crate) surfaced_result_ids: &'a [[u8; 16]],
    pub(crate) empty_reason: Option<String>,
    pub(crate) pack_config: Option<serde_json::Value>,
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
            state: super::state::RetrievalState::one_shot(&score_breakdown),
            policy_trace: None,
            replay_inputs: None,
            turn: None,
            query_expander_id: None,
            dispatch_attempt: None,
            policy_manifest_ref: None,
            policy_manifest_body_hash: None,
            reranker_id: None,
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

    /// Replay re-feeds this exact stored state, without recomputing features
    /// against today's graph or outcome rows.
    pub fn replay_state(&self) -> &super::state::RetrievalState {
        &self.state
    }

    pub(crate) fn with_context(
        mut self,
        state: Option<super::state::RetrievalState>,
        turn: Option<super::state::RetrievalTurn>,
    ) -> Self {
        if let Some(state) = state {
            self.state = state;
        }
        self.turn = turn;
        self
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

    /// Stamps the id of the query expander whose expansion actually ran for
    /// this record (FIX 4451, L05 YES 11:05). The caller passes the label of
    /// the SAME expander that produced the run's expansion; None stays
    /// honest for runs with no attributable expansion.
    pub(crate) fn with_query_expander_id(mut self, id: Option<String>) -> Self {
        self.query_expander_id = id;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalOutcome {
    pub run_id: RetrievalRunId,
    pub key: String,
    pub reward: Option<f32>,
    pub accepted: Option<bool>,
    pub metadata: BTreeMap<String, String>,
}

/// End-of-turn judgement supplied by the ARCH-0053 attribution gate. Only the
/// explicitly named contributing runs receive credit; memory overlap never
/// selects runs or divides the terminal signal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalEndOutcome {
    #[serde(rename = "retrievalRunIds")]
    pub retrieval_run_ids: Vec<RetrievalRunId>,
    pub key: String,
    pub turn_id: [u8; 16],
    pub gate_score: f32,
    pub confirmed_fact_hit: bool,
    pub latency_scale_us: u64,
    pub cost_weight: f32,
    pub metadata: BTreeMap<String, String>,
}

/// Stored evidence for the shaped reward. Only the end-outcome door mints this;
/// an arbitrary `RetrievalOutcome.reward` remains telemetry, not a label.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalRewardEvidence {
    #[serde(rename = "retrievalRunIds")]
    pub retrieval_run_ids: Vec<RetrievalRunId>,
    pub turn_id: [u8; 16],
    pub gate_score: f32,
    pub confirmed_fact_hit: bool,
    pub latency_scale_us: u64,
    pub cost_weight: f32,
}

impl RetrievalRewardEvidence {
    pub(super) fn validate(&self) -> Result<()> {
        if !self.gate_score.is_finite()
            || self.gate_score <= 0.0
            || self.gate_score > 1.0
            || self.latency_scale_us == 0
            || !self.cost_weight.is_finite()
            || self.cost_weight < 0.0
        {
            return Err(Error::InvalidConfig(
                "invalid gated retrieval end outcome".to_owned(),
            ));
        }
        Ok(())
    }

    pub(super) fn reward(&self, run: &RetrievalRunRecord) -> Result<f32> {
        self.validate()?;
        if run.turn.is_none_or(|turn| turn.turn_id != self.turn_id)
            || !self.retrieval_run_ids.contains(&run.run_id)
        {
            return Err(Error::InvalidConfig(
                "retrieval end outcome does not name this run and turn".to_owned(),
            ));
        }
        let hit = if self.confirmed_fact_hit { 1.0 } else { 0.0 };
        let latency_norm = (run.elapsed_us as f64 / self.latency_scale_us as f64) as f32;
        let reward = self.gate_score.mul_add(
            hit,
            -self.cost_weight * (latency_norm + f32::from(run.state.hops)),
        );
        if !reward.is_finite() {
            return Err(Error::InvalidConfig(
                "non-finite shaped retrieval reward".to_owned(),
            ));
        }
        Ok(reward)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RetrievalOutcomeRecord {
    pub version: u8,
    pub run_id: RetrievalRunId,
    pub key: String,
    pub reward: Option<f32>,
    pub accepted: Option<bool>,
    pub metadata: BTreeMap<String, String>,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reward_evidence: Option<RetrievalRewardEvidence>,
}
