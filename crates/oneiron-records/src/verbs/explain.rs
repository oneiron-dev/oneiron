//! Moved from `crates/oneiron/src/verbs/explain.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::retrieval_telemetry::RetrievalScoreComponent;
use oneiron_verb_wire::store::retrieval_telemetry::types::RetrievalScoreBreakdown;
pub use oneiron_verb_wire::verbs::explain::ExplainGateRequest;
pub use oneiron_verb_wire::verbs::explain::ExplainMemoryRequest;
use serde::Deserialize;
use serde::Serialize;

/// The serving run's score breakdown for one memory alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplainScoreEvidence {
    /// Hex entity id.
    pub result_id: String,
    /// Final rank after context-pack hydration.
    pub final_rank: u32,
    /// Final fused score.
    pub final_score: f32,
    /// Read-side access factor applied to the fused score, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_factor: Option<f32>,
    /// Signal-level score components.
    pub components: Vec<RetrievalScoreComponent>,
}

/// Why one memory appeared in the caller's session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplainMemoryReply {
    /// Hex entity id.
    pub id: String,
    /// Hex retrieval run that served it, when that run's telemetry persisted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// 1-based place among the run's primary results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rank: Option<u32>,
    /// Reached as a graph neighbor of a result, not ranked itself.
    pub neighbor: bool,
    /// The MEMORIES tier a board rendered it at: pinned, snippet or index_only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// `<pack>/<hook>` when a hook block pinned it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook: Option<String>,
    /// The run's score breakdown for this row alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<ExplainScoreEvidence>,
}

/// One system notice a gate decision raised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainGateNotice {
    /// Notice type token.
    pub notice_type: String,
    /// Opaque reference to the policy row it cites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_ref: Option<String>,
}

/// Why a write needed approval: one gate decision as the caller may see it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainGateReply {
    /// `gate:<hex>` receipt id.
    pub receipt_id: String,
    /// When the gate decided, Unix seconds.
    pub decided_at: u64,
    /// allow, pending or deny.
    pub outcome: String,
    /// Engine reason codes.
    pub reason_codes: Vec<String>,
    /// The policy rows and checks behind the outcome, by opaque reference.
    pub receipt_reasons: Vec<String>,
    /// System notices the decision raised.
    pub notices: Vec<ExplainGateNotice>,
    /// The writer's actor class.
    pub actor_class: String,
    /// Hex writer, when the caller is it, is the owner, or may read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ref: Option<String>,
    /// What kind of write it was.
    pub content_kind: String,
    /// The policy manifest version it was decided under.
    pub policy_manifest_version: String,
    /// Hex claim the write proposed, when the caller may read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_ref: Option<String>,
}

/// The breakdown of the row `result_id` names: the engine finds it by that
/// id, so the hex is the row's own.
pub fn score_evidence(
    result_id: String,
    breakdown: RetrievalScoreBreakdown,
) -> ExplainScoreEvidence {
    ExplainScoreEvidence {
        result_id,
        final_rank: breakdown.final_rank,
        final_score: breakdown.final_score,
        access_factor: breakdown.access_factor,
        components: breakdown.components,
    }
}
