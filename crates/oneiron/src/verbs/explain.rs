//! The wire shapes of `vault.explain.memory` and `vault.explain.gate`
//! (OF-278): why a memory appeared in the caller's session, and why a write
//! needed approval. They are the replies GET /v1/core/explain/memory/{entity}
//! and GET /v1/core/explain/gate/{receipt} serve, so the HTTP routes and the
//! verb rows speak one shape. A server's host door answers both rows: only
//! it holds the session read sets a memory explanation reads.
use serde::{Deserialize, Serialize};

use crate::context_board::{GateExplanation, MemoryExplanation};
use crate::{RetrievalScoreBreakdown, RetrievalScoreComponent};

/// `vault.explain.memory`'s input: the memory, and the session that was
/// served it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExplainMemoryRequest {
    /// Hex entity id of the memory.
    pub entity: String,
    /// The board or pack session that was served the memory; the caller's
    /// active session when absent.
    #[serde(default)]
    pub session_id: Option<String>,
}

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

/// `vault.explain.gate`'s input: one gate receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExplainGateRequest {
    /// Gate receipt id, `gate:<hex>`.
    pub receipt: String,
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

impl From<MemoryExplanation> for ExplainMemoryReply {
    fn from(explained: MemoryExplanation) -> Self {
        let id = explained.id.to_hex();
        Self {
            score: explained
                .breakdown
                .map(|breakdown| score_evidence(id.clone(), breakdown)),
            id,
            run_id: explained.why.run_id,
            rank: explained.why.rank,
            neighbor: explained.why.neighbor,
            tier: explained.why.tier,
            hook: explained.why.hook,
        }
    }
}

/// The breakdown of the row `result_id` names: the engine finds it by that
/// id, so the hex is the row's own.
fn score_evidence(result_id: String, breakdown: RetrievalScoreBreakdown) -> ExplainScoreEvidence {
    ExplainScoreEvidence {
        result_id,
        final_rank: breakdown.final_rank,
        final_score: breakdown.final_score,
        access_factor: breakdown.access_factor,
        components: breakdown.components,
    }
}

impl From<GateExplanation> for ExplainGateReply {
    fn from(explained: GateExplanation) -> Self {
        Self {
            receipt_id: explained.receipt_id,
            decided_at: explained.decided_at,
            outcome: explained.outcome,
            reason_codes: explained.reason_codes,
            receipt_reasons: explained.receipt_reasons,
            notices: explained
                .notices
                .into_iter()
                .map(|(notice_type, row_ref)| ExplainGateNotice {
                    notice_type,
                    row_ref,
                })
                .collect(),
            actor_class: explained.actor_class,
            actor_ref: explained.actor_ref,
            content_kind: explained.content_kind,
            policy_manifest_version: explained.policy_manifest_version,
            claim_ref: explained.claim_ref,
        }
    }
}
