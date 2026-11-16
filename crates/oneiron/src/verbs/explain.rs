//! The wire shapes of `vault.explain.memory` and `vault.explain.gate`
//! (OF-278): why a memory appeared in the caller's session, and why a write
//! needed approval. They are the replies GET /v1/core/explain/memory/{entity}
//! and GET /v1/core/explain/gate/{receipt} serve, so the HTTP routes and the
//! verb rows speak one shape. A server's host door answers both rows: only
//! it holds the session read sets a memory explanation reads.
use serde::{Deserialize, Serialize};

use crate::context_board::{GateExplanation, MemoryExplanation};
use crate::{RetrievalScoreBreakdown, RetrievalScoreComponent};

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::explain::{ExplainGateRequest, ExplainMemoryRequest};

#[doc(hidden)]
use oneiron_records::verbs::explain::score_evidence;
#[doc(hidden)]
pub use oneiron_records::verbs::explain::{
    ExplainGateNotice, ExplainGateReply, ExplainMemoryReply, ExplainScoreEvidence,
};

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
