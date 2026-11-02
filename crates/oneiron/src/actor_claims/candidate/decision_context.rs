//! The context an owner's craft review keeps (FIX 7499, 7500): the candidate
//! as it was shown, and the resident's dreaming attempt that proposed it, as
//! that attempt's own authority stamp names it. The card's attempt names it;
//! the receipt's notices are never read as a link.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimBody;
use crate::entity_id::EntityId;
use crate::store::{GateDecisionContext, GateDecisionReadContext};

/// The context of the review of `candidate`, written as `body`, whose card
/// names the proposing `attempt` (32 hex).
pub(super) fn craft_review(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidate: &EntityId,
    body: &ClaimBody,
    attempt: &str,
) -> GateDecisionContext {
    let attempt = EntityId::from_hex(attempt)
        .ok()
        .and_then(|id| AttemptId::from_bytes(id.as_bytes()).ok());
    GateDecisionContext {
        read: GateDecisionReadContext::claim(candidate, body)
            .into_iter()
            .collect(),
        links: attempt
            .map(|attempt| vault.attempt_action_link_in_txn(txn, attempt))
            .into_iter()
            .collect(),
        analysis: None,
    }
}
