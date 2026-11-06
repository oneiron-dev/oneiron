//! Commitment successor identity rules.

use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::derived_domains::COMMITMENT_LAPSE_SUCCESSOR;
use oneiron_contracts::error::Result;

/// Whether a status change mints a successor claim carrying the new status and
/// supersedes its predecessor through the claim lifecycle (FIX 9726), rather
/// than rewriting the value under the predecessor's id.
///
/// The commitment, schedule, wake, close, memory, receipt and deep-link
/// readers follow a commitment to the head of that chain
/// ([`Vault::commitment_head_in_txn`]), and the batched lapse stages its
/// successors in the batch's own transaction. A predecessor superseded before
/// its occurred start (a scheduled instance closed before its due window)
/// closes at that start.
pub const STATUS_CHANGE_MINTS_SUCCESSOR: bool = true;

/// The claim a batched lapse of `commitment` writes: with
/// [`STATUS_CHANGE_MINTS_SUCCESSOR`], its successor, derived from the
/// commitment so the gate preflight and the apply name the same new claim;
/// otherwise the commitment itself. A commitment lapses once, so its one
/// derived successor is its own.
pub fn lapse_claim_id(commitment: &EntityId) -> Result<EntityId> {
    if !STATUS_CHANGE_MINTS_SUCCESSOR {
        return Ok(*commitment);
    }
    EntityId::derive(COMMITMENT_LAPSE_SUCCESSOR, &[commitment.as_bytes()])
}

/// [`lapse_claim_id`] for each selected commitment, in order: the ids the
/// batch preflight records its decisions under.
pub fn lapse_claim_ids(commitments: &[EntityId]) -> Result<Vec<EntityId>> {
    commitments.iter().map(lapse_claim_id).collect()
}
