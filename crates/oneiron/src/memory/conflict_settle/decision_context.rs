//! The loop a conflict settlement, its approval or its revert answers (FIX
//! 7500): the loop links the ledger keeps on the decisions bound to the
//! claim it names, the marker a review raised or the claim a settlement
//! resolved. No actor or tag is read as a loop, so a claim no loop wrote
//! leaves none. Read only; a ledger read that fails leaves no link.

use crate::store::{GateDecisionContext, GateDecisionRecord};
use crate::{EntityId, Vault};

/// The loop links of the decisions bound to `claim`, as a decision that
/// answers them carries them. Their read contexts stay with them: the
/// answering receipt is bound to its own claim, not always to `claim`.
pub(super) fn answering_claim(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
) -> GateDecisionContext {
    let linked: Vec<GateDecisionRecord> = vault
        .store
        .gate_decisions_for_claim_in_txn(txn, claim.as_bytes())
        .unwrap_or_default()
        .into_iter()
        .filter(|record| !record.context.links.is_empty())
        .collect();
    GateDecisionContext {
        read: Vec::new(),
        ..GateDecisionContext::answering_all(&linked)
    }
}
