//! The loop a conflict settlement, its approval or its revert answers (FIX
//! 7500): the one decision it answers, selected from those bound to the
//! claim it names (the marker a review raised, the alternative a Keep
//! approved, the settlement a revert undoes), and that decision's loop
//! links, with it as their basis. No actor or tag is read as a loop, so a
//! claim no loop wrote leaves none. Read only; a ledger read that fails
//! leaves no link.

use crate::store::GateDecisionContext;
use crate::{EntityId, Vault};

/// The context of a decision answering the newest decision bound to `claim`
/// that carries a loop link, of the tag `kind` when one is named. Its read
/// contexts stay with it: the answering receipt is bound to its own claim,
/// not always to `claim`.
pub(super) fn answering_claim(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    claim: EntityId,
    kind: Option<&str>,
) -> GateDecisionContext {
    vault
        .store
        .gate_decisions_for_claim_in_txn(txn, claim.as_bytes())
        .unwrap_or_default()
        .into_iter()
        .filter(|record| {
            !record.context.links.is_empty()
                && kind.is_none_or(|kind| record.content_kind == kind)
        })
        .max_by_key(|record| record.created_at)
        .map(|answered| GateDecisionContext {
            read: Vec::new(),
            ..GateDecisionContext::answering(&answered)
        })
        .unwrap_or_default()
}
