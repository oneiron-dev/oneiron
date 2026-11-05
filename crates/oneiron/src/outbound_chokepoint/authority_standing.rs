//! Whether the authority that admitted a send still stands at its send
//! (FIX 11591, ruled FIX 4624(a)).
//!
//! A Pending row keeps the owner whose authenticated word admitted it. Each
//! send of the row, its first one, a live retry and an engine Resume alike,
//! asks again just before transport whether that owner is still a live owner
//! of this vault, and a scoped grant's frozen check names a grant that no
//! longer stands. Only a positive answer ends the send: a check that cannot
//! read names nothing and the send keeps today's path.

use crate::Vault;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::Error;
use crate::outbound_consent::OutboundBindingValidation;
use crate::outbound_intent_ledger::{IntentEscalationReason, IntentLedgerRecord};

/// [`IntentEscalationReason::OwnerNotLive`] when the owner whose proof
/// admitted `record` is no longer a live owner of `vault`, read in a fresh
/// snapshot. `None` for a row no owner's proof admitted, an owner still live,
/// or a read that failed (logged).
///
/// A shared vault left with no live owner at all (its last owner erased,
/// removed or transferred away) reads `false` for that owner here, not a
/// fault; only a row that does not decode is one.
pub(super) fn withdrawn_owner(
    vault: &Vault,
    record: &IntentLedgerRecord,
) -> Option<IntentEscalationReason> {
    let owner = record.authorizing_owner?;
    let standing = (|| -> crate::error::Result<bool> {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        crate::policy_model::holds_live_ownership_in_txn(vault, &txn, &owner)
    })();
    match standing {
        Ok(true) => None,
        Ok(false) => Some(IntentEscalationReason::OwnerNotLive),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                intent = %bytes_to_hex_lower(&record.id),
                "the recheck of a send's admitting owner could not read; the send keeps its path"
            );
            None
        }
    }
}

/// The stop a scoped grant's frozen check names: a grant no longer active
/// under today's policy no longer stands; every other rejection is the
/// binding's own.
pub(super) const fn frozen_grant_stop(
    rejected: OutboundBindingValidation,
) -> IntentEscalationReason {
    match rejected {
        OutboundBindingValidation::GrantNotLive => IntentEscalationReason::GrantNotStanding,
        OutboundBindingValidation::Valid
        | OutboundBindingValidation::Missing
        | OutboundBindingValidation::Invalid => IntentEscalationReason::BindingInvalid,
    }
}
