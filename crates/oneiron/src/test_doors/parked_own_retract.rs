//! Door for `tests/agent_holder_settle_restriction.rs`: an agent's retract
//! of its own claim, parked for the holder's consent
//! (`Vault::retract_own_claim_or_park_in_txn`, the retract door's agent arm).
//! The retract door now refuses a below-owner retract of a claim that
//! restricts someone's access before it parks
//! (`memory::require_live_owner_to_lift_restriction_in_txn`), so this door
//! parks one as the door parked it before that check; a vault may still
//! hold such a parked retract. Its settlement is under test.

use crate::claim::OwnClaimRetract;
use crate::error::Result;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// Parks `author`'s retract of its own claim `id` now. Returns whether it
/// parked: `false` when the gate let it land.
///
/// # Errors
///
/// The retract's refusal.
pub fn park_own_retract(vault: &Vault, author: WriteActor, id: EntityId) -> Result<bool> {
    let now = vault.now_recorded_at();
    vault.with_write_txn_grouped(|txn| {
        Ok(matches!(
            vault.retract_own_claim_or_park_in_txn(txn, &id, now, author)?,
            OwnClaimRetract::Parked(_)
        ))
    })
}
