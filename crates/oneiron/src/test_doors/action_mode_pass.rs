//! Doors for `tests/setting_action_mode_auto_apply.rs` (restriction wave 14, C22): enqueue one
//! owner's action-mode attempt and admit it through the maintenance lane, as the nightly wake
//! does, then run its pass over the state index the test derived, unrefreshed. Thin wrappers
//! over production APIs only. Compiled only under `--cfg oneiron_test_support` (`test_doors`);
//! hidden, never API.

use crate::dreamer_runner::maintenance::action_mode::{self, ACTION_MODE_FACET};
use crate::dreamer_runner::{AdmitDreamerAttempt, DreamerAdmissionOutcome, DreamerRunnerStore};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// The lease owner the door admits under.
const ACTION_MODE_LEASE_OWNER: &str = "action-mode-door";

/// Enqueues the action-mode attempts the nightly wake does while a policy is set (one per
/// owner), admits the next maintenance attempt at `now`, and runs its action-mode pass over the
/// owner's state index as it stands. Returns the finding, or `None` when the index falls in no
/// band.
///
/// # Errors
///
/// The vault's; an admission of nothing or of another facet; the pass's own.
pub fn run_action_mode_pass(vault: &Vault, now: u64) -> Result<Option<EntityId>> {
    let store = DreamerRunnerStore::new(vault);
    vault.with_write_txn(|txn| store.enqueue_action_mode_in_txn(txn, None, None, None, now))?;
    let DreamerAdmissionOutcome::Admitted(admitted) =
        store.admit_next_maintenance(AdmitDreamerAttempt {
            lease_owner: ACTION_MODE_LEASE_OWNER.to_owned(),
            now,
            budget_id: "action-mode-door".to_owned(),
            budget_total_units: 10_000,
            reserve_units: 1,
            started_milestone: None,
        })?
    else {
        return Err(Error::InvalidConfig(
            "no action-mode attempt was admitted".into(),
        ));
    };
    if admitted.status.payload.attempt_type != ACTION_MODE_FACET {
        return Err(Error::InvalidConfig(format!(
            "the maintenance lane admitted {}",
            admitted.status.payload.attempt_type
        )));
    }
    action_mode::land_mode(vault, &admitted, now, false)
}
