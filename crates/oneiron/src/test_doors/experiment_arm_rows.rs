//! TEST-ONLY: an experiment arm row put as given, so a test can stand an arm
//! in a state whose writer is a later row: rung 1 closed, or the arm
//! withdrawn (row M2-E's verdict writes; design pass 32 r2, T43 and T44).
//! And a unit claim put as given, whose writer is row M2-C's reserve door
//! (T16: a forecast after the rung's first claim).

use crate::Vault;
use crate::experiment_arm::ExperimentArm;
use crate::gpu_line::UnitClaim;

/// Puts `arm` as given, in one write.
///
/// # Errors
///
/// A store failure.
pub fn put_arm(vault: &Vault, arm: &ExperimentArm) -> crate::Result<()> {
    vault.with_write_txn(|wtxn| crate::experiment_arm::put_arm_in_txn(vault, wtxn, arm))
}

/// Puts `claim` under its logical attempt as given, in one write.
///
/// # Errors
///
/// A store failure.
pub fn put_claim(vault: &Vault, claim: &UnitClaim) -> crate::Result<()> {
    vault.with_write_txn(|wtxn| crate::gpu_line::claim::put_claim_row_in_txn(vault, wtxn, claim))
}
