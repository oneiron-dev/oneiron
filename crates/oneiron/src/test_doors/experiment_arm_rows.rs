//! TEST-ONLY: an experiment arm row put as given, so a test can stand an arm
//! in a state whose writer is a later row: rung 1 closed, or the arm
//! withdrawn (row M2-E's verdict writes; design pass 32 r2, T43 and T44).

use crate::Vault;
use crate::experiment_arm::ExperimentArm;

/// Puts `arm` as given, in one write.
///
/// # Errors
///
/// A store failure.
pub fn put_arm(vault: &Vault, arm: &ExperimentArm) -> crate::Result<()> {
    vault.with_write_txn(|wtxn| crate::experiment_arm::put_arm_in_txn(vault, wtxn, arm))
}
