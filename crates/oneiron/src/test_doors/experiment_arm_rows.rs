//! TEST-ONLY: an experiment arm row put as given, so a test can stand an arm
//! in a state whose writer is a later row: rung 1 closed, or the arm
//! withdrawn (row M2-E's verdict writes; design pass 32 r2, T43 and T44).
//! And a unit claim put as given, whose writer is row M2-C's reserve door
//! (T16: a forecast after the rung's first claim). And the ask digest a
//! reserve stores on its claim (row RSI-ARM-RESULT: an ask with no result
//! keeps main's digest).

use crate::experiment_arm::{ARMS_UNITS_RESERVE_VERB, ExperimentArm, UnitReserveRequest};
use crate::gpu_line::{IntentAsk, IntentRefused, UnitClaim};
use crate::{EntityId, Vault};

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

/// The digest of `request`'s ask as `asker` frames it for `vault.arms.units.reserve`: the
/// `ask_digest` its reserve stores on the claim.
///
/// # Errors
///
/// A blank intent key, or an ask that does not encode.
pub fn unit_ask_digest(
    asker: EntityId,
    request: &UnitReserveRequest,
) -> Result<String, IntentRefused> {
    IntentAsk::new(
        asker,
        ARMS_UNITS_RESERVE_VERB,
        &request.intent_key,
        &request.ask(),
    )
    .map(|ask| ask.ask_digest().to_owned())
}
