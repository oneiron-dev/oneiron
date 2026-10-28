//! Anchored task outcomes beside edit cost (ARCH-0056 §8, FIX 7828).
//!
//! Low edit distance alone rewards short, bland, hard-to-object-to output. So
//! each folded run is paired with how the TASK it ran for ended, as the write
//! that settled that TASK recorded it, joined through the run's own receipts:
//! the judgment names the attempt, the attempt's pack receipt names its TASK,
//! and the TASK's settled lifecycle receipt names the disposition. The counts
//! ride beside the cost, never blended into it, and the attribution labels
//! never stand in for them. A run with no anchor along that chain adds no
//! count: absent, never invented.

use crate::Vault;
use crate::edit_distance::attribution::AmendmentJudgment;
use crate::entity_id::EntityId;
use crate::error::Result;

/// The settled disposition of the TASK the run behind `judgment` worked, read
/// in `txn`; `None` when the judgment names no attempt, the attempt's receipt
/// names no TASK, or no write has settled it yet.
///
/// # Errors
///
/// Storage errors.
pub(super) fn run_outcome_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    judgment: &AmendmentJudgment,
) -> Result<Option<String>> {
    let Some(attempt) = judgment.attempt_receipt.as_deref() else {
        return Ok(None);
    };
    let Some(receipt) = crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, attempt)?
    else {
        return Ok(None);
    };
    let Some(task) = receipt
        .trigger_ref
        .as_deref()
        .and_then(|hex| EntityId::from_hex(hex).ok())
    else {
        return Ok(None);
    };
    crate::task_verb::settled_outcome_in(vault, txn, task)
}
