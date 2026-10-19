//! The sends one attempt has not settled (DOOR-141 PR3b): what a held turn
//! program's resume waits on, read over the attempt's own index rows.

use super::super::types::{IntentId, IntentLedgerResult, IntentState};
use super::{INTENT_ATTEMPT_INDEX, check_intent_attempt_format, read_intent_record_in_txn};
use crate::Vault;
use crate::attempt_queue::AttemptId;

/// Whether `attempt_id` holds an intent still Pending, or one whose row does
/// not read: a send whose delivery is not settled. A turn program's resume
/// holds on one rather than letting it go out again (DOOR-141 PR3b). Only
/// the attempt's own index rows are read.
pub(crate) fn attempt_has_pending_intent_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_id: AttemptId,
) -> IntentLedgerResult<bool> {
    check_intent_attempt_format(vault, txn)?;
    for row in INTENT_ATTEMPT_INDEX.iter_raw_from(&vault.store, txn, attempt_id.as_bytes())? {
        let (_, raw) = row?;
        let Ok(id) = IntentId::try_from(raw.as_slice()) else {
            return Ok(true);
        };
        match read_intent_record_in_txn(vault, txn, &id) {
            Ok(Some(record)) if record.state != IntentState::Pending => {}
            _ => return Ok(true),
        }
    }
    Ok(false)
}
