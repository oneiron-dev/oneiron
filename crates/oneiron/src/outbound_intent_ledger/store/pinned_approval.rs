//! A later AlwaysAsk press updates only its original canonical intent row.

use super::{LEDGER, get_ledger_record, validate_record};
use crate::Vault;
use crate::consent::approval_proof::PinnedApproval;
use crate::outbound_intent_ledger::{IntentLedgerResult, payload};

/// Keeps the original proof selected by a later AlwaysAsk press in that
/// press's writer. An absent or erased request stays absent or erased.
pub(crate) fn keep_pinned_approval_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    approval: Option<PinnedApproval>,
) -> IntentLedgerResult<()> {
    let Some(approval) = approval else {
        return Ok(());
    };
    let id = approval.proof.intent_id();
    let Some(mut record) = get_ledger_record(vault, wtxn, &id)? else {
        return Ok(());
    };
    if payload::payload_erased(record.payload())? {
        return Ok(());
    }
    record.pinned_approval = Some(approval);
    validate_record(&record)?;
    LEDGER.put(&vault.store, wtxn, &id, &record)?;
    Ok(())
}
