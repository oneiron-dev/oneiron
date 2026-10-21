//! Whole-index scans. A run reads each eligible index to its end, and its
//! cleanup decision commits with the scan in one transaction.

use super::*;
use crate::ports::EntityStoreRead;

/// Every cleanup candidate in `txn`: each checked entity type's index and the
/// completed-queue-record arm, each read to its end.
pub(super) fn scan_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<CleanupCandidate>> {
    let mut candidates = Vec::new();
    for (type_byte, _, _) in CLEANUP_CHECKS {
        for row in vault.store.port_entity_ids_by_type(txn, type_byte, None)? {
            let id = row?;
            if let Some(kind) = zero_live_members_in_txn(vault, txn, &id)? {
                candidates.push(CleanupCandidate { entity: id, kind });
            }
        }
    }
    super::attempt_retention::scan(vault, txn, &mut candidates)?;
    Ok(candidates)
}

pub(super) fn run(vault: &Vault, attempt: &AttemptId) -> Result<CleanupRunReport> {
    vault.with_write_txn_grouped(|txn| run_in_txn(vault, txn, attempt))
}

pub(super) fn run_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &AttemptId,
) -> Result<CleanupRunReport> {
    if let Some(report) = run_record::read_in_txn(vault, txn, attempt)? {
        return Ok(report);
    }
    let candidates = scan_in_txn(vault, txn)?;
    let report = run_cleanup_candidates_in_txn(vault, txn, attempt, candidates)?;
    run_record::put_in_txn(vault, txn, &report)?;
    Ok(report)
}
