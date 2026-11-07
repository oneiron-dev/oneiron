//! Whole-index scans. A run reads each eligible index to its end. The
//! Dreamer's run reads them in a read transaction, off the writer, then reads
//! each candidate again under the writer before its decision commits (FIX
//! 7425). An owner's run (`run_in_txn`) scans inside its own transaction.

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
    let scanned = {
        let rtxn = vault.store.env.read_txn()?;
        if let Some(report) = run_record::read_in_txn(vault, &rtxn, attempt)? {
            return Ok(report);
        }
        scan_in_txn(vault, &rtxn)?
    };
    vault.with_write_txn_grouped(|txn| {
        if let Some(report) = run_record::read_in_txn(vault, txn, attempt)? {
            return Ok(report);
        }
        // A row that stopped being a candidate since the scan drops out; a
        // row that became one waits for the next run.
        let mut candidates = Vec::with_capacity(scanned.len());
        for candidate in &scanned {
            if still_candidate_in_txn(vault, txn, candidate)? {
                candidates.push(*candidate);
            }
        }
        let report = run_cleanup_candidates_in_txn(vault, txn, attempt, candidates)?;
        run_record::put_in_txn(vault, txn, &report)?;
        Ok(report)
    })
}

/// Whether `candidate`, found by a scan off the writer, is still one in
/// `txn`, by the same arm that found it.
fn still_candidate_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    candidate: &CleanupCandidate,
) -> Result<bool> {
    match candidate.kind {
        CleanupKind::CompletedAttempt => {
            super::attempt_retention::still_eligible_in_txn(vault, txn, candidate.entity)
        }
        kind => Ok(zero_live_members_in_txn(vault, txn, &candidate.entity)? == Some(kind)),
    }
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
