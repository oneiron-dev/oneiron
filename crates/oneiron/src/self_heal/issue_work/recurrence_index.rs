//! Each model finding's issue under its recurrence key (FIX 7343): one
//! membership row per issue, written in the transaction that files it, so a
//! judgment, an open check or a recurrence lookup reads exactly the issues
//! of its key, not every issue the Coach ever filed. A retry rewrites the
//! issue, never its key, so membership does not move.
use super::{DiagnosticIssue, ISSUES};
use crate::limit_ask::EngineLimit;
use crate::side_table::{self, Raw, SideTable};
use crate::{EntityId, Result, Vault};

/// An issue under its recurrence key. Key: the key, then the issue.
const BY_KEY: SideTable<([u8; 32], EntityId), (), Raw> =
    SideTable::new(&side_table::COACH_DIAGNOSTIC_ISSUE_BY_KEY);

/// Files `issue` under `key`, in the write that inserts its row.
pub(super) fn insert_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    issue: &EntityId,
) -> Result<()> {
    BY_KEY.put(&vault.store, txn, &(*key, *issue), &())
}

/// Every issue filed under `key`, read whole from its row in the same
/// snapshot, in issue order.
pub(in crate::self_heal) fn same_key_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 32],
) -> Result<Vec<(EntityId, DiagnosticIssue)>> {
    let mut rows = 0u64;
    let mut matched = Vec::new();
    for (_, issue_id) in BY_KEY.scan_keys(&vault.store, txn, key)? {
        rows += 1;
        if let Some(issue) = ISSUES.get(&vault.store, txn, &issue_id)? {
            matched.push((issue_id, issue));
        }
    }
    // Every member is read: past its threshold row the read asks and reads on.
    let _ = vault.measure_limit(EngineLimit::MaintenanceScanRows, rows);
    Ok(matched)
}
