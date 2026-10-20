//! The owner's apply of an action-mode finding's ceiling patch on the
//! applied list (FIX 1786): the finding's row takes the patch's inverse.
use super::{
    APPLIED, APPLY_REASON, AppliedMaintenance, AppliedRow, MAINTENANCE_APPLY_KIND,
    MaintenanceInverse, MaintenanceTarget, claim_revision_in_txn, decision, listed,
};
use crate::dreamer_runner::maintenance::{action_mode, invalid};
use crate::{EntityId, Result, Vault, WriteActor};

/// The applied row of action-mode `finding` once the owner applied its
/// ceiling patch (FIX 1786), for a second apply to return as it is; `None`
/// while no patch applied. A finding the owner reverted applies nothing.
pub(in crate::dreamer_runner::maintenance) fn action_mode_applied_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    finding: EntityId,
) -> Result<Option<AppliedMaintenance>> {
    let target = MaintenanceTarget::Finding(finding);
    let Some(row) = APPLIED.get(&vault.store, txn, &target)? else {
        return Ok(None);
    };
    if row.reverted.is_some() {
        return Err(invalid());
    }
    Ok(matches!(row.inverse, MaintenanceInverse::ActionMode { .. }).then(|| listed(target, row)))
}

/// Records the owner's apply of action-mode `finding`'s ceiling patch in its
/// write (FIX 1786): the finding's applied row takes `inverse` under the
/// owner's receipt, whose handle is the finding's revision then the row's
/// earlier receipt; a finding the owner approved in the run tray, which no
/// row holds, gets its row here.
pub(in crate::dreamer_runner::maintenance) fn record_action_mode_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    finding: EntityId,
    owner: WriteActor,
    inverse: MaintenanceInverse,
    now: u64,
) -> Result<AppliedMaintenance> {
    let target = MaintenanceTarget::Finding(finding);
    let revision = claim_revision_in_txn(vault, &*txn, &finding)?.ok_or_else(invalid)?;
    let held = APPLIED.get(&vault.store, &*txn, &target)?;
    let mut handle = revision.to_vec();
    if let Some(row) = &held {
        handle.extend_from_slice(&row.receipt.as_bytes());
    }
    let mut receipt = decision(
        owner,
        MAINTENANCE_APPLY_KIND,
        APPLY_REASON,
        target,
        handle,
        now,
    );
    vault
        .store
        .append_fresh_gate_decision_in_txn(txn, &mut receipt)?;
    let row = match held {
        Some(row) => AppliedRow {
            inverse,
            applied_at: now,
            receipt: receipt.decision_id,
            ..row
        },
        None => AppliedRow {
            inverse,
            attempt: None,
            facet: action_mode::ACTION_MODE_FACET.to_owned(),
            finding_revision: Some(revision),
            applied_at: now,
            receipt: receipt.decision_id,
            reverted: None,
        },
    };
    APPLIED.put(&vault.store, txn, &target, &row)?;
    Ok(listed(target, row))
}
