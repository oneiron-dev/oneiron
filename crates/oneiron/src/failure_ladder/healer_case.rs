//! Durable failure-ladder cases bind healer admission to the fenced failure.

use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::error::ArtifactError;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

use super::{HealerCase, dispatched_target_ref};

/// Durable failure-ladder case authenticating one healer admission, bound to its lease-fenced
/// failed attempt. Key: hex32 (case_ref).
const CASE: SideTable<String, HealerCase, Named> = SideTable::new(&side_table::HEALER_CASE);

/// Called only by the ladder, in the same transaction as its lease-fenced fail.
pub(super) fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case: &HealerCase,
) -> Result<()> {
    // The lease-fenced failure shares this transaction: invalid context aborts both rows.
    crate::agent_dispatch::validate_healer_case(case)?;
    if CASE.contains(&vault.store, txn, &case.case_ref)? {
        return Err(Error::CorruptedIndex("duplicate durable healer case"));
    }
    CASE.put(&vault.store, txn, &case.case_ref, case)?;
    Ok(())
}

/// Authentication runs before either enqueue or oversight activity, including
/// dedupe replays. A public case DTO is context, never its own authority.
pub(crate) fn require_in_txn(
    vault: &Vault,
    txn: &heed::RwTxn<'_>,
    case: &HealerCase,
    run_id: Option<&str>,
) -> Result<()> {
    let invalid = || {
        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "healer context requires its authentic durable failed-attempt case",
        ))
    };
    let parent = AttemptQueue::new(vault)
        .get_in_write_txn(txn, case.failing_attempt_id)?
        .ok_or_else(invalid)?;
    if parent.state != AttemptState::Failed
        || parent.task_ref != case.task_ref
        || parent.run_id.as_deref() != run_id
        || dispatched_target_ref(&parent)
            != Some(EntityId::from_hex(&case.scope.agent_ref).map_err(|_| invalid())?)
    {
        return Err(invalid());
    }
    let authentic = CASE
        .get(&vault.store, txn, &case.case_ref)?
        .ok_or_else(invalid)?;
    if authentic != *case {
        return Err(invalid());
    }
    Ok(())
}
