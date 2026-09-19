//! Durable failure-ladder cases bind healer admission to the fenced failure.

use crate::attempt_queue::{AttemptQueue, AttemptState};
use crate::error::ArtifactError;
use crate::{EntityId, Error, Result, Vault};

use super::{HealerCase, dispatched_target_ref};

const CASE_PREFIX: &[u8] = b"healer:case:v1:";

fn key(case: &HealerCase) -> Vec<u8> {
    [CASE_PREFIX, case.case_ref.as_bytes()].concat()
}

/// Called only by the ladder, in the same transaction as its lease-fenced fail.
pub(super) fn record_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    case: &HealerCase,
) -> Result<()> {
    let key = key(case);
    if vault.store.vault_meta.get(txn, &key)?.is_some() {
        return Err(Error::CorruptedIndex("duplicate durable healer case"));
    }
    let bytes = rmp_serde::to_vec_named(case)
        .map_err(|_| Error::InvariantViolation("healer case encoding"))?;
    vault.store.vault_meta.put(txn, &key, &bytes)?;
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
    let raw = vault
        .store
        .vault_meta
        .get(txn, &key(case))?
        .ok_or_else(invalid)?;
    let authentic: HealerCase =
        rmp_serde::from_slice(&raw).map_err(|_| Error::CorruptedIndex("durable healer case"))?;
    if authentic != *case {
        return Err(invalid());
    }
    Ok(())
}
