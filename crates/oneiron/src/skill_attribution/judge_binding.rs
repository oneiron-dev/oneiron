//! The judge a run's pack attribution names (FIX 1877, OF-540): the model
//! whose answer to the run's "Done means met?" stands, recorded in the
//! report write that takes that answer, under the run's live lease. A run
//! no model judged keeps its judge unknown; nothing guesses one.

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::error::Result;
use crate::model_decision::ProviderPin;

/// Records `judge` as the judge of the leased run `attempt` at lease
/// generation `generation`, in the report writer `txn` that settles it,
/// before its terminal receipt freezes the attribution. Returns whether it
/// recorded one now: a run that no longer holds that lease or carries no
/// attribution records nothing, and a judge already recorded stays.
///
/// It reads and writes only through `txn`.
///
/// # Errors
///
/// A lease the row no longer holds, a malformed pin, and storage errors.
pub(crate) fn finalize_run_judge_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    generation: u32,
    judge: &ProviderPin,
) -> Result<bool> {
    let queue = AttemptQueue::new(vault);
    let Some(record) = queue.get_in_txn(txn, attempt)? else {
        return Ok(false);
    };
    let Some(lease_owner) = record.lease_owner.as_deref() else {
        return Ok(false);
    };
    if record.attempt_count != generation {
        return Ok(false);
    }
    queue.require_skill_load_lease_in_txn(txn, attempt, lease_owner, generation)?;
    crate::receipt::finalize_attempt_pack_judge_in_txn(
        &vault.store,
        txn,
        attempt,
        &pinned_judge_model(judge),
    )
}

/// `pin` as `model@revision`: its model as it stands when that already
/// names a revision, else its model at its version.
pub(crate) fn pinned_judge_model(pin: &ProviderPin) -> String {
    if pin
        .model
        .rsplit_once('@')
        .is_some_and(|(id, revision)| !id.is_empty() && !revision.is_empty())
    {
        pin.model.clone()
    } else {
        format!("{}@{}", pin.model, pin.version)
    }
}

/// Joins the model actually used by a saved workflow's Done report without
/// changing the wrapper's frozen receipt or its former lease.
pub(super) fn with_workflow_judge_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt_receipt: &str,
    mut fields: crate::receipt::PackAttributionFields,
) -> Result<crate::receipt::PackAttributionFields> {
    if fields.judge.is_some() {
        return Ok(fields);
    }
    let Some(receipt) =
        crate::receipt::attempt_pack_receipt_in_txn(&vault.store, txn, attempt_receipt)?
    else {
        return Ok(fields);
    };
    let Some(generation) = receipt.lease_generation() else {
        return Ok(fields);
    };
    let Some(task) = receipt
        .trigger_ref
        .as_deref()
        .and_then(|task| crate::entity_id::EntityId::from_hex(task).ok())
    else {
        return Ok(fields);
    };
    let Some(attempt) = attempt_receipt
        .rsplit_once(':')
        .and_then(|(_, hex)| crate::entity_id::EntityId::from_hex(hex).ok())
        .and_then(|id| AttemptId::from_bytes(id.as_bytes()).ok())
        .filter(|attempt| crate::receipt::attempt_pack_receipt_id(attempt) == attempt_receipt)
    else {
        return Ok(fields);
    };
    fields.judge =
        crate::task_verb::workflow_done_judge_in_txn(vault, txn, attempt, generation, task)?;
    fields.validate()?;
    Ok(fields)
}
