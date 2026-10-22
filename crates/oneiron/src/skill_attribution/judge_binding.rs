//! The judge a run's pack attribution names (FIX 1877, OF-540): the model
//! whose answer to the run's "Done means met?" stands, recorded in the
//! report write that takes that answer, under the run's live lease. A run
//! no model judged keeps its judge unknown; nothing guesses one.

use crate::Vault;
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::error::Result;
use crate::llm::decision::ProviderPin;

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
    crate::receipt::finalize_attempt_pack_judge_in_txn(&vault.store, txn, attempt, &pinned(judge))
}

/// `pin` as `model@revision`: its model as it stands when that already
/// names a revision, else its model at its version.
fn pinned(pin: &ProviderPin) -> String {
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
