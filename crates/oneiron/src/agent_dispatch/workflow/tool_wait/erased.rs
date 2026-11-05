//! Terminal settlement of a positively erased workflow checkpoint.

use heed::RwTxn;

use super::{TABLE, invalid, key};
use crate::attempt_queue::{
    AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState, InterveneAttempt,
};
use crate::store::attempt_record::AttemptPause;
use crate::{Result, Vault};

const ERASED_CHECKPOINT: &str = "workflow_tool_checkpoint_erased";

/// The caller selected this active leaf from its native workflow record in
/// this writer. The erased row is a fence, never permission for a fresh call.
/// Other holds and an in-flight lease or landing keep their own settlement.
pub(crate) fn settle_erased_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    active: &AttemptRecord,
    now: u64,
) -> Result<bool> {
    let eligible = matches!(active.state, AttemptState::Queued | AttemptState::Scheduled)
        || (active.state == AttemptState::Paused
            && matches!(active.active_pause, Some(AttemptPause::Hook { .. })));
    if !eligible {
        return Ok(false);
    }
    let Some(row) = TABLE.get(&vault.store, txn, &key(active.id)?)? else {
        return Ok(false);
    };
    if row.attempt != active.id || row.generation != active.attempt_count {
        return Err(invalid(
            "workflow checkpoint settlement has foreign generation",
        ));
    }
    if row.content.is_some() {
        return Ok(false);
    }
    AttemptQueue::new(vault).intervene_in_txn(
        txn,
        InterveneAttempt {
            id: active.id,
            kind: AttemptInterventionKind::Cancel,
            actor: "runtime".to_owned(),
            note: Some(ERASED_CHECKPOINT.to_owned()),
            now,
        },
    )?;
    Ok(true)
}
