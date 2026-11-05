//! Terminal settlement of a positively erased workflow checkpoint.

use heed::RwTxn;

use super::{TABLE, fence, invalid, key};
use crate::attempt_queue::{
    AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState, InterveneAttempt,
};
use crate::store::attempt_record::AttemptPause;
use crate::{Result, Vault};

const ERASED_CHECKPOINT: &str = "workflow_tool_checkpoint_erased";
const UNAVAILABLE_CHECKPOINT: &str = "workflow_tool_checkpoint_unavailable";
const UNREADABLE_CHECKPOINT: &str = "workflow_tool_checkpoint_source_unreadable";

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
    let row = TABLE.get(&vault.store, txn, &key(active.id)?)?;
    let fenced = fence::check(&vault.store, txn, active)?;
    let note = match row {
        Some(row) => {
            if row.attempt != active.id || row.generation != active.attempt_count || !fenced {
                return Err(invalid(
                    "workflow checkpoint settlement has foreign generation",
                ));
            }
            if let Some(content) = &row.content {
                if crate::agent_dispatch::AgentDispatcher::new(vault)
                    .workflow_tool_sources_readable_in_txn(
                        txn,
                        active,
                        &content.progress.known_sources,
                    )?
                {
                    return Ok(false);
                }
                UNREADABLE_CHECKPOINT
            } else if row.retained.is_some() {
                UNAVAILABLE_CHECKPOINT
            } else {
                ERASED_CHECKPOINT
            }
        }
        None if fenced => UNAVAILABLE_CHECKPOINT,
        None => return Ok(false),
    };
    AttemptQueue::new(vault).intervene_in_txn(
        txn,
        InterveneAttempt {
            id: active.id,
            kind: AttemptInterventionKind::Cancel,
            actor: "runtime".to_owned(),
            note: Some(note.to_owned()),
            now,
        },
    )?;
    Ok(true)
}
