//! A ledger row its provider accepted as a remote task (FIX 7960): its move
//! to Deferred with the task's handle, and its settlement by what the
//! provider later reports of that task.

use super::super::settlement::{RemoteTaskHandle, RemoteTaskObservation, keep_remote_task_in_txn};
use super::super::types::{
    IntentEscalationReason, IntentLedgerError, IntentLedgerRecord, IntentLedgerResult, IntentState,
    RecordedOutboundOutcome,
};
use super::transition::{Transitioned, transition_record_in_txn};
use super::{force_sync, get_ledger_record, open_payload_in_txn, transition_record_with_outcome};
use crate::Vault;
use crate::error::Error;

/// Moves row `id`, which its provider accepted as a remote task, to
/// Deferred with that task's handle kept beside it, in one writer (FIX
/// 7960). The engine never sends a Deferred row again.
pub(crate) fn defer_record(
    vault: &Vault,
    id: [u8; 32],
    handle: RemoteTaskHandle,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    let mut wtxn = vault.store.env.write_txn()?;
    let mut record = match transition_record_in_txn(
        vault,
        &mut wtxn,
        id,
        IntentState::Deferred,
        RecordedOutboundOutcome::Deferred,
        now_ms,
    )? {
        Transitioned::Moved(record) => record,
        Transitioned::Replayed(mut record) => {
            open_payload_in_txn(vault, &wtxn, &mut record)?;
            return Ok(record);
        }
    };
    keep_remote_task_in_txn(vault, &mut wtxn, &id, handle)?;
    open_payload_in_txn(vault, &wtxn, &mut record)?;
    wtxn.commit().map_err(Error::from)?;
    let synced = force_sync(vault);
    vault.wake_owner_shed();
    synced?;
    Ok(record)
}

/// Settles a Deferred row by what its provider reported of the remote task
/// (FIX 7960): a completed task is the send's Done, a failed one stops it.
fn settle_deferred_record(
    vault: &Vault,
    id: [u8; 32],
    observation: RemoteTaskObservation,
    now_ms: u64,
) -> IntentLedgerResult<IntentLedgerRecord> {
    let (next, outcome) = match observation {
        RemoteTaskObservation::Completed => (IntentState::Done, RecordedOutboundOutcome::Acked),
        RemoteTaskObservation::Failed => (
            IntentState::Abandoned,
            RecordedOutboundOutcome::Abandoned(IntentEscalationReason::RemoteTaskFailed),
        ),
    };
    {
        // Only a Deferred row settles by its remote task; a Pending one is
        // never completed by a provider's later word.
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let current = get_ledger_record(vault, &txn, &id)?.ok_or(
            IntentLedgerError::InvalidRecord("deferred outbound intent is missing"),
        )?;
        if current.state != IntentState::Deferred && current.state != next {
            return Err(IntentLedgerError::InvalidTransition {
                from: current.state,
                to: next,
            });
        }
    }
    transition_record_with_outcome(vault, id, next, outcome, now_ms)
}

impl Vault {
    /// Settles an outbound send its provider accepted as a remote task, by
    /// what that provider later reported of the task (FIX 7960): a completed
    /// task is the send's Done and settles its reserved budget; a failed one
    /// stops the send and gives that budget back. The caller is the trusted
    /// transport that read the provider's own status answer. Returns the
    /// row's state after.
    ///
    /// # Errors
    /// A row that is missing, is not Deferred, or does not read; storage
    /// errors.
    pub fn settle_remote_outbound_task(
        &self,
        intent_id: &[u8; 32],
        observation: RemoteTaskObservation,
    ) -> IntentLedgerResult<IntentState> {
        settle_deferred_record(self, *intent_id, observation, self.now_recorded_at())
            .map(|record| record.state)
    }
}
