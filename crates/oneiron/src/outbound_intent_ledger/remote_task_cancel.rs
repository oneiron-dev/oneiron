//! The owner's stop of a remote task (L8-29; canon agent-runtime-v1
//! `#mcp-tasks-outbound`, ONEIRON-MCP-TASKS = AB): the served host asks the
//! connector to stop the work with one MCP `tasks/cancel`, which undoes
//! nothing already done.
//!
//! The owner asks for it on the call's intent
//! (`POST /v1/owner/connectors/remote-tasks/{intent}/cancel`), and the
//! owner's Stop of a try asks for it for each of that try's Deferred sends,
//! in the Stop's writer. The ask is a mark on the task's poll row, so only a
//! send whose task the host polls takes one: a send whose credential cannot
//! be presented again keeps no poll, and its ask is refused as
//! `remote_task_unpollable`. The mark makes the row due on the host's next
//! pass, which claims it (Sending, in the writer that commits before the
//! POST) and records how the POST went: Sent when the connector took it,
//! Uncertain when that is unknown. A refused or unsent stop stays Sending. A
//! claimed stop is never claimed or sent again, so a crash after its POST
//! sends nothing more.
//!
//! The send stays Deferred: only the end state a later poll reads
//! (`cancelled`, or `completed` when the work finished first) settles it,
//! and `tools/call` is never sent again. The ledger row, its payload,
//! budget and settlement stay as they are; the mark goes with the poll row
//! when the task ends or the row is erased.

use serde::{Deserialize, Serialize};

use super::remote_task_poll::POLLS;
use super::settlement::intent_settlement_in_txn;
use super::types::{IntentLedgerError, IntentLedgerResult, IntentState};
use crate::Vault;
use crate::consent::AuthenticatedOwner;

/// Where the owner's stop of a remote task stands, on its poll row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTaskCancelPhase {
    /// Asked for: the host's next pass sends `tasks/cancel`.
    Requested,
    /// The host claimed the stop and may have sent it; it is never sent
    /// again.
    Sending,
    /// The connector took the stop.
    Sent,
    /// Whether the connector took the stop is unknown; it is never sent
    /// again.
    Uncertain,
}

impl RemoteTaskCancelPhase {
    /// The phase's wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Sending => "sending",
            Self::Sent => "sent",
            Self::Uncertain => "uncertain",
        }
    }
}

/// What an ask to stop a remote task came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteTaskCancelAsk {
    /// The stop is marked, now or by an earlier ask: where it stands.
    Marked(RemoteTaskCancelPhase),
    /// No call has this intent.
    Unknown,
    /// The call is not a Deferred send: its connector never took it as a
    /// remote task, or the task already ended.
    NotDeferred,
    /// The send's task keeps no poll (its credential cannot be presented
    /// again), so nothing can carry the stop.
    Unpollable,
}

/// Marks row `id`'s remote task for the owner's stop in `wtxn`, due on the
/// host's next pass. A stop already marked keeps its phase. Opens no
/// writer.
///
/// # Errors
/// Storage and row-codec faults.
pub(super) fn request_remote_task_cancel_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
) -> IntentLedgerResult<RemoteTaskCancelAsk> {
    let Some(record) = super::store::get_ledger_record(vault, wtxn, id)? else {
        return Ok(RemoteTaskCancelAsk::Unknown);
    };
    if record.state != IntentState::Deferred {
        return Ok(RemoteTaskCancelAsk::NotDeferred);
    }
    let pollable = intent_settlement_in_txn(vault, wtxn, id)?
        .remote_task
        .is_some_and(|handle| handle.poll.is_some());
    let Some(mut state) = POLLS.get(&vault.store, wtxn, id)?.filter(|_| pollable) else {
        return Ok(RemoteTaskCancelAsk::Unpollable);
    };
    if let Some(phase) = state.cancel {
        return Ok(RemoteTaskCancelAsk::Marked(phase));
    }
    state.cancel = Some(RemoteTaskCancelPhase::Requested);
    // Due at once, however long the task's backoff has grown.
    state.next_poll_ms = 0;
    POLLS.put(&vault.store, wtxn, id, &state)?;
    Ok(RemoteTaskCancelAsk::Marked(
        RemoteTaskCancelPhase::Requested,
    ))
}

/// Moves row `id`'s stop from `from` to `to` in `wtxn`, when its poll row
/// is there and its stop stands at `from`. Whether it moved.
fn move_cancel_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
    from: RemoteTaskCancelPhase,
    to: RemoteTaskCancelPhase,
) -> IntentLedgerResult<bool> {
    let Some(mut state) = POLLS.get(&vault.store, wtxn, id)? else {
        return Ok(false);
    };
    if state.cancel != Some(from) {
        return Ok(false);
    }
    state.cancel = Some(to);
    POLLS.put(&vault.store, wtxn, id, &state)?;
    Ok(true)
}

/// A ledger fault inside the owner's door, as the door reports it.
fn owner_door_error(error: IntentLedgerError) -> crate::Error {
    match error {
        IntentLedgerError::Engine(error) => error,
        other => crate::Error::InvalidConfig(other.to_string()),
    }
}

impl Vault {
    /// The owner asks the remote task of the call `intent` to stop (L8-29):
    /// in one writer that checks the owner's proof again, a Deferred send
    /// whose task the host polls is marked, and the host's next pass sends
    /// the connector one `tasks/cancel`. The send stays Deferred until a
    /// poll reads the task's end. An ask on a stop already marked answers
    /// where it stands and marks nothing again.
    ///
    /// # Errors
    /// An owner proof that no longer holds; storage and row-codec faults.
    pub fn request_remote_task_cancel(
        &self,
        owner: &AuthenticatedOwner,
        intent: &[u8; 32],
    ) -> crate::Result<RemoteTaskCancelAsk> {
        self.with_write_txn_grouped(|txn| {
            owner.revalidate_in_txn(self, txn)?;
            request_remote_task_cancel_in_txn(self, txn, intent).map_err(owner_door_error)
        })
    }

    /// Claims the owner's stop of row `intent`'s task `task_id` for the
    /// host's POST (L8-29): only a row still Deferred on that task, its
    /// handle keeping how to poll it, whose stop is Requested, moves to
    /// Sending, in a writer the caller's POST waits on. Whether it did: a
    /// stop claimed once is never claimed again.
    ///
    /// # Errors
    /// Storage and row-codec faults.
    pub fn claim_remote_task_cancel(
        &self,
        intent: &[u8; 32],
        task_id: &str,
    ) -> IntentLedgerResult<bool> {
        self.try_with_write_txn_grouped(|txn| -> IntentLedgerResult<bool> {
            let deferred = super::store::get_ledger_record(self, txn, intent)?
                .is_some_and(|record| record.state == IntentState::Deferred);
            let polled = deferred
                && intent_settlement_in_txn(self, txn, intent)?
                    .remote_task
                    .is_some_and(|handle| handle.id == task_id && handle.poll.is_some());
            if !polled {
                return Ok(false);
            }
            move_cancel_in_txn(
                self,
                txn,
                intent,
                RemoteTaskCancelPhase::Requested,
                RemoteTaskCancelPhase::Sending,
            )
        })
    }

    /// Records that the connector took row `intent`'s claimed stop: Sent.
    /// Only a Sending stop moves.
    ///
    /// # Errors
    /// Storage and row-codec faults.
    pub fn record_remote_task_cancel_sent(&self, intent: &[u8; 32]) -> IntentLedgerResult<()> {
        self.try_with_write_txn_grouped(|txn| {
            move_cancel_in_txn(
                self,
                txn,
                intent,
                RemoteTaskCancelPhase::Sending,
                RemoteTaskCancelPhase::Sent,
            )
            .map(|_| ())
        })
    }

    /// Records that whether the connector took row `intent`'s claimed stop
    /// is unknown, or that it was not sent after its claim: Uncertain, never
    /// sent again. Only a Sending stop moves.
    ///
    /// # Errors
    /// Storage and row-codec faults.
    pub fn record_remote_task_cancel_uncertain(&self, intent: &[u8; 32]) -> IntentLedgerResult<()> {
        self.try_with_write_txn_grouped(|txn| {
            move_cancel_in_txn(
                self,
                txn,
                intent,
                RemoteTaskCancelPhase::Sending,
                RemoteTaskCancelPhase::Uncertain,
            )
            .map(|_| ())
        })
    }
}
