//! Polling the remote tasks providers accepted sends as (FIX 11023). A
//! Deferred row whose handle keeps how to poll it (the MCP session the task
//! was created in, the protocol revision the send pinned, and the
//! credential it presented, when that can be presented again) is polled by
//! the served host: one MCP `tasks/get` per due row, under the row's own
//! frozen endpoint and binding, never its `tools/call` again. A completed
//! task is the send's Done; a failed, cancelled or vanished one stops it
//! with its delivery uncertain (the provider has not shown it never took
//! effect), its reserved budget kept; a running one is polled again after
//! the provider's hint, never sooner than the host's pass, backing off while
//! it runs. A task waiting on input (`input_required`) is polled as running:
//! this host answers no task input, so such a task ends when its provider
//! drops it. The poll table keeps only
//! the next poll time, the count and the last status: the session and the
//! credential choice stay in the handle, which an erase forgets.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::settlement::{RemoteTaskHandle, RemoteTaskObservation, intent_settlement_in_txn};
use super::types::{FrozenOutboundCall, IntentLedgerResult, IntentState};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Each pollable Deferred row's next poll, by its intent id.
const POLLS: SideTable<[u8; 32], RemoteTaskPollState, Named> =
    SideTable::new(&side_table::OUTBOUND_REMOTE_TASK_POLL);

/// The shortest wait between two polls of one task: the host's own pass.
pub const MIN_REMOTE_TASK_POLL_MS: u64 = 30_000;
/// The longest wait a running task backs off to.
const MAX_REMOTE_TASK_POLL_MS: u64 = 15 * 60 * 1_000;
/// The longest status text kept.
const MAX_STATUS_BYTES: usize = 64;

/// How a remote task is polled: what the send the provider took as a task
/// had open. Opaque provider data: never logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTaskPoll {
    /// The MCP session the task was created in (`Mcp-Session-Id`), kept
    /// open for its polls; `None` for a server that keeps no session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// The protocol revision the send pinned (`MCP-Protocol-Version`).
    pub protocol: String,
    /// The credential the send presented, presented again for each poll.
    pub credential: RemoteTaskCredential,
}

impl fmt::Debug for RemoteTaskPoll {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTaskPoll")
            .field("session", &self.session.as_ref().map(|_| "[redacted]"))
            .field("protocol", &self.protocol)
            .field("credential", &self.credential)
            .finish()
    }
}

/// The credential a send presented, as a poll presents it again. A secret
/// grant's redemption or a run's own record cannot be presented after the
/// send, so such a send keeps no poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteTaskCredential {
    /// The custody record the call named (`self.use`).
    Record(EntityId),
    /// What the connector route presents of its own (its secret, resolved
    /// again at each poll, or nothing when it names none).
    Route,
}

/// How a polled task ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteTaskEnd {
    /// The provider says it completed: the send was delivered.
    Completed,
    /// It failed, was cancelled, or the provider no longer knows it: the
    /// provider has not shown whether the send took effect.
    Unconfirmed,
}

/// One pollable row's place.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct RemoteTaskPollState {
    next_poll_ms: u64,
    polls: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_status: Option<String>,
}

/// One Deferred send whose task is due a poll.
pub struct DueRemoteTask {
    pub intent: [u8; 32],
    /// The row's frozen call, opened: its endpoint, server, tool and binding.
    pub call: FrozenOutboundCall,
    /// The provider's task id. Opaque, untrusted: never logged.
    pub task_id: String,
    pub poll: RemoteTaskPoll,
    /// The polls made of it so far.
    pub polls: u32,
}

impl fmt::Debug for DueRemoteTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DueRemoteTask")
            .field(
                "task_id",
                &format_args!("[{} bytes redacted]", self.task_id.len()),
            )
            .field("poll", &self.poll)
            .field("polls", &self.polls)
            .finish_non_exhaustive()
    }
}

/// When the first poll of a task the provider hinted `poll_after_secs` for
/// is due.
fn first_poll_ms(handle: &RemoteTaskHandle, now_ms: u64) -> u64 {
    let after = handle
        .poll_after_secs
        .map_or(MIN_REMOTE_TASK_POLL_MS, |secs| {
            secs.saturating_mul(1_000).max(MIN_REMOTE_TASK_POLL_MS)
        });
    now_ms.saturating_add(after)
}

/// In the writer that defers row `id` with `handle`: schedules its first
/// poll, when the handle keeps how to poll it.
///
/// # Errors
/// Storage faults.
pub(crate) fn schedule_first_poll_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
    handle: &RemoteTaskHandle,
    now_ms: u64,
) -> crate::Result<()> {
    if handle.poll.is_none() {
        return Ok(());
    }
    POLLS.put(
        &vault.store,
        wtxn,
        id,
        &RemoteTaskPollState {
            next_poll_ms: first_poll_ms(handle, now_ms),
            polls: 0,
            last_status: None,
        },
    )
}

impl Vault {
    /// The Deferred sends whose tasks are due a poll at `now_ms`, at most
    /// `limit`, each with its frozen call opened. A poll row whose ledger
    /// row is gone, settled, or keeps no poll any more is dropped.
    ///
    /// # Errors
    /// Storage, row-codec and custody faults.
    pub fn remote_tasks_due(
        &self,
        now_ms: u64,
        limit: usize,
    ) -> IntentLedgerResult<Vec<DueRemoteTask>> {
        let mut due = Vec::new();
        let mut stale = Vec::new();
        {
            let txn = self
                .store
                .env
                .read_txn()
                .map_err(crate::error::Error::from)?;
            for row in POLLS.iter_from(&self.store, &txn, &[])? {
                let (id, state) = row?;
                let Some(mut record) = super::store::get_ledger_record(self, &txn, &id)? else {
                    stale.push(id);
                    continue;
                };
                if record.state != IntentState::Deferred {
                    stale.push(id);
                    continue;
                }
                if state.next_poll_ms > now_ms || due.len() >= limit {
                    continue;
                }
                let Some(handle) = intent_settlement_in_txn(self, &txn, &id)?.remote_task else {
                    stale.push(id);
                    continue;
                };
                let Some(poll) = handle.poll else {
                    stale.push(id);
                    continue;
                };
                super::payload::open_payload_in_txn(self, &txn, &mut record)?;
                due.push(DueRemoteTask {
                    intent: id,
                    call: FrozenOutboundCall::from_record(&record),
                    task_id: handle.id,
                    poll,
                    polls: state.polls,
                });
            }
        }
        if !stale.is_empty() {
            self.with_write_txn_grouped(|txn| {
                for id in &stale {
                    POLLS.delete(&self.store, txn, id)?;
                }
                Ok(())
            })?;
        }
        Ok(due)
    }

    /// Records a poll that found row `intent`'s task still running, as
    /// `status`: its next poll waits the longer of the provider's hint
    /// (`poll_after_ms`) and a backoff that starts at the host's pass and
    /// doubles with each poll up to fifteen minutes.
    ///
    /// # Errors
    /// Storage faults.
    pub fn remote_task_polled(
        &self,
        intent: &[u8; 32],
        poll_after_ms: Option<u64>,
        status: &str,
        now_ms: u64,
    ) -> IntentLedgerResult<()> {
        let mut status = status.to_owned();
        if status.len() > MAX_STATUS_BYTES || !status.bytes().all(|byte| byte.is_ascii_graphic()) {
            status = "unrecognized".to_owned();
        }
        self.with_write_txn_grouped(|txn| {
            let Some(mut state) = POLLS.get(&self.store, txn, intent)? else {
                return Ok(());
            };
            state.polls = state.polls.saturating_add(1);
            let backoff = MIN_REMOTE_TASK_POLL_MS
                .saturating_mul(1_u64 << state.polls.min(5))
                .min(MAX_REMOTE_TASK_POLL_MS);
            let after = backoff.max(poll_after_ms.unwrap_or(0));
            state.next_poll_ms = now_ms.saturating_add(after);
            state.last_status = Some(status);
            POLLS.put(&self.store, txn, intent, &state)
        })?;
        Ok(())
    }

    /// Whether row `intent` is still a Deferred send whose kept handle names
    /// the task `task_id` and keeps how to poll it: read again just before a
    /// poll leaves, so an erase or a settlement since the pass began sends
    /// nothing.
    ///
    /// # Errors
    /// Storage and row-codec faults.
    pub fn remote_task_still_due(
        &self,
        intent: &[u8; 32],
        task_id: &str,
    ) -> IntentLedgerResult<bool> {
        let txn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        let deferred = super::store::get_ledger_record(self, &txn, intent)?
            .is_some_and(|record| record.state == IntentState::Deferred);
        Ok(deferred
            && intent_settlement_in_txn(self, &txn, intent)?
                .remote_task
                .is_some_and(|handle| handle.id == task_id && handle.poll.is_some()))
    }

    /// Settles row `intent` by how a poll found its task ended (FIX 11023):
    /// a completed task is the send's Done
    /// ([`Vault::settle_remote_outbound_task`]); any other end stops the send
    /// with its delivery uncertain and its reserved budget kept. Its poll row
    /// goes.
    ///
    /// # Errors
    /// A row that is not Deferred; storage faults.
    pub fn settle_polled_remote_task(
        &self,
        intent: &[u8; 32],
        end: RemoteTaskEnd,
    ) -> IntentLedgerResult<IntentState> {
        let state = match end {
            RemoteTaskEnd::Completed => {
                self.settle_remote_outbound_task(intent, RemoteTaskObservation::Completed)?
            }
            RemoteTaskEnd::Unconfirmed => super::store::abandon_unconfirmed_remote_task(
                self,
                *intent,
                self.now_recorded_at(),
            )?,
        };
        self.with_write_txn_grouped(|txn| POLLS.delete(&self.store, txn, intent).map(|_| ()))?;
        Ok(state)
    }
}
