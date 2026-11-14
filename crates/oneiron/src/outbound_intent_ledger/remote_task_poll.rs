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
//! it runs. A task waiting on input (`input_required`) is polled as running,
//! its requests read through `tasks/result`: a form question, in a session
//! that declared form elicitation, is parked for the owner, and a task whose
//! parked question the owner answered is due on the host's next pass, which
//! sends the answer (FIX 16029). Each writer that drops a task's poll row
//! forgets its parked question and stages the retirement of its task-input
//! subject, whether or not a question ever committed, or keeps the poll row
//! for the next pass. A session the connector ended (HTTP 404) is
//! renewed: the host opens a new one under the row's own endpoint and
//! credential, declaring what the send's session declared, and the handle
//! keeps its id for the polls that follow (FIX 16028). A session
//! whose handle goes before it ended (an erase takes the request, or the
//! row settles another way) is owed its end: the host ends it on its next
//! pass. The poll table keeps only
//! the next poll time, the count, the last status and where the owner's
//! stop of the task stands (L8-29, `remote_task_cancel`): the
//! session and the credential choice stay in the handle, which an erase
//! forgets.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::remote_task_cancel::RemoteTaskCancelPhase;
use super::settlement::{RemoteTaskHandle, RemoteTaskObservation, intent_settlement_in_txn};
use super::types::{FrozenOutboundCall, IntentLedgerError, IntentLedgerResult, IntentState};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// Each pollable Deferred row's next poll, by its intent id.
pub(super) const POLLS: SideTable<[u8; 32], RemoteTaskPollState, Named> =
    SideTable::new(&side_table::OUTBOUND_REMOTE_TASK_POLL);

/// Each MCP session a remote task's polls kept open whose handle went
/// before the session ended (FIX 16028): the served host ends each, then
/// drops its row.
const SESSION_ENDS: SideTable<[u8; 32], RemoteTaskSessionEnd, Named> =
    SideTable::new(&side_table::OUTBOUND_REMOTE_TASK_SESSION_END);

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
    /// The MCP session the task's polls go in (`Mcp-Session-Id`): the one
    /// it was created in, kept open for them, or the one that replaced it
    /// once the connector ended that one; `None` for a server that keeps no
    /// session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// The protocol revision the send pinned (`MCP-Protocol-Version`).
    pub protocol: String,
    /// The credential the send presented, presented again for each poll.
    pub credential: RemoteTaskCredential,
    /// Whether the send's `initialize` declared form elicitation (FIX
    /// 16029): a renewed session declares the same, and only then is a form
    /// question the task asks parked for the owner. A handle kept without
    /// it reads as none declared.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub form_elicitation: bool,
}

impl fmt::Debug for RemoteTaskPoll {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTaskPoll")
            .field("session", &self.session.as_ref().map(|_| "[redacted]"))
            .field("protocol", &self.protocol)
            .field("credential", &self.credential)
            .field("form_elicitation", &self.form_elicitation)
            .finish()
    }
}

/// An MCP session a remote task's polls kept open, owed its end: where it
/// is, and the credential that opens it. Opaque provider data: never
/// logged.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteTaskSessionEnd {
    /// The connector the call went to, by its registry name.
    pub server: String,
    pub tool: String,
    pub endpoint: String,
    /// The key the call's binding named, 32-hex, when it named one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
    /// The protocol revision the send pinned.
    pub protocol: String,
    /// The session (`Mcp-Session-Id`).
    pub session: String,
    pub credential: RemoteTaskCredential,
}

impl fmt::Debug for RemoteTaskSessionEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteTaskSessionEnd")
            .field("server", &self.server)
            .field("tool", &self.tool)
            .field("protocol", &self.protocol)
            .field("session", &"[redacted]")
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

/// Keeps, in `wtxn`, the end owed to the MCP session row `id`'s remote
/// task is polled in, before its handle goes (FIX 16028): the served host
/// ends it. A handle that keeps no session, or a row whose frozen call does
/// not read, owes none.
///
/// # Errors
/// Storage, row-codec and custody faults.
pub(crate) fn keep_session_end_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &[u8; 32],
) -> IntentLedgerResult<()> {
    let Some(poll) = intent_settlement_in_txn(vault, wtxn, id)?
        .remote_task
        .and_then(|handle| handle.poll)
    else {
        return Ok(());
    };
    let Some(session) = poll.session else {
        return Ok(());
    };
    let Some(mut record) = super::store::get_ledger_record(vault, wtxn, id)? else {
        return Ok(());
    };
    // A payload that does not open names no session's place: the erase it
    // runs in never fails for it.
    if super::payload::open_payload_in_txn(vault, wtxn, &mut record).is_err() {
        return Ok(());
    }
    let call = FrozenOutboundCall::from_record(&record);
    let Ok(view) = crate::outbound_consent::FrozenToolCallView::read(&call) else {
        return Ok(());
    };
    let end = RemoteTaskSessionEnd {
        server: view.server().to_owned(),
        tool: view.tool().to_owned(),
        endpoint: view.endpoint().to_owned(),
        key_ref: view.key_ref().map(str::to_owned),
        protocol: poll.protocol,
        session,
        credential: poll.credential,
    };
    SESSION_ENDS.put(&vault.store, wtxn, id, &end)?;
    Ok(())
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
pub(super) struct RemoteTaskPollState {
    pub(super) next_poll_ms: u64,
    polls: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_status: Option<String>,
    /// Where the owner's stop of the task stands (L8-29); `None` while
    /// nobody asked for it. A row kept without it reads as none asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) cancel: Option<RemoteTaskCancelPhase>,
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
    /// Whether the owner asked the task to stop and the host has not yet
    /// claimed that stop (L8-29): the pass sends `tasks/cancel` first.
    pub cancel_requested: bool,
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
            .field("cancel_requested", &self.cancel_requested)
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
            cancel: None,
        },
    )
}

impl Vault {
    /// The Deferred sends whose tasks are due a poll at `now_ms`, at most
    /// `limit`, each with its frozen call opened. A poll row whose ledger
    /// row is gone, settled, or keeps no poll any more is dropped, in the
    /// writer that forgets its task's parked question and stages the
    /// retirement of its task-input subject whether or not a question
    /// committed (FIX 16029); a row whose question cannot be forgotten now
    /// stays for the next pass, so the intent is found again. The key
    /// retirements are carried out after the commit.
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
                    cancel_requested: state.cancel == Some(RemoteTaskCancelPhase::Requested),
                });
            }
        }
        if !stale.is_empty() {
            let withdrawn =
                self.try_with_write_txn_grouped(|txn| -> IntentLedgerResult<Vec<u64>> {
                    let mut withdrawn = Vec::new();
                    for id in &stale {
                        // The task is done with: its parked question goes, and
                        // its task-input subject's retirement is staged even
                        // with no question row (a first park whose writer
                        // failed may have published its key, FIX 16029).
                        match self.forget_input_in_txn(txn, id) {
                            Ok(ask) => withdrawn.extend(ask),
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    "a remote task's parked question was not forgotten; its poll \
                                     row waits for the next pass"
                                );
                                continue;
                            }
                        }
                        // A row settled another way may keep the session its
                        // polls had open: it is owed its end (FIX 16028).
                        keep_session_end_in_txn(self, txn, id)?;
                        POLLS.delete(&self.store, txn, id)?;
                    }
                    Ok(withdrawn)
                })?;
            for seq in withdrawn {
                self.signal_decision_answer(seq);
            }
            self.finish_remote_task_input_retirements();
        }
        Ok(due)
    }

    /// The MCP sessions owed their end, at most `limit` (FIX 16028).
    ///
    /// # Errors
    /// Storage and row-codec faults.
    pub fn remote_task_sessions_to_end(
        &self,
        limit: usize,
    ) -> IntentLedgerResult<Vec<([u8; 32], RemoteTaskSessionEnd)>> {
        let txn = self
            .store
            .env
            .read_txn()
            .map_err(crate::error::Error::from)?;
        SESSION_ENDS
            .iter_from(&self.store, &txn, &[])?
            .take(limit)
            .map(|row| row.map_err(IntentLedgerError::from))
            .collect()
    }

    /// Drops the end owed to row `intent`'s session: the host ended it, or
    /// can no longer reach it.
    ///
    /// # Errors
    /// Storage faults.
    pub fn remote_task_session_ended(&self, intent: &[u8; 32]) -> IntentLedgerResult<()> {
        self.with_write_txn_grouped(|txn| {
            SESSION_ENDS.delete(&self.store, txn, intent).map(|_| ())
        })?;
        Ok(())
    }

    /// Records a poll that found row `intent`'s task still running, as
    /// `status`: its next poll waits the longer of the provider's hint
    /// (`poll_after_ms`) and a backoff that starts at the host's pass and
    /// doubles with each poll up to fifteen minutes. A stop the owner asked
    /// for after this poll's pass read the row (`stop_seen` false while the
    /// row's stop is Requested) keeps its due-now poll, so the next pass
    /// sends it (L8-29).
    ///
    /// # Errors
    /// Storage faults.
    pub fn remote_task_polled(
        &self,
        intent: &[u8; 32],
        poll_after_ms: Option<u64>,
        status: &str,
        now_ms: u64,
        stop_seen: bool,
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
            let stop_asked_since =
                !stop_seen && state.cancel == Some(RemoteTaskCancelPhase::Requested);
            if !stop_asked_since {
                let backoff = MIN_REMOTE_TASK_POLL_MS
                    .saturating_mul(1_u64 << state.polls.min(5))
                    .min(MAX_REMOTE_TASK_POLL_MS);
                let after = backoff.max(poll_after_ms.unwrap_or(0));
                state.next_poll_ms = now_ms.saturating_add(after);
            }
            state.last_status = Some(status);
            POLLS.put(&self.store, txn, intent, &state)
        })?;
        Ok(())
    }

    /// Makes the polls of `intents` due at `now_ms` (FIX 16029): each is a
    /// task whose parked question the owner answered, which the host's next
    /// pass drives to `tasks/result` however recently it last read the task.
    /// The backoff of every other poll stays as it is; an intent with no
    /// poll row, or one already due, changes nothing.
    ///
    /// # Errors
    /// Storage faults.
    pub fn remote_task_polls_due_at(
        &self,
        intents: &[[u8; 32]],
        now_ms: u64,
    ) -> IntentLedgerResult<()> {
        if intents.is_empty() {
            return Ok(());
        }
        self.with_write_txn_grouped(|txn| {
            for intent in intents {
                let Some(mut state) = POLLS.get(&self.store, txn, intent)? else {
                    continue;
                };
                if state.next_poll_ms > now_ms {
                    state.next_poll_ms = now_ms;
                    POLLS.put(&self.store, txn, intent, &state)?;
                }
            }
            Ok(())
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

    /// Records that row `intent`'s task `task_id` is polled in the MCP
    /// session `session` from now on (FIX 16028): the connector ended the
    /// one its polls went in (HTTP 404), and a new `initialize` under the
    /// row's own endpoint and credential opened this one. Only a row still
    /// Deferred on that task, its handle keeping how to poll it, changes:
    /// whether it did, so a host that renewed a session for a row settled
    /// or erased since ends it.
    ///
    /// # Errors
    /// Storage and row-codec faults.
    pub fn remote_task_session_renewed(
        &self,
        intent: &[u8; 32],
        task_id: &str,
        session: Option<String>,
    ) -> IntentLedgerResult<bool> {
        self.try_with_write_txn_grouped(|txn| -> IntentLedgerResult<bool> {
            let deferred = super::store::get_ledger_record(self, txn, intent)?
                .is_some_and(|record| record.state == IntentState::Deferred);
            if !deferred {
                return Ok(false);
            }
            super::settlement::renew_remote_task_session_in_txn(self, txn, intent, task_id, session)
        })
    }

    /// Settles row `intent` by how a poll found its task ended (FIX 11023):
    /// a completed task is the send's Done
    /// ([`Vault::settle_remote_outbound_task`]); any other end stops the send
    /// with its delivery uncertain and its reserved budget kept. Its poll row
    /// goes, in the writer that forgets its parked question and its owner
    /// Ask and stages the retirement of its task-input subject whether or
    /// not a question ever committed (FIX 16029); the Ask's waiters wake and
    /// the key retirement is carried out after that commit. A stop before
    /// that writer leaves the poll row, and the next pass's due read drops
    /// it the same way.
    ///
    /// # Errors
    /// A row that is not Deferred; storage and custody faults.
    pub fn settle_polled_remote_task(
        &self,
        intent: &[u8; 32],
        end: RemoteTaskEnd,
    ) -> IntentLedgerResult<IntentState> {
        let state = match end {
            // The served poller has no turn queue to steer: a completed
            // task's budget events fire in its settling writer, and only the
            // state goes back.
            RemoteTaskEnd::Completed => {
                self.settle_remote_outbound_task(intent, RemoteTaskObservation::Completed)?
                    .state
            }
            RemoteTaskEnd::Unconfirmed => super::store::abandon_unconfirmed_remote_task(
                self,
                *intent,
                self.now_recorded_at(),
            )?,
        };
        let withdrawn =
            self.try_with_write_txn_grouped(|txn| -> IntentLedgerResult<Option<u64>> {
                POLLS.delete(&self.store, txn, intent)?;
                self.forget_input_in_txn(txn, intent)
            })?;
        if let Some(seq) = withdrawn {
            self.signal_decision_answer(seq);
        }
        self.finish_remote_task_input_retirements();
        Ok(state)
    }
}
