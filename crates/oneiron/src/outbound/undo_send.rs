//! The undo-send window on an agent's send (DEC-0006 #undo-send; owner
//! ruling REV-8 = B, 2026-10-09: "undo send is a great idea, yeah. like
//! email has it right"). Entry: [`hold_agent_send_for_undo_in_txn`], and the
//! owner's [`Vault::undo_send`].
//!
//! The owner's setting (`settings::undo_send`) gives each outbound channel a
//! length, off by default. While it is not zero, every schedule door's one
//! enqueue holds an agent's send: in the same write that queues its attempt
//! and its connector-send TASK, the attempt waits Scheduled until its release
//! instant, and a held row names it. The connector executor claims it at that
//! instant, as it claims a retry's backoff, so the release needs no worker of
//! its own and a restart keeps the hold. Until then the owner takes it back
//! with `vault.outbound.undo_send`: the attempt is cancelled and the TASK
//! settles with the synced reason `undo_send`, so no machine sends it. Once
//! the window closes the send is one-way in effect, like any outside effect.
//!
//! Never held: a person's or the system's own send, a legal send for
//! signature (ARCH-0082 #act-table: no delay proof), and a send whose gate
//! answer names the catastrophe floor, which stays one-way (DEC-0006
//! #undo-send). The hold adds and skips no consent: the schedule's gate ran
//! as it always runs (invariant 1; DEC-0006, reading not ruled).
//!
//! The first agent send through each channel, held or not, is recorded once:
//! the setting's read and the held list name it, so a surface shows the
//! one-line hint that a delay can be set.

use serde::{Deserialize, Serialize};

use super::connector_task::project_connector_send_task_undone_in_txn;
use std::fmt::Write as _;

use crate::attempt_queue::{
    AttemptId, AttemptInterventionEffect, AttemptInterventionKind, AttemptQueue, AttemptRecord,
    AttemptState, InterveneAttempt,
};
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::error::Result;
use crate::memory::{MEMORY_CODE_INVALID_STATE, Memory, MemoryError, MemoryResult};
use crate::settings::undo_send::{UNDO_SEND_EXCLUDED_CHANNEL, undo_send_setting_in_txn};
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// The list verb's name, as a refusal names it.
const HELD_VERB: &str = "vault.outbound.undo_send.held";

/// The undo verb's name, as a refusal names it.
const UNDO_VERB: &str = "vault.outbound.undo_send";

/// The note the owner's cancel leaves on the attempt's event history.
const UNDO_SEND_NOTE: &str = "undo send";

/// One agent send in its undo-send window. Key: id16 (the connector-send
/// TASK).
const HELD: SideTable<EntityId, UndoSendHold, Named> = SideTable::new(&side_table::UNDO_SEND_HELD);

/// The first agent send through each channel. Key: string (the channel, as
/// its capability manifest names it).
const FIRST_AGENT_SEND: SideTable<String, UndoSendFirstSendRow, Named> =
    SideTable::new(&side_table::UNDO_SEND_FIRST_AGENT_SEND);

/// A held send's row: the attempt the window holds and when it goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct UndoSendHold {
    attempt_id: AttemptId,
    release_at: u64,
    /// Whether this is the first agent send through its channel.
    first_send_hint: bool,
}

/// The first agent send through one channel, as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct UndoSendFirstSendRow {
    task_ref: EntityId,
    at: u64,
}

/// The first agent send through one channel: the send a surface shows the
/// one-line hint on, that a delay can be set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoSendFirstAgentSend {
    /// The outbound connector, as its capability manifest names it.
    pub channel: String,
    /// The send's connector-send TASK (32 hex).
    pub task_ref: EntityId,
    /// When it was scheduled, Unix seconds.
    pub at: u64,
}

/// One send in its undo-send window, as `vault.outbound.undo_send.held`
/// lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoSendHeldSend {
    /// The send's connector-send TASK (32 hex): `vault.outbound.undo_send`
    /// names it.
    pub task_ref: EntityId,
    /// The intent ref the schedule's receipt gave the agent
    /// (`intent:<attempt hex>`).
    pub intent_ref: String,
    /// The agent the send is from (32 hex).
    pub actor_ref: EntityId,
    pub channel: String,
    pub verb: String,
    /// The delivery target (address or handle), never the body.
    pub target: String,
    /// When the window closes and the send goes, Unix seconds.
    pub release_at: u64,
    /// Whether this is the first agent send through its channel: a surface
    /// shows the one-line hint that a delay can be set.
    pub first_send_hint: bool,
}

/// `vault.outbound.undo_send.held`'s answer: every send whose window is
/// open, soonest release first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoSendHeldSends {
    pub sends: Vec<UndoSendHeldSend>,
}

/// `vault.outbound.undo_send`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoSendRequest {
    /// The held send's connector-send TASK (32 hex), as
    /// `vault.outbound.undo_send.held` lists it.
    pub task_ref: EntityId,
}

/// `vault.outbound.undo_send`'s answer: the send taken back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UndoSendUndone {
    pub task_ref: EntityId,
    /// When the window would have closed, Unix seconds.
    pub release_at: u64,
    /// When the owner took it back, Unix seconds.
    pub undone_at: u64,
}

/// What the owner's undo came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndoSendOutcome {
    /// Taken back inside its window: the attempt is cancelled and the TASK
    /// settles `undo_send`.
    Undone { release_at: u64, undone_at: u64 },
    /// The window closed at `release_at`, or the executor already took the
    /// send: it is one-way now. Nothing was written.
    WindowClosed { release_at: u64 },
    /// No agent send under this TASK waits in a window. Nothing was written.
    NotHeld,
}

/// An agent send at the one schedule enqueue, as the window reads it.
pub(crate) struct UndoSendCandidate<'a> {
    /// The send's connector-send TASK.
    pub(crate) task_ref: EntityId,
    /// The channel as the draft spells it.
    pub(crate) channel: &'a str,
    /// The class of the actor the send is from.
    pub(crate) actor_class: EdgeActorClass,
    /// The schedule's gate reason codes.
    pub(crate) gate_reason_codes: &'a [String],
}

/// The intent ref a schedule's receipt gives for `attempt_id`
/// (`intent:<attempt hex>`, `memory::outbound`'s spelling).
fn intent_ref(attempt_id: AttemptId) -> String {
    let mut out = String::from("intent:");
    for byte in attempt_id.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Whether the schedule's gate answer names the catastrophe floor: such a
/// send stays one-way (DEC-0006 #undo-send).
fn names_catastrophe_floor(gate_reason_codes: &[String]) -> bool {
    let floor = crate::gate::GateReasonCode::PendingConsentCatastropheFloor.as_str();
    gate_reason_codes.iter().any(|code| code == floor)
}

/// Holds `record`, the attempt this transaction just enqueued for an agent's
/// send, for its channel's undo-send window, in the caller's write. A send no
/// window covers, a length of zero, and a row the queue does not defer come
/// back as they were. The first agent send through a channel is recorded
/// here, held or not.
///
/// # Errors
///
/// Queue and storage errors.
pub(crate) fn hold_agent_send_for_undo_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: AttemptRecord,
    send: &UndoSendCandidate<'_>,
) -> Result<AttemptRecord> {
    if send.actor_class != EdgeActorClass::Agent {
        return Ok(record);
    }
    let Some(manifest) = super::outbound_capability_manifest(send.channel) else {
        return Ok(record);
    };
    let channel = manifest.connector.as_str();
    if channel == UNDO_SEND_EXCLUDED_CHANNEL {
        return Ok(record);
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let first_send_hint = record_first_agent_send_in_txn(vault, wtxn, channel, send.task_ref, now)?;
    if names_catastrophe_floor(send.gate_reason_codes) {
        return Ok(record);
    }
    let secs = undo_send_setting_in_txn(vault, wtxn)?.secs_for(channel);
    if secs == 0 {
        return Ok(record);
    }
    prune_closed_windows_in_txn(vault, wtxn, now)?;
    let release_at = now.max(record.created_at).saturating_add(u64::from(secs));
    let record = AttemptQueue::new(vault).defer_enqueued_in_txn(wtxn, record, release_at)?;
    if record.state == AttemptState::Scheduled && record.scheduled_at == Some(release_at) {
        HELD.put(
            &vault.store,
            wtxn,
            &send.task_ref,
            &UndoSendHold {
                attempt_id: record.id,
                release_at,
                first_send_hint,
            },
        )?;
    }
    Ok(record)
}

/// Records `task_ref` as the first agent send through `channel` unless one
/// is recorded already; `true` when this send is the first.
fn record_first_agent_send_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    channel: &str,
    task_ref: EntityId,
    now: u64,
) -> Result<bool> {
    let key = channel.to_owned();
    if FIRST_AGENT_SEND.contains(&vault.store, wtxn, &key)? {
        return Ok(false);
    }
    FIRST_AGENT_SEND.put(
        &vault.store,
        wtxn,
        &key,
        &UndoSendFirstSendRow { task_ref, at: now },
    )?;
    Ok(true)
}

/// Drops the rows of windows that closed by `now`: their sends went to the
/// executor and no undo reads them again.
fn prune_closed_windows_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, now: u64) -> Result<()> {
    let closed: Vec<EntityId> = HELD
        .scan(&vault.store, wtxn)?
        .into_iter()
        .filter(|(_, hold)| hold.release_at <= now)
        .map(|(task_ref, _)| task_ref)
        .collect();
    for task_ref in closed {
        HELD.delete(&vault.store, wtxn, &task_ref)?;
    }
    Ok(())
}

/// The first agent send through each channel, in channel order, read in
/// `txn`.
///
/// # Errors
///
/// Storage errors, and a row that does not decode.
pub(crate) fn undo_send_first_agent_sends_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
) -> Result<Vec<UndoSendFirstAgentSend>> {
    Ok(FIRST_AGENT_SEND
        .scan(&vault.store, txn)?
        .into_iter()
        .map(|(channel, row)| UndoSendFirstAgentSend {
            channel,
            task_ref: row.task_ref,
            at: row.at,
        })
        .collect())
}

impl Vault {
    /// Every agent send whose undo-send window is open, soonest release
    /// first, under the owner's proof: its attempt still waits Scheduled and
    /// its window has not closed.
    ///
    /// # Errors
    ///
    /// A proof that no longer holds, and storage errors.
    pub fn undo_send_held_as_owner(&self, owner: &AuthenticatedOwner) -> Result<UndoSendHeldSends> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let now = self.now_recorded_at();
        let queue = AttemptQueue::new(self);
        let mut sends = Vec::new();
        for (task_ref, hold) in HELD.scan(&self.store, &txn)? {
            if hold.release_at <= now {
                continue;
            }
            let Some(attempt) = queue.get_in_txn(&txn, hold.attempt_id)? else {
                continue;
            };
            if attempt.state != AttemptState::Scheduled {
                continue;
            }
            let Some(task) = self.connector_send_task_in(&txn, &task_ref)? else {
                continue;
            };
            sends.push(UndoSendHeldSend {
                task_ref,
                intent_ref: intent_ref(hold.attempt_id),
                actor_ref: task.actor_ref,
                channel: task.intent.channel,
                verb: task.intent.verb,
                target: task.intent.target,
                release_at: hold.release_at,
                first_send_hint: hold.first_send_hint,
            });
        }
        sends.sort_by_key(|send| (send.release_at, send.task_ref));
        Ok(UndoSendHeldSends { sends })
    }

    /// The owner takes back the agent send `task_ref` names while its
    /// undo-send window is open: in one write the attempt is cancelled, the
    /// TASK settles failed with the synced reason `undo_send` (no machine
    /// sends it again) and the held row goes. Once the window has closed, or
    /// the executor took the send, the answer is
    /// [`UndoSendOutcome::WindowClosed`] and nothing is written. The proof is
    /// the vault owner's, rechecked in the writer.
    ///
    /// # Errors
    ///
    /// A proof that is not a live owner's, queue and storage errors.
    pub fn undo_send(
        &self,
        owner: &AuthenticatedOwner,
        task_ref: EntityId,
    ) -> Result<UndoSendOutcome> {
        let outcome = self.with_write_txn_grouped(|wtxn| {
            let actor = owner.revalidate_in_txn(self, &*wtxn)?;
            let now = crate::ports::recorded_at_in_txn(&self.store, wtxn)?;
            let Some(hold) = HELD.get(&self.store, wtxn, &task_ref)? else {
                return Ok(UndoSendOutcome::NotHeld);
            };
            let closed = UndoSendOutcome::WindowClosed {
                release_at: hold.release_at,
            };
            if now >= hold.release_at {
                return Ok(closed);
            }
            let queue = AttemptQueue::new(self);
            let Some(attempt) = queue.get_in_write_txn(wtxn, hold.attempt_id)? else {
                return Ok(UndoSendOutcome::NotHeld);
            };
            if attempt.state != AttemptState::Scheduled {
                return Ok(closed);
            }
            let cancel = queue.intervene_in_txn(
                wtxn,
                InterveneAttempt {
                    id: hold.attempt_id,
                    kind: AttemptInterventionKind::Cancel,
                    actor: actor.to_hex(),
                    note: Some(UNDO_SEND_NOTE.to_owned()),
                    now,
                },
            )?;
            if cancel.effect != AttemptInterventionEffect::Cancelled {
                return Ok(closed);
            }
            project_connector_send_task_undone_in_txn(self, wtxn, task_ref, now)?;
            HELD.delete(&self.store, wtxn, &task_ref)?;
            Ok(UndoSendOutcome::Undone {
                release_at: hold.release_at,
                undone_at: now,
            })
        })?;
        if matches!(outcome, UndoSendOutcome::Undone { .. }) {
            self.store.notify_attempt_observers();
            // A cancelled row's job notice commits in this write, outside any
            // owner scope, so this door sends the signal itself (FIX 11482).
            self.store.notify_notification_updates();
        }
        Ok(outcome)
    }
}

/// `vault.outbound.undo_send.held` under the owner's proof.
///
/// # Errors
///
/// A proof that no longer holds, and storage errors.
pub fn undo_send_held_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
) -> MemoryResult<UndoSendHeldSends> {
    Ok(vault.undo_send_held_as_owner(owner)?)
}

/// `vault.outbound.undo_send.held` on the embedded owner's handle.
///
/// # Errors
///
/// A handle that is not the vault owner's, and storage errors.
pub fn undo_send_held_embedded(memory: &Memory<'_>) -> MemoryResult<UndoSendHeldSends> {
    undo_send_held_as(memory.vault(), &memory.embedded_owner(HELD_VERB)?)
}

/// `vault.outbound.undo_send` under the owner's proof. A send whose window
/// closed is refused `INVALID_STATE`, and a TASK no window holds
/// `NOT_FOUND`; neither writes anything.
///
/// # Errors
///
/// As [`Vault::undo_send`], and the two refusals above.
pub fn undo_send_as(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: UndoSendRequest,
) -> MemoryResult<UndoSendUndone> {
    match vault.undo_send(owner, input.task_ref)? {
        UndoSendOutcome::Undone {
            release_at,
            undone_at,
        } => Ok(UndoSendUndone {
            task_ref: input.task_ref,
            release_at,
            undone_at,
        }),
        UndoSendOutcome::WindowClosed { release_at } => Err(MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            format!(
                "the undo-send window of {} closed at {release_at}: the send is one-way now",
                input.task_ref.to_hex()
            ),
            &["A send can be taken back only while its window is open."],
        )),
        UndoSendOutcome::NotHeld => Err(MemoryError::not_found(format!(
            "no agent send under {} waits in an undo-send window",
            input.task_ref.to_hex()
        ))),
    }
}

/// `vault.outbound.undo_send` on the embedded owner's handle.
///
/// # Errors
///
/// A handle that is not the vault owner's, and as [`undo_send_as`].
pub fn undo_send_embedded(
    memory: &Memory<'_>,
    input: UndoSendRequest,
) -> MemoryResult<UndoSendUndone> {
    undo_send_as(memory.vault(), &memory.embedded_owner(UNDO_VERB)?, input)
}
