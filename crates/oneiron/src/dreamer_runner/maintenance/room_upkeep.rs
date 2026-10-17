//! Room upkeep (ARCH-0067 §8, ARCH-0079, OF-417): "The engine performs every
//! room's mechanical upkeep, and a host does the speaking part." The Coach is
//! born with a read of room refs and turn times only (the Engine's OF-417
//! ruling): its [`RoomReach`] reads each room as the Dreamer reads it and
//! keeps refs and times alone ([`crate::workspace_roster::room_upkeep_input`]),
//! never a turn's words or a member's text. No grant names it, and the
//! Coach's own scoped read still reads only what a grant names. It decides
//! with no model call:
//!
//! - **Summary.** A room whose turns moved since the Coach last declared its
//!   summary is declared again on the existing scope-summary path, and the
//!   Dreamer writes the words under its own read. The declaration lands on no
//!   turn and posts nothing. It is made only when the room's whole
//!   conversation is what the Dreamer reads, so a summary never stands for
//!   turns its writer could not read. An edit inside the same turns is the
//!   summary's own re-derivation.
//! - **Nudge.** A thread with open TASKs, quiet for [`ROOM_NUDGE_IDLE_SECS`],
//!   gets one Proposed finding addressed to the room's host, citing the
//!   thread and its TASKs. A room with no host gets none. The Coach never
//!   speaks: only the host, on its own authorised turn, voices a nudge.
use std::collections::BTreeSet;

use super::coach::{COACH_ROOM_NUDGE_PREDICATE, COACH_ROOM_UPKEEP_FACET};
use super::proposals;
use crate::claim::{ScopedRead, ScopedReadActorKey};
use crate::conversation_dag::{ScopePath, ScopeSelector};
use crate::dreamer_runner::DreamerAdmittedAttempt;
use crate::scope_summary::{ScopeSummaryRequest, ScopeSummaryTarget};
use crate::side_table::{self, Raw, SideTable};
use crate::workspace_roster::{
    RoomUpkeepInput, RoomUpkeepThread, room_upkeep_host, room_upkeep_input, upkeep_rooms,
};
use crate::{EntityId, Error, Result, Vault, WriteActor, WriteEnvelope};

/// How long a thread with open TASKs stays quiet before its host is nudged.
/// Canon names no interval: one day, as long as an idle room-wide offer
/// waits (OF-530).
const ROOM_NUDGE_IDLE_SECS: u64 = 24 * 60 * 60;
const STATE_DOMAIN: &[u8] = b"oneiron:coach-room-upkeep-summary:v1";

/// What the Coach last declared each room's summary from: a hash of the room
/// and the turns it read there. Key: the room.
const DECLARED: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::COACH_ROOM_UPKEEP_DECLARED);

/// The Coach's room reach: the refs and turn times of the rooms and turns
/// the Dreamer reads, under the Dreamer's relationship gate, so the Coach
/// sees no turn the Dreamer's summary could not read. The Dreamer's read
/// stays inside; only [`room_upkeep_input`]'s refs and times come out, and
/// only a leased `coach.room_upkeep` attempt opens it.
struct RoomReach<'v>(ScopedRead<'v>);

impl<'v> RoomReach<'v> {
    fn for_attempt(vault: &'v Vault, attempt: &DreamerAdmittedAttempt) -> Result<Self> {
        vault.require_coach_attempt(attempt, COACH_ROOM_UPKEEP_FACET)?;
        let dreamer = vault.dreamer_authority()?;
        let key = ScopedReadActorKey::with_actor_class(
            dreamer.entity_ref().to_hex(),
            dreamer.actor_class().gate_actor_class(),
        )
        .ok_or_else(|| Error::InvalidConfig("invalid Dreamer read key".into()))?
        .require_relationship_grants(Some(dreamer.entity_ref()));
        Ok(Self(vault.scoped_read(key)))
    }

    /// `room`'s refs and times. A room the Dreamer does not read is a
    /// missing room.
    fn input(&self, room: EntityId) -> Result<RoomUpkeepInput> {
        room_upkeep_input(&self.0, room)
    }
}

/// One pass over every room in the Coach's reach. A room whose read or write
/// fails is left for the next night; the others still run.
pub(super) fn run(vault: &Vault, attempt: &DreamerAdmittedAttempt, now: u64) -> Result<()> {
    let reach = RoomReach::for_attempt(vault, attempt)?;
    let envelope =
        proposals::run_tray_envelope(vault, COACH_ROOM_UPKEEP_FACET, attempt.status.attempt.id)?;
    let coach = vault.coach_authority()?;
    let rooms = upkeep_rooms(vault)?;
    let mut declared = false;
    for room in &rooms {
        let input = match reach.input(*room) {
            Ok(input) => input,
            // A room outside the Coach's reach.
            Err(Error::EntityNotFound) => continue,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "room upkeep did not read a room");
                continue;
            }
        };
        match upkeep(vault, attempt, &envelope, coach, &input, now) {
            Ok(summary) => declared |= summary,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "room upkeep did not run on a room");
            }
        }
    }
    if declared {
        vault.store.notify_attempt_observers();
    }
    forget_gone(vault, &rooms)
}

/// One room's upkeep in one write: its summary declaration, when due, and a
/// nudge for each quiet thread. Returns whether it declared a summary.
fn upkeep(
    vault: &Vault,
    attempt: &DreamerAdmittedAttempt,
    envelope: &WriteEnvelope,
    coach: WriteActor,
    input: &RoomUpkeepInput,
    now: u64,
) -> Result<bool> {
    if input.source_refs.is_empty() {
        return Ok(false);
    }
    let quiet: Vec<&RoomUpkeepThread> = input
        .threads
        .iter()
        .filter(|thread| {
            !thread.open_tasks.is_empty()
                && !thread.waiting_for_person(now)
                && now.saturating_sub(thread.last_message_at) >= ROOM_NUDGE_IDLE_SECS
        })
        .collect();
    // Resolved before the write: the host's presence read opens its own
    // snapshot. Presence is the session of the newest turn in the reach.
    let host = if quiet.is_empty() {
        None
    } else {
        room_upkeep_host(vault, input.room, input.source_refs.last().copied())?
    };
    let state = source_state(input);
    vault.with_write_txn_grouped(|txn| {
        let declared = declare_in_txn(vault, txn, attempt, coach, input, &state, now)?;
        if let Some(host) = host {
            for thread in &quiet {
                nudge_in_txn(vault, txn, envelope, input.room, host, thread, now)?;
            }
        }
        Ok(declared)
    })
}

/// Declares the room's summary when the turns in the Coach's reach there
/// moved since its last declaration, and only when the room's whole
/// conversation is those turns: every one the Dreamer reads. Returns whether
/// it declared.
fn declare_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: &DreamerAdmittedAttempt,
    coach: WriteActor,
    input: &RoomUpkeepInput,
    state: &[u8; 32],
    now: u64,
) -> Result<bool> {
    if DECLARED.get(&vault.store, &*txn, &input.room)? == Some(*state) {
        return Ok(false);
    }
    let scope = ScopeSelector {
        conversation: input.room,
        session: None,
        path: ScopePath::Canonical,
        include_forks: true,
    };
    let selected: BTreeSet<EntityId> = crate::conversation_dag::resolve_in_txn(vault, txn, &scope)?
        .records
        .into_iter()
        .collect();
    if selected != input.source_refs.iter().copied().collect::<BTreeSet<_>>() {
        return Ok(false);
    }
    vault.request_scope_summary_in_txn(
        txn,
        &ScopeSummaryRequest {
            target: ScopeSummaryTarget::Scope {
                scope,
                land_on: None,
                as_record: false,
            },
            requester: coach,
        },
        Some(attempt.status.attempt.id),
        attempt.status.attempt.run_id.as_deref(),
        now,
    )?;
    DECLARED.put(&vault.store, txn, &input.room, state)?;
    Ok(true)
}

/// One quiet thread's nudge to `host`: the room, the thread, its open TASKs
/// and when it last moved, citing the thread and the TASKs. The same thread
/// unchanged under the same host is the same finding, so a later night files
/// none twice.
fn nudge_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    envelope: &WriteEnvelope,
    room: EntityId,
    host: EntityId,
    thread: &RoomUpkeepThread,
    now: u64,
) -> Result<EntityId> {
    let value = serde_json::json!({
        "room": room.to_hex(),
        "thread": thread.handle.to_hex(),
        "host": host.to_hex(),
        "last_activity": thread.last_message_at,
        "open_tasks": thread.open_tasks.iter().map(EntityId::to_hex).collect::<Vec<_>>(),
    });
    let evidence: Vec<EntityId> = std::iter::once(thread.handle)
        .chain(thread.open_tasks.iter().copied())
        .collect();
    proposals::emit_in_txn(
        vault,
        txn,
        host,
        COACH_ROOM_NUDGE_PREDICATE,
        &value,
        &evidence,
        envelope,
        now,
    )
}

/// The room and the turns in the Coach's reach there, as one hash.
fn source_state(input: &RoomUpkeepInput) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(STATE_DOMAIN);
    hash.update(input.room.as_bytes());
    for turn in &input.source_refs {
        hash.update(turn.as_bytes());
    }
    *hash.finalize().as_bytes()
}

/// Drops the declaration rows of rooms the vault no longer holds.
fn forget_gone(vault: &Vault, rooms: &[EntityId]) -> Result<()> {
    let rooms: BTreeSet<EntityId> = rooms.iter().copied().collect();
    let gone: Vec<EntityId> = {
        let txn = vault.store.env.read_txn()?;
        DECLARED
            .scan_keys(&vault.store, &txn, &[])?
            .into_iter()
            .filter(|room| !rooms.contains(room))
            .collect()
    };
    if gone.is_empty() {
        return Ok(());
    }
    vault.with_write_txn_grouped(|txn| {
        for room in &gone {
            DECLARED.delete(&vault.store, txn, room)?;
        }
        Ok(())
    })
}
