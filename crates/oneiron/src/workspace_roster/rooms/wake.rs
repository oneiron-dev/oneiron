//! The room wake producer (FIX 15647): a committed room turn wakes each
//! agent it addresses, and each agent holding an open TASK on its thread.
//!
//! The witness that mints a room turn stages one wake per such agent in its
//! own write: an attempt row of [`ROOM_WAKE_ATTEMPT_KIND`] that names the
//! room, the turn and the agent by ref and holds no word of the turn, keyed
//! once per (turn, agent). Nothing in that write runs a model or dispatches
//! an agent. The speaker never wakes itself; a pen takes part as its PERSON
//! and is no agent to wake; an agent with no live standing there now, or off
//! a private thread's audience, is staged no wake (owner ruling 2026-09-23:
//! an agent speaks only when it is addressed or holds a task there, and it
//! never joins on its own).
//!
//! After the commit, whoever runs the agent takes its wake: a settled
//! resident's inbox pass dispatches it under the resident's wake mode, and
//! the board publisher hands any other agent's to its STREAM connections
//! (`context_board::PendingRoomWake`). Each reads the wake live again first
//! ([`Vault::room_wake_turn`]): the agent still stands there, the turn still
//! stands, and nobody holds its claim yet. Each then settles the row
//! ([`Vault::settle_room_wakes`]), so no pass takes it twice.
//!
//! A wake is the frame, never the claim: the woken agent reads the room
//! with its own reads, so one admitted from now on reads no earlier history
//! (owner ruling 2026-10-20), and it takes the claim before it speaks.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::audience::{names_actor_in, thread_audience_allows_in};
use super::participation::{
    agent_standing_in_txn, participant_in_txn, thread_task_holders_in_txn, turn_root_in_txn,
};
use super::{CLAIMS, RoomTurn, TURNS};
use crate::attempt_queue::{
    AttemptId, AttemptQueue, AttemptState, ClaimAttempt, ClaimOutcome, CompleteAttempt,
    EnqueueAttempt,
};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_PERSON;
use crate::workspace_roster::JoinSubject;
use crate::{EntityId, Vault};

/// Attempt-queue kind of a staged room wake: the outbox row the witness
/// writes and the wake's consumer settles.
pub const ROOM_WAKE_ATTEMPT_KIND: &str = "rooms.wake.v1";

/// The lease owner a consumer settles a staged room wake under.
const ROOM_WAKE_LEASE_OWNER: &str = "rooms.wake";

/// One staged room wake: the room, the turn that woke the agent there, and
/// the agent. Refs only: no speaker, no words.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoomWake {
    pub room: EntityId,
    pub turn: EntityId,
    pub agent: EntityId,
}

impl RoomWake {
    /// The queue key every staging of this wake shares: one per (turn,
    /// agent).
    fn dedupe_key(&self) -> String {
        format!("rooms.wake:{}:{}", self.turn.to_hex(), self.agent.to_hex())
    }
}

/// A staged room wake as its consumer reads it: the queue row and its wake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StagedRoomWake {
    pub attempt: AttemptId,
    pub wake: RoomWake,
}

/// What a live room wake's turn tells its consumer: whether a PERSON spoke
/// it, which a resident's human-messages mode wakes on alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoomWakeTurn {
    pub speaker_is_person: bool,
}

/// Stages a wake for each agent the room turn `turn` wakes, in the witness
/// write that minted its row: each agent it addresses and each holder of an
/// open TASK of its thread `branch`, but never its speaker. An agent wakes
/// only when it takes part as an agent, stands in the room or the thread
/// now, and, on a private thread, is in `audience`, the audience that reads
/// the turn. A standing that does not read is logged and wakes no one; a
/// row that does not stage fails the write.
pub(super) fn stage_room_wakes_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    branch: Option<EntityId>,
    turn: &RoomTurn,
    audience: Option<&BTreeSet<EntityId>>,
    now: u64,
) -> Result<()> {
    let room = EntityId::from_hex(&turn.room_id)?;
    let turn_id = EntityId::from_hex(&turn.turn_id)?;
    let mut agents = BTreeSet::new();
    for named in &turn.addressed_agents {
        agents.insert(EntityId::from_hex(named)?);
    }
    agents.extend(thread_task_holders_in_txn(vault, txn, turn)?);
    if let Ok(speaker) = EntityId::from_hex(&turn.actor) {
        agents.remove(&speaker);
    }
    for agent in agents {
        match wakes_in_txn(vault, txn, room, branch, agent, audience) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(error) => {
                tracing::warn!(
                    room = %room.to_hex(),
                    turn = %turn_id.to_hex(),
                    agent = %agent.to_hex(),
                    %error,
                    "room wake: the agent's standing did not read; no wake staged"
                );
                continue;
            }
        }
        let wake = RoomWake {
            room,
            turn: turn_id,
            agent,
        };
        let payload =
            serde_json::to_vec(&wake).map_err(|_| Error::InvariantViolation("room wake encode"))?;
        crate::ports::JobQueue::port_job_enqueue(
            vault,
            &mut *txn,
            EnqueueAttempt {
                kind: ROOM_WAKE_ATTEMPT_KIND.to_owned(),
                payload,
                dedupe_key: Some(wake.dedupe_key()),
                run_id: None,
                now,
            },
        )?;
    }
    Ok(())
}

/// Whether `agent` is one a turn in `room`, or its thread `branch`, wakes:
/// it takes part as an agent, it is in the private `audience` when there is
/// one, and it stands there now.
fn wakes_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    branch: Option<EntityId>,
    agent: EntityId,
    audience: Option<&BTreeSet<EntityId>>,
) -> Result<bool> {
    let at = vault.store.clock.now_recorded_at();
    if !matches!(
        participant_in_txn(vault, txn, agent, at)?,
        Some(JoinSubject::Agent(_))
    ) {
        return Ok(false);
    }
    if let Some(audience) = audience
        && !names_actor_in(vault, txn, audience, agent)?
    {
        return Ok(false);
    }
    Ok(agent_standing_in_txn(vault, txn, room, branch, agent, None)?.is_some())
}

impl Vault {
    /// Every staged room wake that waits for its consumer, oldest first. A
    /// row whose wake does not decode is logged and left in the queue.
    pub fn staged_room_wakes(&self) -> Result<Vec<StagedRoomWake>> {
        let txn = self.store.env.read_txn()?;
        let rows =
            AttemptQueue::new(self).kind_working_rows_in_txn(&txn, ROOM_WAKE_ATTEMPT_KIND)?;
        let mut staged = Vec::new();
        for row in rows {
            if row.state != AttemptState::Queued {
                continue;
            }
            match serde_json::from_slice::<RoomWake>(&row.payload) {
                Ok(wake) => staged.push(StagedRoomWake {
                    attempt: row.id,
                    wake,
                }),
                Err(error) => tracing::warn!(
                    attempt = ?row.id,
                    %error,
                    "a staged room wake does not decode; it is left in the queue"
                ),
            }
        }
        Ok(staged)
    }

    /// The turn `wake` still wakes its agent for, read live now: `None` once
    /// the turn's row is gone or is no longer the room's, once anyone holds
    /// its claim, or once the agent no longer takes part as an agent, is off
    /// the audience that reads the turn, or no longer stands in its room or
    /// thread. The answer carries nothing of the turn but whether a PERSON
    /// spoke it.
    pub fn room_wake_turn(&self, wake: &RoomWake) -> Result<Option<RoomWakeTurn>> {
        let txn = self.store.env.read_txn()?;
        let Some(turn) = TURNS.get(&self.store, &txn, &wake.turn)? else {
            return Ok(None);
        };
        if turn.room_id != wake.room.to_hex()
            || CLAIMS.get(&self.store, &txn, &wake.turn)?.is_some()
        {
            return Ok(None);
        }
        let at = self.store.clock.now_recorded_at();
        if !matches!(
            participant_in_txn(self, &txn, wake.agent, at)?,
            Some(JoinSubject::Agent(_))
        ) {
            return Ok(None);
        }
        match thread_audience_allows_in(self, &txn, wake.room, wake.turn, wake.agent) {
            Ok(true) => {}
            Ok(false) | Err(Error::EntityNotFound) => return Ok(None),
            Err(error) => return Err(error),
        }
        let branch = turn_root_in_txn(self, &txn, &turn)?;
        if agent_standing_in_txn(self, &txn, wake.room, branch, wake.agent, None)?.is_none() {
            return Ok(None);
        }
        let speaker_is_person = match EntityId::from_hex(&turn.actor) {
            Ok(speaker) => self.get_entity_type_in_txn(&txn, &speaker)? == Some(ENTITY_TYPE_PERSON),
            Err(_) => false,
        };
        Ok(Some(RoomWakeTurn { speaker_is_person }))
    }

    /// Settles the staged room wakes `attempts` names once their consumer
    /// took them or found them spent: each still queued row is claimed and
    /// completed in one write, so no pass takes it again. A row that is gone,
    /// no room wake, or no longer queued is passed over.
    pub fn settle_room_wakes(&self, attempts: &[AttemptId], now: u64) -> Result<()> {
        if attempts.is_empty() {
            return Ok(());
        }
        self.with_write_txn(|txn| {
            let queue = AttemptQueue::new(self);
            for &id in attempts {
                let Some(row) = queue.get_in_write_txn(txn, id)? else {
                    continue;
                };
                if row.kind != ROOM_WAKE_ATTEMPT_KIND || row.state != AttemptState::Queued {
                    continue;
                }
                let claimed = crate::ports::JobQueue::port_job_claim_id(
                    self,
                    &mut *txn,
                    id,
                    ClaimAttempt {
                        lease_owner: ROOM_WAKE_LEASE_OWNER.to_owned(),
                        now,
                    },
                )?;
                let ClaimOutcome::Claimed(leased) = claimed else {
                    continue;
                };
                crate::ports::JobQueue::port_job_complete(
                    self,
                    &mut *txn,
                    CompleteAttempt {
                        id,
                        lease_owner: ROOM_WAKE_LEASE_OWNER.to_owned(),
                        attempt_count: leased.attempt_count,
                        now,
                    },
                )?;
            }
            Ok(())
        })
    }
}
