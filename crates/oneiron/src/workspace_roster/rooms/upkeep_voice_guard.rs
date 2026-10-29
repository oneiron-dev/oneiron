//! What a room host's upkeep voice must still hold in the write it lands in
//! (OF-417). [`Memory::voice_prepare_in_txn`] runs in the room witness
//! writer before the room admits the turn, on that writer's own snapshot:
//! the nudge is live and authentic, the caller is the host it names and the
//! host the engine selects now, the caller reads the room and the thread,
//! stands in the thread, the thread still has open TASKs, no person's own
//! schedule holds it, the room's posture lets the host chime in, and the
//! thread's newest turn is free for the host to answer. Each refusal names
//! its bound; none counts, sizes or rates anything (rule 5). The witness
//! guard that follows is unchanged and keeps the final word.
use super::participation::{agent_standing_in_txn, turn_root_in_txn};
use super::upkeep::{room_upkeep_fold_in_txn, room_upkeep_hosts_in_txn};
use super::upkeep_voice::{RoomUpkeepNudge, RoomUpkeepVoiceReceipt};
use super::*;
use crate::claim::ScopedRead;
use crate::context_board::RoomMode;
use crate::dreamer_runner::maintenance::coach::room_upkeep_nudge_in_txn;
use crate::memory::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND};
use crate::registry::{ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

/// One refusal of `vault.rooms.upkeep.voice`, by the bound it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VoiceRefusal {
    Finding,
    Host,
    Scope,
    Standing,
    Thread,
    PersonWait,
    Posture,
    Turn,
    Identity,
}

impl VoiceRefusal {
    /// The refusal's gate reason code.
    pub(super) const fn gate(self) -> &'static str {
        match self {
            Self::Finding => "gate.rooms.upkeep.finding",
            Self::Host => "gate.rooms.upkeep.host",
            Self::Scope => "gate.rooms.upkeep.scope",
            Self::Standing => "gate.rooms.upkeep.standing",
            Self::Thread => "gate.rooms.upkeep.thread",
            Self::PersonWait => "gate.rooms.upkeep.person_wait",
            Self::Posture => "gate.rooms.upkeep.posture",
            Self::Turn => "gate.rooms.upkeep.turn",
            Self::Identity => "gate.rooms.upkeep.identity",
        }
    }

    /// The bound the refusal names.
    pub(super) const fn bound(self) -> &'static str {
        match self {
            Self::Finding => {
                "a live, active, non-stale Coach room nudge, Proposed or Approved, that the caller's lane reads"
            }
            Self::Host => {
                "the caller is the host the nudge names and the room's host as the engine selects it now"
            }
            Self::Scope => {
                "the caller reads the nudge's room and thread here, and they read base reality"
            }
            Self::Standing => {
                "the host stands in the nudge's thread: its audience, and a seat or a covering Ready receipt"
            }
            Self::Thread => {
                "the nudge's thread still stands in the room, unconverted, with open TASKs the caller reads"
            }
            Self::PersonWait => {
                "no live PERSON the caller reads holds the thread by a next notice or cutoff still ahead"
            }
            Self::Posture => "the room's posture is chime; silent and asked_only hold the voice",
            Self::Turn => {
                "the thread's newest turn, unanswered, held by no other speaker, naming no agent unless it names the host"
            }
            Self::Identity => {
                "the voice's TURN and MESSAGE ids are this nudge's own: unused, or its recorded voice"
            }
        }
    }

    /// The refusal as the facade answers it, its gate code leading the
    /// message and typed in its `reason_codes` (FIX 7398), so no caller
    /// parses it out of the message. An unknown nudge reads as not found, so
    /// a withheld one discloses nothing.
    pub(super) fn error(self) -> MemoryError {
        let code = match self {
            Self::Finding => MEMORY_CODE_NOT_FOUND,
            Self::Host | Self::Scope | Self::Standing => MEMORY_CODE_FORBIDDEN,
            Self::Thread | Self::PersonWait | Self::Posture | Self::Turn | Self::Identity => {
                MEMORY_CODE_INVALID_STATE
            }
        };
        let (gate, bound) = (self.gate(), self.bound());
        let mut error = MemoryError::new(code, format!("{gate}: {bound}"), &[]);
        error.reason_codes = vec![gate.to_owned()];
        error
    }
}

/// The caller's lanes, taken before any snapshot: Recorded for the nudge,
/// the room and its turns, Surfaceable for the room's posture rules. Beside
/// them the Coach's reach, which selects the host as the Coach did (FIX
/// 7399); `None` when it cannot be read, and the caller's reach selects alone.
pub(super) struct VoiceLanes<'m> {
    pub(super) recorded: ScopedRead<'m>,
    pub(super) surfaceable: ScopedRead<'m>,
    pub(super) upkeep: Option<ScopedRead<'m>>,
}

/// One voice as planned before its write: the nudge, the turn it answers
/// and the ids it lands under.
pub(super) struct VoicePlan {
    pub(super) nudge: RoomUpkeepNudge,
    pub(super) parent: EntityId,
    pub(super) turn: EntityId,
    pub(super) message: EntityId,
}

impl Memory<'_> {
    /// The voice's checks in the witness writer's own write, before the
    /// room admits the turn. A voice of the same nudge that landed first is
    /// put in `replay` and this write lands nothing. When the host holds no
    /// claim on the answered turn, its claim is recorded here, with the
    /// participation facts a claim records; the witness guard then admits
    /// the reply on it and takes the turn's one answer slot.
    pub(super) fn voice_prepare_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        lanes: &VoiceLanes<'_>,
        plan: &VoicePlan,
        replay: &mut Option<RoomUpkeepVoiceReceipt>,
    ) -> MemoryResult<()> {
        let vault = self.vault();
        let caller = self.actor();
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let ids = (plan.turn, plan.message);
        if let Some(receipt) = self.voice_replay_in_txn(txn, lanes, plan.nudge.finding, ids, now)? {
            *replay = Some(receipt);
            return Err(VoiceRefusal::Identity.error());
        }
        let (claimant, parent, fresh_claim) = {
            let txn: &heed::RoTxn<'_> = txn;
            let (room, thread) = (plan.nudge.room, plan.nudge.thread);
            let nudge = room_upkeep_nudge_in_txn(&lanes.recorded, txn, plan.nudge.finding)?
                .filter(|nudge| nudge.room == room && nudge.thread == thread)
                .ok_or_else(|| VoiceRefusal::Finding.error())?;
            if nudge.host != caller {
                return Err(VoiceRefusal::Host.error());
            }
            if self.room_turn().is_some_and(|turn| turn.room != room) {
                return Err(VoiceRefusal::Scope.error());
            }
            let ceiling =
                crate::context_board::thread_ceiling_in(vault, txn, room, thread, caller)?
                    .ok_or_else(|| VoiceRefusal::Scope.error())?;
            if !turns_readable(&ceiling.terms.get().worlds) {
                return Err(VoiceRefusal::Scope.error());
            }
            let (input, newest) = match room_upkeep_fold_in_txn(&lanes.recorded, txn, room, now) {
                Ok(fold) => fold.finish(vault),
                Err(Error::EntityNotFound) => return Err(VoiceRefusal::Scope.error()),
                Err(error) => return Err(error.into()),
            };
            let last = (room, input.source_refs.last().copied());
            if !room_upkeep_hosts_in_txn(vault, txn, lanes.upkeep.as_ref(), last, caller, now)? {
                return Err(VoiceRefusal::Host.error());
            }
            if !thread_audience_allows_in(vault, txn, room, thread, caller)?
                || agent_standing_in_txn(vault, txn, room, Some(thread), caller, None)?.is_none()
            {
                return Err(VoiceRefusal::Standing.error());
            }
            let row = input
                .threads
                .iter()
                .find(|row| row.handle == thread && !row.open_tasks.is_empty())
                .ok_or_else(|| VoiceRefusal::Thread.error())?;
            if row.waiting_for_person(now) {
                return Err(VoiceRefusal::PersonWait.error());
            }
            match self.room_upkeep_mode_in_txn(txn, &lanes.surfaceable, room)? {
                Some(RoomMode::Chime) => {}
                Some(RoomMode::AskedOnly | RoomMode::Silent) => {
                    return Err(VoiceRefusal::Posture.error());
                }
                None => return Err(VoiceRefusal::Scope.error()),
            }
            if newest.get(&thread) != Some(&plan.parent) {
                return Err(VoiceRefusal::Turn.error());
            }
            let parent = turn_in(vault, txn, plan.parent)?;
            let held = CLAIMS.get(&vault.store, txn, &plan.parent)?;
            let host = caller.to_hex();
            if held
                .as_ref()
                .is_some_and(|claim| claim.actor != host || claim.room_id != room.to_hex())
                || RESPONSE.get(&vault.store, txn, &plan.parent)?.is_some()
                || (!parent.addressed_agents.is_empty() && !parent.addressed_agents.contains(&host))
            {
                return Err(VoiceRefusal::Turn.error());
            }
            let claimant = Claimant::admit_in_txn(vault, txn, room, &parent, caller)?;
            claimant.admit_speech_in(vault, txn)?;
            (claimant, parent, held.is_none())
        };
        let named = parent.addressed_agents.contains(&caller.to_hex());
        let task = claimant.held_task_in_txn(vault, txn, &parent)?;
        if fresh_claim {
            let receipt = RoomClaimReceipt {
                room_id: plan.nudge.room.to_hex(),
                turn_id: plan.parent.to_hex(),
                actor: caller.to_hex(),
                receipt_ref: format!("rooms.upkeep.voice:{}", plan.nudge.finding.to_hex()),
                at: now,
            };
            CLAIMS.put(&vault.store, txn, &plan.parent, &receipt)?;
        }
        claimant.record_in_txn(vault, txn, plan.parent, named, task)?;
        Ok(())
    }

    /// The voice `finding` already has in `txn`, when its ids are taken:
    /// its recorded TURN and MESSAGE, each only when the Recorded lane reads
    /// it, or neither for a voice whose rows an erase took. `None` while
    /// both ids are free. A replay still needs the nudge, its host and the
    /// room's current host to be the caller, as a first voice does, and
    /// never writes or takes new words. An id taken by anything but this
    /// nudge's voice is refused.
    pub(super) fn voice_replay_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        lanes: &VoiceLanes<'_>,
        finding: EntityId,
        (turn, message): (EntityId, EntityId),
        now: u64,
    ) -> MemoryResult<Option<RoomUpkeepVoiceReceipt>> {
        let vault = self.vault();
        let caller = self.actor();
        let lane = &lanes.recorded;
        if !super::upkeep_voice::voiced_in(vault, txn, (turn, message))? {
            return Ok(None);
        }
        let nudge = room_upkeep_nudge_in_txn(lane, txn, finding)?
            .ok_or_else(|| VoiceRefusal::Finding.error())?;
        if nudge.host != caller {
            return Err(VoiceRefusal::Host.error());
        }
        if self.room_turn().is_some_and(|held| held.room != nudge.room) {
            return Err(VoiceRefusal::Scope.error());
        }
        let input = match room_upkeep_fold_in_txn(lane, txn, nudge.room, now) {
            Ok(fold) => fold.finish(vault).0,
            Err(Error::EntityNotFound) => return Err(VoiceRefusal::Scope.error()),
            Err(error) => return Err(error.into()),
        };
        let last = (nudge.room, input.source_refs.last().copied());
        if !room_upkeep_hosts_in_txn(vault, txn, lanes.upkeep.as_ref(), last, caller, now)? {
            return Err(VoiceRefusal::Host.error());
        }
        let receipt_ref = format!("witness:{}", turn.to_hex());
        let Some(row) = TURNS.get(&vault.store, txn, &turn)? else {
            if vault.get_entity_type_in_txn(txn, &turn)?.is_some()
                || vault.get_entity_type_in_txn(txn, &message)?.is_some()
            {
                return Err(VoiceRefusal::Identity.error());
            }
            return Ok(Some(RoomUpkeepVoiceReceipt {
                finding,
                turn: None,
                message: None,
                receipt_ref,
                replayed: true,
            }));
        };
        if row.actor != caller.to_hex()
            || row.room_id != nudge.room.to_hex()
            || !row.message_ids.contains(&message.to_hex())
            || turn_root_in_txn(vault, txn, &row)? != Some(nudge.thread)
        {
            return Err(VoiceRefusal::Identity.error());
        }
        let readable = lane.entities_readable_in_txn(txn, &[turn, message])?;
        let shown = |index: usize| readable.get(index).copied().unwrap_or(false);
        Ok(Some(RoomUpkeepVoiceReceipt {
            finding,
            turn: shown(0).then(|| crate::lens::RecordRef::from_id(ENTITY_TYPE_TURN, &turn, None)),
            message: shown(1)
                .then(|| crate::lens::RecordRef::from_id(ENTITY_TYPE_MESSAGE, &message, None)),
            receipt_ref,
            replayed: true,
        }))
    }
}
