//! Participants in a room (ARCH-0052 D5, the notice model, owner ruling
//! 2026-10-10).
//!
//! An off-record stretch can run in a room: a conversation whose roster is
//! everyone in it. Anyone on the roster may start a stretch there, and anyone
//! may keep their own copy of the talk. A live owner of this vault saves it
//! into this vault, which is theirs. This vault is nobody else's, so everyone
//! else takes an export file; the engine never writes another vault. Each save
//! or export posts a notice to the room's own timeline, naming who and what,
//! never the content. An agent may suggest a save: the suggestion is a notice
//! everyone sees, and it saves nothing. A stretch the owner entered alone has
//! no room. It is the 1:1 with their own companion, and it posts no notice.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::batch::BatchOp;
use crate::conversation::MembershipWindow;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::off_record::promote::PromoteOutcome;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE};
use crate::session_overlay::{JournalEntry, JournalRole};

use super::registry::{OffRecordSessionEntryState, session_entry_state};
use super::session::{OffRecordSession, OffRecordSessionVault};
use super::types::{
    OffRecordBackendClass, OffRecordNotice, OffRecordNoticeAct, OffRecordTalk,
    OffRecordTalkMessage, OffRecordTalkTurn,
};

/// The most notices a room's timeline holds; past it the oldest drop, so a
/// member repeating an act cannot grow the room without bound.
const MAX_ROOM_NOTICES: usize = 1024;

/// Every turn saved by one act, each with what it wrote.
pub type SavedTurns = Vec<(EntityId, PromoteOutcome)>;

impl<'vault> OffRecordSessionVault<'vault> {
    /// Starts an off-record stretch in `room` for `by`, who must be on the
    /// room's roster now.
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordNotInRoom`] when `room` is no conversation
    /// or `by` is not on its roster; otherwise as [`Self::enter`].
    pub fn enter_in_room(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        room: EntityId,
        by: EntityId,
    ) -> Result<OffRecordSession<'vault>> {
        let txn = self.vault.store.env.read_txn()?;
        let member = is_member_in_txn(self.vault, &txn, room, by)?;
        drop(txn);
        if !member {
            return Err(not_in_room(session_ref, by));
        }
        let entry = self.vault.enter_off_record_session_entry(
            session_ref,
            backend,
            self.vault.config.off_record_overlay_budget_bytes,
            Some((room, by)),
        )?;
        Ok(OffRecordSession {
            vault: self.vault,
            session_ref: session_ref.to_owned(),
            entry,
        })
    }
}

impl OffRecordSession<'_> {
    /// The room this stretch runs in; `None` for the owner's 1:1.
    pub fn room(&self) -> Result<Option<EntityId>> {
        session_entry_state(&self.entry)?
            .record
            .room
            .map(EntityId::from_bytes)
            .transpose()
    }

    /// The room, when this stretch runs in one and `actor` is on its roster
    /// now. A 1:1 and a stranger get the same refusal.
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordNotInRoom`] otherwise.
    pub fn require_in_room(&self, actor: EntityId) -> Result<EntityId> {
        let room = self
            .room()?
            .ok_or_else(|| not_in_room(&self.session_ref, actor))?;
        let txn = self.vault.store.env.read_txn()?;
        if !is_member_in_txn(self.vault, &txn, room, actor)? {
            return Err(not_in_room(&self.session_ref, actor));
        }
        Ok(room)
    }

    /// Whether `actor` is on `room`'s roster in `txn`.
    pub(crate) fn is_member_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        actor: EntityId,
    ) -> Result<bool> {
        is_member_in_txn(self.vault, txn, room, actor)
    }

    /// An agent in the room suggests a save. Everyone in the room sees the
    /// suggestion in its timeline. Nothing is saved: only a person's own
    /// [`Self::save_talk_by`] or [`Self::export_talk_by`] keeps a copy.
    pub fn suggest_save_by(&self, agent: EntityId) -> Result<()> {
        self.require_in_room(agent)?;
        let mut state = self.recording_state()?;
        let at = self.vault.store.clock.now_recorded_at();
        post_notice(&mut state, OffRecordNoticeAct::SaveSuggested, agent, at);
        self.entry.publish_state(&state);
        Ok(())
    }

    /// A copy of the talk for `person`, who is in the room: every turn of the
    /// stretch from the times their membership lets them see, saved or not.
    /// It posts an `exported` notice and writes no vault.
    pub fn export_talk_by(&self, person: EntityId) -> Result<OffRecordTalk> {
        let room = self.require_in_room(person)?;
        let windows = self.vault.windows(room, person)?;
        let mut state = self.recording_state()?;
        let talk = self.talk(&state, Some(windows.as_slice()))?;
        let at = self.vault.store.clock.now_recorded_at();
        post_notice(&mut state, OffRecordNoticeAct::Exported, person, at);
        self.entry.publish_state(&state);
        Ok(talk)
    }

    /// Saves the whole talk so far into this vault for `person`, who is in the
    /// room and a live owner of this vault, so the vault is theirs. Every
    /// turn they could see that nobody saved yet lands in ONE transaction,
    /// which checks both facts again, and the room hears a `saved_talk`
    /// notice. A person this vault does not belong to is refused and nothing
    /// is written; they keep their copy with [`Self::export_talk_by`].
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordPromoteUnauthenticated`] when `person` owns
    /// no part of this vault, [`OffRecordError::OffRecordNotInRoom`] when they
    /// are not in the room; otherwise as [`Self::promote_turn`].
    pub fn save_talk_by(&self, person: EntityId) -> Result<SavedTurns> {
        let room = self.require_in_room(person)?;
        let session_ref = self.session_ref.clone();
        let check = |vault: &Vault, txn: &heed::RoTxn<'_>| {
            if !is_member_in_txn(vault, txn, room, person)? {
                return Err(not_in_room(&session_ref, person));
            }
            if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &person)? {
                return Err(Error::OffRecord(
                    OffRecordError::OffRecordPromoteUnauthenticated {
                        session_ref: session_ref.clone(),
                        actor_ref: person.to_hex(),
                    },
                ));
            }
            Ok(())
        };
        // Refused the same way whether or not there is anything to save yet.
        check(self.vault, &self.vault.store.env.read_txn()?)?;
        let windows = self.vault.windows(room, person)?;
        self.save_talk(person, Some(windows.as_slice()), check)
    }

    /// The owner's save of the whole talk so far. The owner already may save
    /// any turn one by one, so no membership window narrows it; `owner`'s
    /// proof is rechecked in the transaction that saves.
    pub fn save_talk_as(&self, owner: &crate::consent::AuthenticatedOwner) -> Result<SavedTurns> {
        self.save_talk(owner.actor(), None, |vault, txn| {
            owner.revalidate_in_txn(vault, txn)
        })
    }

    /// Flips the room on record for the owner: later turns are saved as they
    /// land, and the room hears a `saving_from_here` notice.
    pub fn flip_on_record_as(&self, owner: &crate::consent::AuthenticatedOwner) -> Result<()> {
        let was = self.mode()?;
        self.flip_on_record()?;
        // A room already on record hears nothing new, and one that closed
        // since the flip has nobody left to tell.
        if was != super::types::OffRecordMode::OnRecord
            && let Ok(mut state) = self.recording_state()
        {
            let at = self.vault.store.clock.now_recorded_at();
            post_notice(
                &mut state,
                OffRecordNoticeAct::SavingFromHere,
                owner.actor(),
                at,
            );
            self.entry.publish_state(&state);
        }
        Ok(())
    }

    fn save_talk(
        &self,
        by: EntityId,
        windows: Option<&[MembershipWindow]>,
        check: impl FnOnce(&Vault, &heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<SavedTurns> {
        let saved = {
            let mut state = self.recording_state()?;
            let promoted: BTreeSet<[u8; 16]> =
                state.record.promoted_turns.iter().copied().collect();
            let snapshot = self.entry.overlay.snapshot()?;
            let plans = snapshot
                .journal_entries()
                .iter()
                .filter_map(turn_put)
                .filter(|(turn, at)| !promoted.contains(turn.as_bytes()) && visible(windows, *at))
                .map(|(turn, _)| snapshot.plan_promotion(turn))
                .collect::<Result<Vec<_>>>()?;
            drop(snapshot);
            if plans.is_empty() {
                return Ok(Vec::new());
            }
            let saved = self.promote_plans(&mut state, plans, |wtxn| check(self.vault, wtxn))?;
            let at = self.vault.store.clock.now_recorded_at();
            post_notice(&mut state, OffRecordNoticeAct::SavedTalk, by, at);
            self.entry.publish_state(&state);
            saved
        };
        let turns: Vec<EntityId> = saved.iter().map(|(turn, _)| *turn).collect();
        self.refresh_promoted_turns(&turns);
        Ok(saved)
    }

    /// The talk as data: the turns already saved, then the turns still in the
    /// room, in the order the room took them, each with its visible messages.
    fn talk(
        &self,
        state: &OffRecordSessionEntryState,
        windows: Option<&[MembershipWindow]>,
    ) -> Result<OffRecordTalk> {
        let promoted: BTreeSet<[u8; 16]> = state.record.promoted_turns.iter().copied().collect();
        let snapshot = self.entry.overlay.snapshot()?;
        // A promoted turn whose retirement was deferred is still in the
        // journal; its saved copy is the one that counts.
        let live = snapshot
            .journal_entries()
            .iter()
            .filter(|entry| !promoted.contains(entry.scope.turn().as_bytes()));
        let entries: Vec<&JournalEntry> = state.saved_transcript.iter().chain(live).collect();

        let mut turns = Vec::new();
        let mut index = BTreeMap::new();
        for (turn, at) in entries.iter().copied().filter_map(turn_put) {
            if visible(windows, at) && !index.contains_key(&turn) {
                index.insert(turn, turns.len());
                turns.push(OffRecordTalkTurn {
                    turn: *turn.as_bytes(),
                    speaker: None,
                    occurred_at: at,
                    saved: promoted.contains(turn.as_bytes()),
                    messages: Vec::new(),
                });
            }
        }
        for entry in entries {
            let Some(&slot) = index.get(&entry.scope.turn()) else {
                continue;
            };
            match (&entry.role, &entry.op) {
                (
                    JournalRole::MessagePartOf,
                    BatchOp::Put {
                        entity_type, data, ..
                    },
                ) if *entity_type == ENTITY_TYPE_MESSAGE => {
                    if let Some(message) = visible_message(data)? {
                        turns[slot].messages.push(message);
                    }
                }
                (
                    JournalRole::AttributionEdge,
                    BatchOp::PublicEdgeWithCreatedAt {
                        kind: EdgeKind::AuthoredBy,
                        tgt,
                        ..
                    }
                    | BatchOp::EdgeWithCreatedAt {
                        kind: EdgeKind::AuthoredBy,
                        tgt,
                        ..
                    },
                ) => turns[slot].speaker = Some(*tgt.as_bytes()),
                _ => {}
            }
        }
        for turn in &mut turns {
            turn.messages.sort_by_key(|message| message.order);
        }
        turns.sort_by_key(|turn| turn.occurred_at);
        Ok(OffRecordTalk {
            session_ref: self.session_ref.clone(),
            room: state.record.room,
            turns,
        })
    }
}

/// Posts a notice to the room's timeline. A stretch with no room is the
/// owner's 1:1 with their own companion: no other person is there to hear it.
pub(super) fn post_notice(
    state: &mut OffRecordSessionEntryState,
    act: OffRecordNoticeAct,
    by: EntityId,
    at: u64,
) {
    if state.record.room.is_some() {
        if state.record.notices.len() >= MAX_ROOM_NOTICES {
            state.record.notices.remove(0);
        }
        state.record.notices.push(OffRecordNotice {
            act,
            by: *by.as_bytes(),
            at,
        });
    }
}

/// Whether a journal entry carries a turn's words or who spoke them: the
/// rows a copy of the talk is read from after promote retires them.
pub(super) fn is_transcript_entry(entry: &JournalEntry) -> bool {
    matches!(
        entry.role,
        JournalRole::TurnPut | JournalRole::MessagePartOf | JournalRole::AttributionEdge
    )
}

/// A witnessed TURN's own put: its id and when it was said.
fn turn_put(entry: &JournalEntry) -> Option<(EntityId, u64)> {
    match &entry.op {
        BatchOp::Put { id, .. }
            if entry.role == JournalRole::TurnPut && *id == entry.scope.turn() =>
        {
            Some((*id, entry.occurred.start))
        }
        _ => None,
    }
}

fn visible(windows: Option<&[MembershipWindow]>, at: u64) -> bool {
    windows.is_none_or(|windows| windows.iter().any(|window| window.contains(at)))
}

fn is_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    if vault.get_entity_type_in_txn(txn, &room)? != Some(ENTITY_TYPE_CONVERSATION) {
        return Ok(false);
    }
    Ok(vault.members_in_txn(txn, room)?.contains(&actor))
}

fn not_in_room(session_ref: &str, actor: EntityId) -> Error {
    Error::OffRecord(OffRecordError::OffRecordNotInRoom {
        session_ref: session_ref.to_owned(),
        actor_ref: actor.to_hex(),
    })
}

/// Decodes a staged MESSAGE body (the witness door's canonical encoding) and
/// keeps it only when it is part of the visible transcript.
fn visible_message(body: &[u8]) -> Result<Option<OffRecordTalkMessage>> {
    let malformed = || Error::InvariantViolation("an off-record MESSAGE body does not decode");
    let mut cursor = body;
    let rmpv::Value::Map(entries) =
        rmpv::decode::read_value(&mut cursor).map_err(|_| malformed())?
    else {
        return Err(malformed());
    };
    let (mut author, mut message_type, mut content, mut is_visible, mut order) =
        (None, None, None, None, None);
    for (key, value) in entries {
        match key.as_str() {
            Some("author") => author = value.as_str().map(str::to_owned),
            Some("type") => message_type = value.as_str().map(str::to_owned),
            Some("content") => content = value.as_str().map(str::to_owned),
            Some("is_visible") => is_visible = value.as_bool(),
            Some("order") => order = value.as_u64(),
            _ => {}
        }
    }
    if !is_visible.ok_or_else(malformed)? {
        return Ok(None);
    }
    Ok(Some(OffRecordTalkMessage {
        author: author.ok_or_else(malformed)?,
        message_type: message_type.ok_or_else(malformed)?,
        content: content.ok_or_else(malformed)?,
        order: order.ok_or_else(malformed)?,
    }))
}
