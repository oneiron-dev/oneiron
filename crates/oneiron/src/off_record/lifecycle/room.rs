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
//!
//! Each room names its own stretches: the registry keys one as
//! [`room_session_key`], so a name taken in one room says nothing about
//! another room, nor about the owner's own 1:1s.

use std::collections::{BTreeMap, BTreeSet};

use crate::Vault;
use crate::authority::VerifiedSlip;
use crate::batch::BatchOp;
use crate::conversation::MembershipWindow;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::off_record::promote::PromoteOutcome;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE};
use crate::session_overlay::{JournalEntry, JournalRole, OverlaySnapshot};

use super::registry::{KeptMessage, OffRecordSessionEntryState, session_entry_state};
use super::session::{OffRecordSession, OffRecordSessionVault};
use super::types::{
    OffRecordBackendClass, OffRecordMode, OffRecordNotice, OffRecordNoticeAct,
    OffRecordSessionRecord, OffRecordTalk, OffRecordTalkMessage, OffRecordTalkTurn,
};

/// The most notices a room's timeline holds; past it the oldest drop, so a
/// member repeating an act cannot grow the room without bound.
const MAX_ROOM_NOTICES: usize = 1024;

/// The prefix of every room stretch's registry key. A stretch the owner
/// enters alone may not take a name that starts with it.
pub(super) const ROOM_KEY_PREFIX: &str = "room:";

/// Every turn saved by one act, each with what it wrote.
pub type SavedTurns = Vec<(EntityId, PromoteOutcome)>;

/// The registry key of the stretch `session_ref` in `room`. The owner's own
/// routes address a room's stretch by this key.
#[must_use]
pub fn room_session_key(room: EntityId, session_ref: &str) -> String {
    format!("{ROOM_KEY_PREFIX}{}:{session_ref}", room.to_hex())
}

impl<'vault> OffRecordSessionVault<'vault> {
    /// Starts an off-record stretch named `session_ref` in `room` for `by`,
    /// who must be on the room's roster now.
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordNotInRoom`] when `room` is no conversation
    /// or `by` is not on its roster, checked before the name is; otherwise as
    /// [`Self::enter`].
    pub fn enter_in_room(
        &self,
        session_ref: &str,
        backend: OffRecordBackendClass,
        room: EntityId,
        by: EntityId,
    ) -> Result<OffRecordSession<'vault>> {
        let key = room_session_key(room, session_ref);
        let txn = self.vault.store.env.read_txn()?;
        let member = is_member_in_txn(self.vault, &txn, room, by)?;
        drop(txn);
        if !member {
            return Err(not_in_room(&key, by));
        }
        let entry = self.vault.enter_off_record_session_entry(
            &key,
            backend,
            self.vault.config.off_record_overlay_budget_bytes,
            Some((room, by)),
        )?;
        Ok(OffRecordSession {
            vault: self.vault,
            session_ref: key,
            entry,
        })
    }

    /// Binds the stretch `session_ref` in `room` for `actor`, who must be on
    /// the room's roster now. No such stretch and a stretch in a room the
    /// actor is not in are the same refusal.
    pub fn bind_in_room(
        &self,
        session_ref: &str,
        room: EntityId,
        actor: EntityId,
    ) -> Result<OffRecordSession<'vault>> {
        let key = room_session_key(room, session_ref);
        // Membership first, so a stranger learns nothing of the room's
        // stretches, not even that one is closing.
        let txn = self.vault.store.env.read_txn()?;
        let member = is_member_in_txn(self.vault, &txn, room, actor)?;
        drop(txn);
        if !member {
            return Err(not_in_room(&key, actor));
        }
        let session = self.bind(&key).map_err(|error| match error {
            Error::OffRecord(OffRecordError::OffRecordSessionNotFound { .. }) => {
                not_in_room(&key, actor)
            }
            other => other,
        })?;
        session.require_in_room(actor)?;
        Ok(session)
    }

    /// Binds the stretch the registry keys `key` for `actor`. A room's key
    /// ([`room_session_key`]) binds as [`Self::bind_in_room`] does, so only
    /// for someone on that room's roster, checked before the name; any other
    /// key binds as [`Self::bind`].
    pub fn bind_for(&self, key: &str, actor: EntityId) -> Result<OffRecordSession<'vault>> {
        let Some(rest) = key.strip_prefix(ROOM_KEY_PREFIX) else {
            return self.bind(key);
        };
        let (room, session_ref) = rest
            .split_once(':')
            .and_then(|(room, session_ref)| Some((EntityId::from_hex(room).ok()?, session_ref)))
            .ok_or_else(|| not_in_room(key, actor))?;
        self.bind_in_room(session_ref, room, actor)
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

    /// The stretch as `actor`, who is in its room, may see it: the notices
    /// from the times their membership shows them, and no list of saved
    /// turns (their copy marks which turns are saved).
    pub fn record_for(&self, actor: EntityId) -> Result<OffRecordSessionRecord> {
        let room = self.require_in_room(actor)?;
        let mut record = session_entry_state(&self.entry)?.record.clone();
        let windows = self.sight(room, actor)?;
        record.promoted_turns.clear();
        record
            .notices
            .retain(|notice| visible(Some(windows.as_slice()), notice.at));
        Ok(record)
    }

    /// `actor`'s membership windows in `room`, read AFTER whatever they
    /// filter: someone removed before this read is refused, and anything
    /// said after they left falls outside the windows it returns.
    fn sight(&self, room: EntityId, actor: EntityId) -> Result<Vec<MembershipWindow>> {
        let txn = self.vault.store.env.read_txn()?;
        if !is_member_in_txn(self.vault, &txn, room, actor)? {
            return Err(not_in_room(&self.session_ref, actor));
        }
        self.vault.windows_in_txn(&txn, room, actor)
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
    /// stretch from the times their membership shows them, saved or not.
    /// It posts an `exported` notice and writes no vault.
    pub fn export_talk_by(&self, person: EntityId) -> Result<OffRecordTalk> {
        let room = self.require_in_room(person)?;
        let mut state = self.recording_state()?;
        let gathered = self.gather_talk(&state)?;
        let windows = self.sight(room, person)?;
        let talk = OffRecordTalk {
            session_ref: self.session_ref.clone(),
            room: state.record.room,
            turns: gathered.finish(Some(windows.as_slice())),
        };
        let at = self.vault.store.clock.now_recorded_at();
        post_notice(&mut state, OffRecordNoticeAct::Exported, person, at);
        self.entry.publish_state(&state);
        Ok(talk)
    }

    /// Saves the whole talk so far into this vault for `person`, who is in the
    /// room and a live owner of this vault, so the vault is theirs. Every
    /// turn they could see that nobody saved yet lands in ONE transaction,
    /// which checks again that they own the vault, that `credential` is live,
    /// that they are in the room and that their membership shows each turn.
    /// The room hears a `saved_talk` notice. A person this vault does not
    /// belong to is refused and nothing is written; they keep their copy with
    /// [`Self::export_talk_by`].
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordPromoteUnauthenticated`] when `person` owns
    /// no part of this vault or `credential` was revoked,
    /// [`OffRecordError::OffRecordNotInRoom`] when they are not in the room or
    /// their membership stopped showing a turn; otherwise as
    /// [`Self::promote_turn`].
    pub fn save_talk_by(
        &self,
        person: EntityId,
        credential: Option<&VerifiedSlip>,
    ) -> Result<SavedTurns> {
        let room = self.require_in_room(person)?;
        let refused = || {
            Error::OffRecord(OffRecordError::OffRecordPromoteUnauthenticated {
                session_ref: self.session_ref.clone(),
                actor_ref: person.to_hex(),
            })
        };
        let authority = |vault: &Vault, txn: &heed::RoTxn<'_>| {
            if !crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &person)? {
                return Err(refused());
            }
            if let Some(credential) = credential
                && !vault.capability_slip_is_live_in_txn(txn, credential)?
            {
                return Err(refused());
            }
            Ok(())
        };
        // Refused the same way whether or not there is anything to save yet.
        authority(self.vault, &self.vault.store.env.read_txn()?)?;
        self.save_talk(person, Some(room), authority)
    }

    /// The owner's save of the whole talk so far; `owner`'s proof, and that
    /// they own this vault, are rechecked in the transaction that saves. In a
    /// room the owner must be on the roster, and only the turns their
    /// membership shows them are saved.
    pub fn save_talk_as(&self, owner: &crate::consent::AuthenticatedOwner) -> Result<SavedTurns> {
        let room = match self.room()? {
            Some(_) => Some(self.require_in_room(owner.actor())?),
            None => None,
        };
        let authority = |vault: &Vault, txn: &heed::RoTxn<'_>| {
            owner.revalidate_as_vault_owner_in_txn(vault, txn)
        };
        // Refused the same way whether or not there is anything to save yet.
        authority(self.vault, &self.vault.store.env.read_txn()?)?;
        self.save_talk(owner.actor(), room, authority)
    }

    /// Flips the stretch on record for the owner: later turns are saved as
    /// they land, and the room hears a `saving_from_here` notice. In a room
    /// the owner must be on the roster and own this vault, since the flip
    /// saves everyone's later turns into it.
    pub fn flip_on_record_as(&self, owner: &crate::consent::AuthenticatedOwner) -> Result<()> {
        let in_room = self.room()?.is_some();
        {
            let txn = self.vault.store.env.read_txn()?;
            if in_room {
                owner.revalidate_as_vault_owner_in_txn(self.vault, &txn)?;
            } else {
                owner.revalidate_in_txn(self.vault, &txn)?;
            }
        }
        if in_room {
            self.require_in_room(owner.actor())?;
        }
        // This handle's own entry, under one lock: the flip and its notice
        // land on the stretch the owner acted on, never on one that took its
        // name since, and a closing stretch is refused before either.
        let mut state = session_entry_state(&self.entry)?;
        let was = state.record.mode;
        super::vault_api::set_entry_mode(
            &self.entry,
            &mut state,
            &self.session_ref,
            OffRecordMode::OnRecord,
        )?;
        // A room already on record hears nothing new.
        if was != OffRecordMode::OnRecord {
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
        room: Option<EntityId>,
        authority: impl FnOnce(&Vault, &heed::RoTxn<'_>) -> Result<()>,
    ) -> Result<SavedTurns> {
        let windows = room.map(|room| self.vault.windows(room, by)).transpose()?;
        let saved = {
            let mut state = self.recording_state()?;
            let promoted: BTreeSet<[u8; 16]> =
                state.record.promoted_turns.iter().copied().collect();
            let snapshot = self.entry.overlay.snapshot()?;
            // A turn is saved whole, so only a turn whose every moment the
            // saver's membership shows is theirs to save.
            let turns: Vec<(EntityId, Vec<u64>)> = snapshot
                .journal_entries()
                .iter()
                .filter_map(turn_put)
                .filter(|(turn, _)| !promoted.contains(turn.as_bytes()))
                .map(|(turn, _)| (turn, turn_times(&snapshot, turn)))
                .filter(|(_, times)| times.iter().all(|at| visible(windows.as_deref(), *at)))
                .collect();
            let plans = turns
                .iter()
                .map(|(turn, _)| snapshot.plan_promotion(*turn))
                .collect::<Result<Vec<_>>>()?;
            drop(snapshot);
            if plans.is_empty() {
                return Ok(Vec::new());
            }
            let times: Vec<u64> = turns.into_iter().flat_map(|(_, times)| times).collect();
            let saved = self.promote_plans(&mut state, plans, |wtxn| {
                authority(self.vault, wtxn)?;
                match room {
                    Some(room) => {
                        require_sight_in_txn(self.vault, wtxn, &self.session_ref, room, by, &times)
                    }
                    None => Ok(()),
                }
            })?;
            let at = self.vault.store.clock.now_recorded_at();
            post_notice(&mut state, OffRecordNoticeAct::SavedTalk, by, at);
            self.entry.publish_state(&state);
            saved
        };
        let turns: Vec<EntityId> = saved.iter().map(|(turn, _)| *turn).collect();
        self.refresh_promoted_turns(&turns);
        Ok(saved)
    }

    /// The talk so far, gathered: the messages of this stretch already in
    /// this vault (saved, or said while the room was on record) read back
    /// from the vault, and the turns and messages still in the room read from
    /// its journal. [`Talk::finish`] keeps only what a reader's membership
    /// shows.
    fn gather_talk(&self, state: &OffRecordSessionEntryState) -> Result<Talk> {
        let mut talk = Talk::default();
        for (message, kept) in &state.kept_messages {
            self.read_kept_message(&mut talk, *message, kept)?;
        }
        let snapshot = self.entry.overlay.snapshot()?;
        for (turn, at) in snapshot.journal_entries().iter().filter_map(turn_put) {
            talk.turn(turn, at, false);
        }
        for entry in snapshot.journal_entries() {
            match (&entry.role, &entry.op) {
                (
                    JournalRole::MessagePartOf,
                    BatchOp::Put {
                        id,
                        entity_type,
                        data,
                        ..
                    },
                ) if *entity_type == ENTITY_TYPE_MESSAGE => {
                    // A message can join a saved turn after the save (an
                    // agent's run keeps speaking into one turn).
                    talk.message(entry.scope.turn(), *id, entry.occurred.start, data)?;
                }
                (JournalRole::AttributionEdge, op) => {
                    if let Some(speaker) = authored_by(op) {
                        talk.speaker(entry.scope.turn(), speaker);
                    }
                }
                _ => {}
            }
        }
        drop(snapshot);
        Ok(talk)
    }

    /// One message of this stretch as the vault holds it now. Only the
    /// stretch's own messages are read, never anything added to their turn
    /// in the vault since, and a message is left out once the vault no
    /// longer holds the body that was said: deleted, or edited since.
    fn read_kept_message(
        &self,
        talk: &mut Talk,
        message: EntityId,
        kept: &KeptMessage,
    ) -> Result<()> {
        let turn = kept.turn;
        let Some(header) = self.vault.read_entity_header(&turn)? else {
            return Ok(());
        };
        if self.vault.get(&turn)?.is_none() {
            return Ok(());
        }
        talk.turn(turn, header.occurred_start, true);
        let (Some(body), Some(header)) = (
            self.vault.get(&message)?,
            self.vault.read_entity_header(&message)?,
        ) else {
            return Ok(());
        };
        if blake3::hash(&body).as_bytes() != &kept.digest {
            return Ok(());
        }
        // Filtered by when the stored row says it was said.
        talk.message(turn, message, header.occurred_start, &body)?;
        if let Some(actor) = self
            .vault
            .targets(&message, EdgeKind::AuthoredBy, None)?
            .first()
        {
            talk.speaker(turn, *actor);
        }
        Ok(())
    }
}

/// A copy of the talk being gathered: turns by id, each message once.
#[derive(Default)]
struct Talk {
    turns: BTreeMap<EntityId, OffRecordTalkTurn>,
    /// Each message with when it was said.
    messages: BTreeMap<EntityId, (EntityId, u64, Option<OffRecordTalkMessage>)>,
}

impl Talk {
    fn turn(&mut self, turn: EntityId, at: u64, saved: bool) {
        self.turns.entry(turn).or_insert(OffRecordTalkTurn {
            turn: *turn.as_bytes(),
            speaker: None,
            occurred_at: at,
            saved,
            messages: Vec::new(),
        });
    }

    fn message(&mut self, turn: EntityId, id: EntityId, at: u64, body: &[u8]) -> Result<()> {
        if self.turns.contains_key(&turn) && !self.messages.contains_key(&id) {
            let message = visible_message(body)?;
            self.messages.insert(id, (turn, at, message));
        }
        Ok(())
    }

    fn speaker(&mut self, turn: EntityId, speaker: EntityId) {
        if let Some(turn) = self.turns.get_mut(&turn) {
            turn.speaker.get_or_insert(*speaker.as_bytes());
        }
    }

    /// The turns holding a visible message the reader's membership shows at
    /// the moment it was said, in the order the room took them.
    fn finish(mut self, windows: Option<&[MembershipWindow]>) -> Vec<OffRecordTalkTurn> {
        for (turn, at, message) in self.messages.into_values() {
            if let (Some(message), Some(turn)) = (message, self.turns.get_mut(&turn))
                && visible(windows, at)
            {
                turn.messages.push(message);
            }
        }
        let mut turns: Vec<OffRecordTalkTurn> = self
            .turns
            .into_values()
            .filter(|turn| !turn.messages.is_empty())
            .collect();
        for turn in &mut turns {
            turn.messages.sort_by_key(|message| message.order);
        }
        turns.sort_by_key(|turn| turn.occurred_at);
        turns
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

/// The refusal of an unbound save or flip on a stretch in a room: there it
/// takes a proof of who acts.
pub(super) fn unbound_in_room(session_ref: &str) -> Error {
    Error::OffRecord(OffRecordError::OffRecordPromoteUnauthenticated {
        session_ref: session_ref.to_owned(),
        actor_ref: String::new(),
    })
}

/// Every moment a turn still in the room holds: when it was said, and when
/// each of its messages was.
pub(super) fn turn_times(snapshot: &OverlaySnapshot, turn: EntityId) -> Vec<u64> {
    snapshot
        .journal_entries()
        .iter()
        .filter(|entry| {
            entry.scope.turn() == turn
                && matches!(entry.op, BatchOp::Put { .. })
                && matches!(
                    entry.role,
                    JournalRole::TurnPut | JournalRole::MessagePartOf
                )
        })
        .map(|entry| entry.occurred.start)
        .collect()
}

/// Refuses unless, in `txn`, `actor` is on `room`'s roster and their
/// membership shows every one of `times`.
pub(super) fn require_sight_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    session_ref: &str,
    room: EntityId,
    actor: EntityId,
    times: &[u64],
) -> Result<()> {
    if !is_member_in_txn(vault, txn, room, actor)? {
        return Err(not_in_room(session_ref, actor));
    }
    let windows = vault.windows_in_txn(txn, room, actor)?;
    if times
        .iter()
        .any(|at| !visible(Some(windows.as_slice()), *at))
    {
        return Err(not_in_room(session_ref, actor));
    }
    Ok(())
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

/// The speaker an `AuthoredBy` edge names, in whichever edge form the
/// journal staged it.
fn authored_by(op: &BatchOp) -> Option<EntityId> {
    match op {
        BatchOp::Edge {
            kind: EdgeKind::AuthoredBy,
            tgt,
            ..
        }
        | BatchOp::PublicEdgeWithCreatedAt {
            kind: EdgeKind::AuthoredBy,
            tgt,
            ..
        }
        | BatchOp::EdgeWithCreatedAt {
            kind: EdgeKind::AuthoredBy,
            tgt,
            ..
        } => Some(*tgt),
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

/// Decodes a MESSAGE body (the witness door's canonical encoding) and keeps
/// it only when it is part of the visible transcript.
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
