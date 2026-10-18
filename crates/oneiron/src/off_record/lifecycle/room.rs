//! Participants in a room (ARCH-0052 D5, the notice model, owner ruling
//! 2026-10-10).
//!
//! An off-record stretch can run in a room: a conversation whose roster is
//! everyone in it. Anyone on the roster may start a stretch there, and anyone
//! may keep their own copy of the talk. A holder of this vault's write grant,
//! person or agent, saves it into this vault (ARCH-0052 #d5-save-grant, owner
//! ruling 2026-10-16; see `save_grant`). Everyone else takes an export file;
//! the engine never writes another vault. Each save or export posts a notice
//! to the room's own timeline, naming who and what, never the content. An
//! agent may suggest a save: the suggestion is a notice everyone sees, and it
//! waits, saving nothing, until a holder confirms or declines it. A stretch
//! the owner entered alone has no room. It is the 1:1 with their own
//! companion, and it posts no notice; nor does a room that holds only the
//! owner and the vault's own agents.
//!
//! Each room names its own stretches: the registry keys one as
//! [`room_session_key`], so a name taken in one room says nothing about
//! another room, nor about the owner's own 1:1s.

use std::collections::BTreeMap;

use crate::Vault;
use crate::authority::VerifiedSlip;
use crate::batch::BatchOp;
use crate::code_run::ResultOccurrence;
use crate::conversation::MembershipWindow;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, OffRecordError, Result};
use crate::memory::MessageResultAttachment;
use crate::off_record::promote::PromoteOutcome;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE};
use crate::session_overlay::{JournalEntry, JournalRole};
use crate::side_table::{self, Raw, SideTable};

use super::registry::{KeptMessage, OffRecordSessionEntryState, session_entry_state};
use super::session::{OffRecordSession, OffRecordSessionVault};
use super::types::{
    OffRecordBackendClass, OffRecordNotice, OffRecordNoticeAct, OffRecordSaveSuggestion,
    OffRecordSessionRecord, OffRecordTalk, OffRecordTalkMessage, OffRecordTalkTurn,
};

/// The most notices a room's timeline holds, and the most save suggestions
/// that wait in it; past it the oldest drop, so a member repeating an act
/// cannot grow the room without bound.
const MAX_ROOM_NOTICES: usize = 1024;

/// The prefix of every room stretch's registry key. A stretch the owner
/// enters alone may not take a name that starts with it.
pub(super) const ROOM_KEY_PREFIX: &str = "room:";

/// The taint sidecar of one result occurrence, keyed by the occurrence under
/// its body's handle. Only presence is read here: a room keeps no view of
/// custody rotation, so any taint row is live taint. The codec stays with
/// `code_run`.
const RESULT_TAINTS: SideTable<String, Vec<u8>, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT_TAINT);

/// The secret scan's mark on one result occurrence, keyed as its taint
/// sidecar is.
const RESULT_SECRETS: SideTable<String, String, Raw> =
    SideTable::new(&side_table::CODE_RUN_RAW_OUTPUT_SECRET);

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
        Ok(self.handle(key, entry))
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
    /// and waiting suggestions from the times their membership shows them,
    /// and no list of saved turns (their copy marks which turns are saved).
    pub fn record_for(&self, actor: EntityId) -> Result<OffRecordSessionRecord> {
        let room = self.require_in_room(actor)?;
        // A saver who left the room has stopped saving, read or not.
        self.lapse_saver()?;
        let mut record = session_entry_state(&self.entry)?.record.clone();
        let windows = self.sight_in_txn(&self.vault.store.env.read_txn()?, room, actor, None)?;
        record.promoted_turns.clear();
        record
            .notices
            .retain(|notice| visible(Some(windows.as_slice()), notice.at));
        record
            .suggestions
            .retain(|suggestion| visible(Some(windows.as_slice()), suggestion.at));
        Ok(record)
    }

    /// `actor`'s membership windows in `room`, read in `txn` AFTER whatever
    /// they filter: someone removed, or whose `credential` was revoked,
    /// before this read is refused, and anything said after they left falls
    /// outside the windows it returns.
    fn sight_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        room: EntityId,
        actor: EntityId,
        credential: Option<&VerifiedSlip>,
    ) -> Result<Vec<MembershipWindow>> {
        if let Some(credential) = credential
            && !self.vault.capability_slip_is_live_in_txn(txn, credential)?
        {
            return Err(Error::OffRecord(
                OffRecordError::OffRecordPromoteUnauthenticated {
                    session_ref: self.session_ref.clone(),
                    actor_ref: actor.to_hex(),
                },
            ));
        }
        if !is_member_in_txn(self.vault, txn, room, actor)? {
            return Err(not_in_room(&self.session_ref, actor));
        }
        self.vault.windows_in_txn(txn, room, actor)
    }

    /// An agent in the room suggests a save. Everyone in the room sees the
    /// suggestion in its timeline, and it waits, one per agent, until a
    /// holder of this vault's write grant answers it with
    /// [`Self::confirm_save_by`] or [`Self::decline_save_by`]. Nothing is
    /// saved: only a holder's own save, or someone's
    /// [`Self::export_talk_by`], keeps a copy.
    pub fn suggest_save_by(&self, agent: EntityId) -> Result<()> {
        self.require_in_room(agent)?;
        let mut state = self.recording_state()?;
        let hearing = Hearing::now(self.vault, state.record.room);
        let suggestions = &mut state.record.suggestions;
        suggestions.retain(|suggestion| suggestion.by != *agent.as_bytes());
        if suggestions.len() >= MAX_ROOM_NOTICES {
            suggestions.remove(0);
        }
        // It waits even where no notice posts: the owner alone with their
        // own agent still answers it.
        suggestions.push(OffRecordSaveSuggestion {
            by: *agent.as_bytes(),
            at: hearing.at,
        });
        post_notice(
            &mut state,
            OffRecordNoticeAct::SaveSuggested,
            agent,
            hearing,
        );
        self.entry.publish_state(&state);
        Ok(())
    }

    /// A copy of the talk for `person`, who is in the room: every turn of the
    /// stretch from the times their membership shows them, saved or not.
    /// It posts an `exported` notice and writes no vault.
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordPromoteUnauthenticated`] when `credential`
    /// was revoked or expired by the time the talk is gathered,
    /// [`OffRecordError::OffRecordNotInRoom`] when `person` is not in the
    /// room by then: either way nothing is released and nobody is told.
    pub fn export_talk_by(
        &self,
        person: EntityId,
        credential: Option<&VerifiedSlip>,
    ) -> Result<OffRecordTalk> {
        let room = self.require_in_room(person)?;
        let mut state = self.recording_state()?;
        let gathered = self.gather_talk(&state)?;
        // Who hears the export is read with the sight that admits it.
        let (windows, hearing) = {
            let txn = self.vault.store.env.read_txn()?;
            let windows = self.sight_in_txn(&txn, room, person, credential)?;
            (windows, Hearing::in_txn(self.vault, &txn, Some(room)))
        };
        let talk = OffRecordTalk {
            session_ref: self.session_ref.clone(),
            room: state.record.room,
            turns: gathered.finish(Some(windows.as_slice())),
        };
        post_notice(&mut state, OffRecordNoticeAct::Exported, person, hearing);
        self.entry.publish_state(&state);
        Ok(talk)
    }

    /// Saves the whole talk so far into this vault for `holder`, who is in
    /// the room and holds this vault's write grant (ARCH-0052
    /// #d5-save-grant): a person who owns this vault or whose shared-vault
    /// membership writes its content, or one of this vault's own agents. They
    /// act on `credential`, their own slip as this vault minted it (not
    /// narrowed or handed on), able to write with no record bound. Every turn
    /// they could see that nobody saved yet lands in ONE transaction, which
    /// checks again that they hold the grant, that `credential` is live and
    /// the slip this vault's authority log minted, that they are in the room
    /// and that their membership shows each turn. The room hears a
    /// `saved_talk` notice, and every save suggestion waiting there is
    /// answered. Anyone else is refused and nothing is written: a person
    /// keeps their copy with [`Self::export_talk_by`], an agent asks with
    /// [`Self::suggest_save_by`].
    ///
    /// A handle names whom it saves for only with that holder's slip
    /// (H203); a caller holding the owner's proof uses [`Self::save_talk_as`]:
    ///
    /// ```compile_fail
    /// fn save(session: &oneiron::off_record::OffRecordSession<'_>, owner: oneiron::EntityId) {
    ///     let _ = session.save_talk_by(owner, None);
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// [`OffRecordError::OffRecordPromoteUnauthenticated`] when `credential`
    /// is not such a slip of `holder`'s, when this vault grants them no write
    /// or when `credential` was revoked or expired,
    /// [`OffRecordError::OffRecordNotInRoom`] when they are not in the room or
    /// their membership stopped showing a turn; otherwise as
    /// [`Self::promote_turn_as`].
    pub fn save_talk_by(&self, holder: EntityId, credential: &VerifiedSlip) -> Result<SavedTurns> {
        self.save_talk_for_holder(holder, credential, false)
            .map(Option::unwrap_or_default)
    }

    /// The owner's save of the whole talk so far; `owner`'s proof, and that
    /// they own this vault, are rechecked in the transaction that saves. In a
    /// room the owner must be on the roster, and only the turns their
    /// membership shows them are saved.
    pub fn save_talk_as(&self, owner: &crate::consent::AuthenticatedOwner) -> Result<SavedTurns> {
        self.save_talk_for_owner(owner, false)
            .map(Option::unwrap_or_default)
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
        for (turn, at) in snapshot
            .journal_entries()
            .iter()
            .filter_map(|entry| turn_put(entry))
        {
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
        // A result is shown as the room's marks stand now, never as it was
        // said.
        for (message, (_, _, shown)) in &mut talk.messages {
            if let Some(shown) = shown
                && let Some(result) = shown.result.take()
            {
                shown.result = Some(self.shown_talk_result(*message, result)?);
            }
        }
        Ok(talk)
    }

    /// `result` as MESSAGE `message` of this stretch shows it now: its
    /// preview withheld while a mark in the room taints the producer's
    /// occurrence of the body or the MESSAGE's own. A room keeps no view of
    /// custody rotation, so any mark is live taint, as a run in it reads one.
    fn shown_talk_result(
        &self,
        message: EntityId,
        result: MessageResultAttachment,
    ) -> Result<MessageResultAttachment> {
        let output = result.output()?;
        let mut marked = false;
        for owner in [result.source.run_id, message] {
            let key = ResultOccurrence::of(Some(owner), &output)?.mark_key(&output.handle);
            marked |= self.side_table_get(&RESULT_SECRETS, &key)?.is_some()
                || self.side_table_get(&RESULT_TAINTS, &key)?.is_some();
        }
        Ok(result.as_shown(marked))
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

/// Who hears an act in a room, and when. A stretch with no room, and a room
/// whose roster is one owner of this vault and the vault's own agents, is
/// the owner's 1:1 with their own companion: no other person is there to
/// hear it.
#[derive(Clone, Copy)]
pub(super) struct Hearing {
    heard: bool,
    at: u64,
}

impl Hearing {
    /// The hearing of an act that keeps a copy, read in the transaction that
    /// admitted it: someone who leaves once the copy is kept still had it
    /// noticed.
    pub(super) fn in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, room: Option<EntityId>) -> Self {
        let heard = room.is_some_and(|room| {
            heard_by_another_in_txn(vault, txn, room).unwrap_or_else(heard_unread)
        });
        Self {
            heard,
            at: vault.store.clock.now_recorded_at(),
        }
    }

    /// The hearing of an act that keeps nothing, on the roster as it reads
    /// now.
    pub(super) fn now(vault: &Vault, room: Option<[u8; 16]>) -> Self {
        let heard = room.is_some_and(|room| {
            let read = || -> Result<bool> {
                let txn = vault.store.env.read_txn()?;
                heard_by_another_in_txn(vault, &txn, EntityId::from_bytes(room)?)
            };
            read().unwrap_or_else(heard_unread)
        });
        Self {
            heard,
            at: vault.store.clock.now_recorded_at(),
        }
    }
}

/// Posts a notice to the room's timeline, when someone there hears it.
pub(super) fn post_notice(
    state: &mut OffRecordSessionEntryState,
    act: OffRecordNoticeAct,
    by: EntityId,
    hearing: Hearing,
) {
    if state.record.room.is_none() || !hearing.heard {
        return;
    }
    if state.record.notices.len() >= MAX_ROOM_NOTICES {
        state.record.notices.remove(0);
    }
    state.record.notices.push(OffRecordNotice {
        act,
        by: *by.as_bytes(),
        at: hearing.at,
    });
}

/// Whether, in `txn`, `room`'s roster holds anyone but one owner of this
/// vault and the vault's own agents: another person, a second owner, or
/// someone else's agent.
fn heard_by_another_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Result<bool> {
    let fold = vault.authority_fold_readonly_in_txn(txn)?;
    let mut owners = 0_usize;
    for member in vault.members_in_txn(txn, room)? {
        if crate::policy_model::is_live_vault_owner_in_txn(vault, txn, &member)? {
            owners += 1;
        } else if !crate::disclosure::is_vault_agent_in(vault, txn, &fold, &member)? {
            return Ok(true);
        }
    }
    Ok(owners > 1)
}

/// A roster that does not read counts as heard, so the notice posts.
fn heard_unread(error: Error) -> bool {
    tracing::warn!(error = %error, "a room's roster did not read; its notice posts");
    true
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
pub(super) fn turn_put(entry: &JournalEntry) -> Option<(EntityId, u64)> {
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

pub(super) fn visible(windows: Option<&[MembershipWindow]>, at: u64) -> bool {
    windows.is_none_or(|windows| windows.iter().any(|window| window.contains(at)))
}

pub(super) fn is_member_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    actor: EntityId,
) -> Result<bool> {
    // A deleted room keeps its shell and has no one in it, as an absent one
    // has no one: the liveness the room's body door refuses on, read first.
    if crate::vault::live_entity_row_in_txn(&vault.store, txn, &room)?.live_type()
        != Some(ENTITY_TYPE_CONVERSATION)
    {
        return Ok(false);
    }
    Ok(vault.members_in_txn(txn, room)?.contains(&actor))
}

pub(super) fn not_in_room(session_ref: &str, actor: EntityId) -> Error {
    Error::OffRecord(OffRecordError::OffRecordNotInRoom {
        session_ref: session_ref.to_owned(),
        actor_ref: actor.to_hex(),
    })
}

/// Decodes a MESSAGE body (the witness door's canonical encoding) and keeps
/// it only when it is part of the visible transcript. Its result is as the
/// MESSAGE says it, which a talk copy shows only as the room's marks stand
/// when it is gathered; a reserved value that is no result is none.
pub(super) fn visible_message(body: &[u8]) -> Result<Option<OffRecordTalkMessage>> {
    let malformed = || Error::InvariantViolation("an off-record MESSAGE body does not decode");
    let mut cursor = body;
    let rmpv::Value::Map(entries) =
        rmpv::decode::read_value(&mut cursor).map_err(|_| malformed())?
    else {
        return Err(malformed());
    };
    let (mut author, mut message_type, mut content, mut metadata, mut is_visible, mut order) =
        (None, None, None, None, None, None);
    for (key, value) in entries {
        match key.as_str() {
            Some("author") => author = value.as_str().map(str::to_owned),
            Some("type") => message_type = value.as_str().map(str::to_owned),
            Some("content") => content = value.as_str().map(str::to_owned),
            Some("metadata") => metadata = Some(crate::serialize::msgpack_value_to_json(&value)),
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
        result: MessageResultAttachment::from_metadata(metadata.as_ref())
            .ok()
            .flatten(),
    }))
}
