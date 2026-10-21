//! The source selector (OF-420 A3; FIX 5502 owner rulings): what counts of
//! one of this vault's conversations, read from the canonical rows, never
//! from provenance a caller supplies.
//!
//! Every live conversation of the vault is a source, once, rooms where only
//! agents spoke included. In each, the TURNs come in the order they
//! occurred, and each TURN's MESSAGEs in their order. Who wrote a message and
//! which world it sits in are judged from the rows: the MESSAGE `author`, its
//! writer edge, the TURN's PERSON stamp and import stamp, who stands behind
//! the writer (the room stack's own rule, `join_subject_for_actor_in_txn`),
//! and the engine's world rule (`record_world_in`; a conversation row sits in
//! base reality). Which of those parts count is one hook,
//! [`training_source_counts_turn`] (C4, CALLS-4): while the vault's setting
//! is on, everything counts, people, agents and guests alike, when its one
//! writer is a live actor of this vault. A part whose writer the rows do not
//! prove (none, several, another PERSON's stamp, no live actor) never counts,
//! nor does an import, a system or tool row, an attachment or result, any
//! metadata, or a hidden row.
//!
//! When the vault lets people opt out, a person who did (`super::opted_out`,
//! read once per person here) keeps their own messages out of every
//! conversation; a conversation whose only human is them (their one-on-one
//! with agents) drops whole, agents' replies included. In a room with two or
//! more humans only their own messages drop. Agents' own work always counts.
//!
//! A selection is whole: a long conversation is offered whole, in as many
//! transport chunks as it takes (Rule 5); nothing here caps or cuts it. Its
//! revision ([`TrainingSelection::revision`]) is a digest of the exact
//! snapshot read (each selected text, id and writer, and the deletion marker
//! of every row read), so a release recomputes it and holds back an offer
//! whose source changed (D4).

use std::collections::{BTreeMap, BTreeSet};

use rmpv::Value;

use crate::Vault;
use crate::authority::AuthorityFold;
use crate::conversation::ConversationBody;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::{WitnessMessageBodyAuthor, validate_canonical_witness_message_body};
use crate::ports::{
    DeletionState, EdgeDirection, EdgeStoreRead, EntityRecord, EntityStoreRead, TombstoneStoreRead,
};
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_PERSON,
    ENTITY_TYPE_TURN,
};
use crate::workspace_roster::JoinSubject;

use super::opted_out;

/// The key context of a selection's revision digest.
const SOURCE_REVISION_CONTEXT: &str = "oneiron publisher training source revision v2";

/// Who wrote one message, as the selector proves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TrainingSpeaker {
    /// A person, member or guest: a `user` message whose one writer is that
    /// live PERSON or their own agent, in a TURN whose PERSON stamp, if any,
    /// is theirs.
    Person(EntityId),
    /// An agent: a `companion` message, or a `user` one an agent of no
    /// person wrote, whose one writer is a live actor of this vault.
    Agent,
    /// A writer the rows do not prove: none, several, another PERSON's
    /// stamp, or no live actor of this vault.
    Unproven,
    /// A system or tooling row.
    System,
}

/// One message as the C4 hook judges it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TrainingPart {
    pub(super) speaker: TrainingSpeaker,
    /// Its TURN or room carries an import stamp, or it has no writer edge:
    /// the importer did not write it, so whose words they are is unproven.
    pub(super) imported: bool,
    /// The transcript shows it.
    pub(super) visible: bool,
    /// It carries metadata: an attachment, a result, an imported message's
    /// provenance, or any other passenger.
    pub(super) carries_metadata: bool,
    /// Its person left their own messages out, while the vault lets people
    /// opt out.
    pub(super) opted_out: bool,
}

/// C4 (CALLS-4; FIX 5502 owner rulings), whose text counts while the
/// vault's setting is on: every person's and agent's, members and guests
/// alike, whose one writer is a live actor of this vault, unless its person
/// opted out. Never a part whose writer is unproven or whose shape is not
/// plain conversation (an import, a system or tool row, an attachment or
/// result, a hidden row). A private world never counts: that is the egress
/// check's, which every offer passes before and at release. A ruling
/// changes this hook.
pub(super) const fn training_source_counts_turn(part: &TrainingPart) -> bool {
    if part.imported || !part.visible || part.carries_metadata || part.opted_out {
        return false;
    }
    match part.speaker {
        TrainingSpeaker::Person(_) | TrainingSpeaker::Agent => true,
        TrainingSpeaker::Unproven | TrainingSpeaker::System => false,
    }
}

/// What counts of one conversation.
pub(super) struct TrainingSelection {
    /// The CONVERSATION.
    pub(super) source: EntityId,
    /// Every person whose words the selection carries, members and guests
    /// alike; empty when only agents' words count.
    pub(super) persons: BTreeSet<EntityId>,
    /// The worlds the room and every selected message sit in.
    pub(super) worlds: BTreeSet<EntityId>,
    /// The selected messages, in transcript order.
    pub(super) messages: Vec<SelectedMessage>,
    /// The digest of the exact snapshot read (D4).
    pub(super) revision: [u8; 32],
    /// The newest `learned_at` of any row read: how recently the room moved.
    pub(super) newest: u64,
}

/// One selected message. Its text is the stored text, unfiltered: it leaves
/// only through the in-vault filter.
pub(super) struct SelectedMessage {
    pub(super) id: EntityId,
    pub(super) speaker: TrainingSpeaker,
    pub(super) text: String,
}

impl TrainingSelection {
    /// The text to filter, as the contract's `filtered-text-utf8-v1` lays
    /// it out: each message as a line naming its speaker, its text and an
    /// empty line.
    pub(super) fn text(&self) -> String {
        let mut out = String::new();
        for message in &self.messages {
            out.push_str(match message.speaker {
                TrainingSpeaker::Person(_) => "### person\n",
                TrainingSpeaker::Agent | TrainingSpeaker::Unproven | TrainingSpeaker::System => {
                    "### agent\n"
                }
            });
            out.push_str(&message.text);
            out.push_str("\n\n");
        }
        out
    }

    /// The selected MESSAGE ids.
    pub(super) fn message_ids(&self) -> Vec<EntityId> {
        self.messages.iter().map(|message| message.id).collect()
    }
}

/// Every conversation of this vault, in id order; [`select`] judges each.
/// The whole type index is walked.
pub(super) fn vault_conversations(vault: &Vault, txn: &heed::RoTxn<'_>) -> Result<Vec<EntityId>> {
    let mut rooms = Vec::new();
    for id in vault
        .store
        .port_entity_ids_by_type(txn, ENTITY_TYPE_CONVERSATION, None)?
    {
        rooms.push(id?);
    }
    Ok(rooms)
}

/// What counts of `conversation` now, read in `txn` against `fold` (the
/// opt-outs); `None` when nothing of it counts.
pub(super) fn select(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    conversation: EntityId,
) -> Result<Option<TrainingSelection>> {
    let Some(record) = vault.store.port_entity_record(txn, &conversation)? else {
        return Ok(None);
    };
    let room_marker = vault.store.port_deletion_state(txn, &conversation)?;
    if record.entity_type != ENTITY_TYPE_CONVERSATION || hidden(room_marker) {
        return Ok(None);
    }
    let Ok(body) = ConversationBody::from_bytes(&record.body) else {
        return Ok(None);
    };
    let Some(room_world) = row_world(vault, txn, conversation, &record)? else {
        return Ok(None);
    };
    let mut read = Read {
        room_imported: body.extra.contains_key(crate::memory::IMPORTED_SOURCE_KEY),
        markers: vec![(b'c', conversation, marker_byte(room_marker))],
        parts: Vec::new(),
        newest: record.learned_at,
        writers: Writers {
            vault,
            at: vault.store.clock.now_recorded_at(),
            subjects: BTreeMap::new(),
        },
    };
    read.turns(vault, txn, conversation)?;
    // The room's humans: its PERSON members and every person who wrote in
    // it. Each one's opt-out is read once.
    let mut humans = BTreeSet::new();
    for member in &body.member_ids {
        if vault.get_entity_type_in_txn(txn, member)? == Some(ENTITY_TYPE_PERSON) {
            humans.insert(*member);
        }
    }
    for part in &read.parts {
        if let TrainingSpeaker::Person(person) = part.part.speaker {
            humans.insert(person);
        }
    }
    let left_out: BTreeSet<EntityId> = humans
        .iter()
        .copied()
        .filter(|person| opted_out(fold, *person))
        .collect();
    // Their one-on-one with agents drops whole, agents' replies included.
    if humans.len() == 1 && left_out == humans {
        return Ok(None);
    }
    let mut worlds = BTreeSet::from([room_world]);
    let mut persons = BTreeSet::new();
    let mut messages = Vec::new();
    for mut part in read.parts {
        part.part.opted_out = matches!(
            part.part.speaker,
            TrainingSpeaker::Person(person) if left_out.contains(&person)
        );
        if !training_source_counts_turn(&part.part) {
            continue;
        }
        let Some(world) = part.world else {
            continue;
        };
        worlds.insert(world);
        if let TrainingSpeaker::Person(person) = part.part.speaker {
            persons.insert(person);
        }
        messages.push(SelectedMessage {
            id: part.id,
            speaker: part.part.speaker,
            text: part.text,
        });
    }
    if messages.is_empty() {
        return Ok(None);
    }
    let revision = source_revision(conversation, &read.markers, &messages);
    Ok(Some(TrainingSelection {
        source: conversation,
        persons,
        worlds,
        messages,
        revision,
        newest: read.newest,
    }))
}

/// One MESSAGE read and classified.
struct ReadPart {
    id: EntityId,
    part: TrainingPart,
    text: String,
    world: Option<EntityId>,
}

/// Who stands behind each writer, for one room's read, each read once.
struct Writers<'a> {
    vault: &'a Vault,
    at: u64,
    subjects: BTreeMap<EntityId, Option<JoinSubject>>,
}

impl Writers<'_> {
    /// Who stands behind `writer` when it is a live actor of this vault (the
    /// room stack's rule): a live PERSON is itself; a live AGENT_DEF is its
    /// person's own agent, or an agent. `None` for any other row.
    fn subject(&mut self, txn: &heed::RoTxn<'_>, writer: EntityId) -> Result<Option<JoinSubject>> {
        if let Some(subject) = self.subjects.get(&writer) {
            return Ok(*subject);
        }
        let live = match self.vault.get_entity_type_in_txn(txn, &writer)? {
            Some(ENTITY_TYPE_PERSON) => {
                crate::consent::person_is_live_in_txn(self.vault, txn, &writer)?
            }
            Some(ENTITY_TYPE_AGENT_DEF) => {
                crate::vault::live_entity_row_in_txn(&self.vault.store, txn, &writer)?.is_live()
            }
            _ => false,
        };
        let subject = if live {
            Some(crate::workspace_roster::join_subject_for_actor_in_txn(
                self.vault, txn, writer, self.at,
            )?)
        } else {
            None
        };
        self.subjects.insert(writer, subject);
        Ok(subject)
    }

    /// Who wrote a message: a person only when its one writer stands for
    /// them and its TURN stamps no other PERSON; an agent when its one
    /// writer is a live agent, or it is a `companion` message of a live
    /// actor.
    fn speaker(
        &mut self,
        txn: &heed::RoTxn<'_>,
        author: WitnessMessageBodyAuthor,
        writers: &BTreeSet<EntityId>,
        stamp: Option<TurnStamp>,
    ) -> Result<TrainingSpeaker> {
        if author == WitnessMessageBodyAuthor::System {
            return Ok(TrainingSpeaker::System);
        }
        let mut one = writers.iter();
        let (Some(writer), None) = (one.next(), one.next()) else {
            return Ok(TrainingSpeaker::Unproven);
        };
        Ok(match (author, self.subject(txn, *writer)?) {
            (WitnessMessageBodyAuthor::User, Some(JoinSubject::Person(person))) => {
                if stamp.is_some_and(|stamp| stamp.actor.is_none_or(|actor| actor == person)) {
                    TrainingSpeaker::Person(person)
                } else {
                    TrainingSpeaker::Unproven
                }
            }
            (_, Some(_)) => TrainingSpeaker::Agent,
            (_, None) => TrainingSpeaker::Unproven,
        })
    }
}

/// One room's read: every row's deletion marker, every visible part.
struct Read<'a> {
    room_imported: bool,
    markers: Vec<(u8, EntityId, u8)>,
    parts: Vec<ReadPart>,
    newest: u64,
    writers: Writers<'a>,
}

impl Read<'_> {
    /// The room's TURNs in the order they occurred, then by id.
    fn turns(&mut self, vault: &Vault, txn: &heed::RoTxn<'_>, room: EntityId) -> Result<()> {
        let mut turns = Vec::new();
        for edge in
            vault
                .store
                .port_edges(txn, &room, EdgeDirection::In, Some(EdgeKind::ChildOf), None)?
        {
            let turn = edge?.target;
            if let Some(record) = vault.store.port_entity_record(txn, &turn)?
                && record.entity_type == ENTITY_TYPE_TURN
            {
                turns.push((record.occurred.start, turn, record));
            }
        }
        turns.sort_by_key(|(at, id, _)| (*at, *id.as_bytes()));
        for (_, turn, record) in turns {
            let marker = vault.store.port_deletion_state(txn, &turn)?;
            self.markers.push((b't', turn, marker_byte(marker)));
            self.newest = self.newest.max(record.learned_at);
            if hidden(marker) {
                continue;
            }
            let stamp = person_stamp(vault, txn, turn_stamp(&record.body))?;
            self.messages(vault, txn, turn, stamp)?;
        }
        Ok(())
    }

    /// One TURN's MESSAGEs in their order, then by id. A TURN whose body
    /// does not decode stamps nothing, so its messages read as imported.
    fn messages(
        &mut self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        turn: EntityId,
        stamp: Option<TurnStamp>,
    ) -> Result<()> {
        let mut rows = Vec::new();
        for edge in
            vault
                .store
                .port_edges(txn, &turn, EdgeDirection::In, Some(EdgeKind::PartOf), None)?
        {
            let id = edge?.target;
            if let Some(record) = vault.store.port_entity_record(txn, &id)?
                && record.entity_type == ENTITY_TYPE_MESSAGE
            {
                rows.push((id, record));
            }
        }
        let mut read = Vec::new();
        for (id, record) in rows {
            let marker = vault.store.port_deletion_state(txn, &id)?;
            self.markers.push((b'm', id, marker_byte(marker)));
            self.newest = self.newest.max(record.learned_at);
            if hidden(marker) {
                continue;
            }
            let Some(fields) = message_fields(&record.body) else {
                continue;
            };
            let writers = message_writers(vault, txn, id)?;
            let speaker = self.writers.speaker(txn, fields.author, &writers, stamp)?;
            let imported = stamp.is_none_or(|stamp| stamp.imported)
                || self.room_imported
                || (fields.author != WitnessMessageBodyAuthor::System && writers.is_empty());
            let part = TrainingPart {
                speaker,
                imported,
                visible: fields.visible,
                carries_metadata: fields.metadata,
                opted_out: false,
            };
            read.push((
                fields.order,
                ReadPart {
                    id,
                    part,
                    text: fields.content,
                    world: row_world(vault, txn, id, &record)?,
                },
            ));
        }
        read.sort_by_key(|(order, part)| (*order, *part.id.as_bytes()));
        self.parts.extend(read.into_iter().map(|(_, part)| part));
        Ok(())
    }
}

/// What a TURN body stamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TurnStamp {
    imported: bool,
    /// The PERSON the witness door stamped, when the writer was one, or an
    /// id this store does not know yet ([`person_stamp`]).
    actor: Option<EntityId>,
}

/// A TURN body's stamps; `None` when it does not decode.
fn turn_stamp(body: &[u8]) -> Option<TurnStamp> {
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut &body[..]) else {
        return None;
    };
    let mut stamp = TurnStamp {
        imported: false,
        actor: None,
    };
    for (key, value) in &entries {
        match key.as_str() {
            Some(crate::memory::IMPORTED_SOURCE_KEY) => stamp.imported = true,
            Some("actor") => stamp.actor = Some(EntityId::from_hex(value.as_str()?).ok()?),
            _ => {}
        }
    }
    Some(stamp)
}

/// A TURN's stamps as the speaker check reads them. An `actor` naming a
/// known non-PERSON, such as the agent a witness TURN stamps for its Agent
/// writer (FIX 7129), reads as no stamp, as on an unstamped TURN; a PERSON,
/// or an id this store does not know yet, is kept.
fn person_stamp(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    stamp: Option<TurnStamp>,
) -> Result<Option<TurnStamp>> {
    let Some(mut stamp) = stamp else {
        return Ok(None);
    };
    if let Some(actor) = stamp.actor
        && crate::batch::stored_entity_type(&vault.store, txn, &actor)?
            .is_some_and(|kind| kind != ENTITY_TYPE_PERSON)
    {
        stamp.actor = None;
    }
    Ok(Some(stamp))
}

/// The fields of one canonical MESSAGE body.
struct MessageFields {
    author: WitnessMessageBodyAuthor,
    content: String,
    visible: bool,
    order: u32,
    metadata: bool,
}

/// A MESSAGE body's fields; `None` for a body that is no canonical
/// envelope.
fn message_fields(body: &[u8]) -> Option<MessageFields> {
    let author = validate_canonical_witness_message_body(body).ok()?;
    let Ok(Value::Map(entries)) = rmpv::decode::read_value(&mut &body[..]) else {
        return None;
    };
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    Some(MessageFields {
        author,
        content: field("content")?.as_str()?.to_owned(),
        visible: field("is_visible")?.as_bool()?,
        order: u32::try_from(field("order")?.as_u64()?).ok()?,
        metadata: field("metadata").is_some_and(|value| !value.is_nil()),
    })
}

/// Every actor a MESSAGE's writer edges name.
fn message_writers(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    message: EntityId,
) -> Result<BTreeSet<EntityId>> {
    let mut writers = BTreeSet::new();
    for edge in vault.store.port_edges(
        txn,
        &message,
        EdgeDirection::Out,
        Some(EdgeKind::AuthoredBy),
        None,
    )? {
        writers.insert(edge?.target);
    }
    Ok(writers)
}

/// The world a stored row sits in, base reality for a row the engine's rule
/// places there; `None` when the row cannot prove its world.
fn row_world(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
    record: &EntityRecord,
) -> Result<Option<EntityId>> {
    Ok(crate::federation::record_scope::record_world_in(
        &vault.store,
        txn,
        id,
        record.entity_type,
        &record.body,
    )?
    .map(|world| world.unwrap_or_else(crate::claim::base_world_id)))
}

/// A row no transcript shows.
const fn hidden(marker: DeletionState) -> bool {
    marker.deleted || marker.archived || marker.stale
}

/// A deletion marker as one byte for the revision digest.
fn marker_byte(marker: DeletionState) -> u8 {
    u8::from(marker.deleted) | (u8::from(marker.archived) << 1) | (u8::from(marker.stale) << 2)
}

/// The digest of the exact snapshot: the room, every row's deletion marker
/// in read order, then each selected message's id, writer and text.
fn source_revision(
    room: EntityId,
    markers: &[(u8, EntityId, u8)],
    messages: &[SelectedMessage],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_derive_key(SOURCE_REVISION_CONTEXT);
    digest.update(room.as_bytes());
    for (kind, id, marker) in markers {
        digest.update(&[*kind]);
        digest.update(id.as_bytes());
        digest.update(&[*marker]);
    }
    for message in messages {
        digest.update(message.id.as_bytes());
        match message.speaker {
            TrainingSpeaker::Person(person) => {
                digest.update(&[1]);
                digest.update(person.as_bytes());
            }
            TrainingSpeaker::Agent | TrainingSpeaker::Unproven | TrainingSpeaker::System => {
                digest.update(&[2]);
            }
        }
        digest.update(&(message.text.len() as u64).to_le_bytes());
        digest.update(message.text.as_bytes());
    }
    *digest.finalize().as_bytes()
}
