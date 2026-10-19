//! The source selector (OF-420 A3): one person's words in one conversation,
//! read from the canonical rows, never from provenance a caller supplies.
//!
//! The person's conversations are the ones holding a MESSAGE their own
//! writer edge (`AuthoredBy`) names. In each, the TURNs come in the order
//! they occurred, and each TURN's MESSAGEs in their order. Whose words a
//! message is, which worlds it sits in and whether the room is the person's
//! own are judged from the rows: the MESSAGE `author`, its writer edge, the
//! TURN's PERSON stamp and import stamp, the room's kind and members, and
//! the engine's world rule (`record_world_in`; a conversation row sits in
//! base reality). Which of those parts count is one hook,
//! [`training_source_counts_turn`] (C4, CALLS-4).
//!
//! A selection is whole: a long conversation is offered whole, in as many
//! transport chunks as it takes (Rule 5); nothing here caps or cuts it. Its
//! revision ([`TrainingSelection::revision`]) is a digest of the exact
//! snapshot read (each selected text and id, and the deletion marker of
//! every row read), so a release recomputes it and holds back an offer
//! whose source changed (D4).

use std::collections::BTreeSet;

use rmpv::Value;

use crate::Vault;
use crate::conversation::{ConversationBody, ConversationKind};
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::{WitnessMessageBodyAuthor, validate_canonical_witness_message_body};
use crate::ports::{
    DeletionState, EdgeDirection, EdgeStoreRead, EntityRecord, EntityStoreRead, TombstoneStoreRead,
};
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};

/// The key context of a selection's revision digest.
const SOURCE_REVISION_CONTEXT: &str = "oneiron publisher training source revision v1";

/// Who spoke one message, as the selector proves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TrainingSpeaker {
    /// The person: a `user` message whose one writer edge names them, in a
    /// TURN whose PERSON stamp, if any, is theirs.
    Person,
    /// The companion: a `companion` message.
    Agent,
    /// A `user` message the rows do not prove is the person's: another
    /// human's, or one with no or another writer.
    OtherHuman,
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
    /// The room is provably the person's own thread: a direct or agent room
    /// that names no member but them, holds no import, and every `user`
    /// message in it is theirs.
    pub(super) own_thread: bool,
}

/// C4 (CALLS-4), whose text counts: a person's own turns, and the agent's
/// replies in a thread that is provably that person's own. Never another
/// human's turn, never a part whose ownership is unknown or unprovable
/// (an import, a system or tool row, an attachment or result, a hidden
/// row). A private world never counts: that is the egress check's, which
/// every offer passes before and at release. A ruling changes this hook.
pub(super) const fn training_source_counts_turn(part: &TrainingPart) -> bool {
    if part.imported || !part.visible || part.carries_metadata {
        return false;
    }
    match part.speaker {
        TrainingSpeaker::Person => true,
        TrainingSpeaker::Agent => part.own_thread,
        TrainingSpeaker::OtherHuman | TrainingSpeaker::System => false,
    }
}

/// One person's selected words in one conversation.
pub(super) struct TrainingSelection {
    /// The CONVERSATION.
    pub(super) source: EntityId,
    /// Whose words.
    pub(super) person: EntityId,
    /// The worlds the room and every selected message sit in.
    pub(super) worlds: BTreeSet<EntityId>,
    /// The selected messages, in transcript order.
    pub(super) messages: Vec<SelectedMessage>,
    /// The digest of the exact snapshot read (D4).
    pub(super) revision: [u8; 32],
    /// The newest `learned_at` of any row read: how recently the room moved.
    pub(super) newest: u64,
}

/// One selected message. Its text is the stored text, unfiltered: it
/// leaves only through the in-vault filter.
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
                TrainingSpeaker::Person => "### person\n",
                TrainingSpeaker::Agent | TrainingSpeaker::OtherHuman | TrainingSpeaker::System => {
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

/// The conversations `person` wrote a message in: every MESSAGE their
/// writer edge names, and the room it belongs to. The whole adjacency is
/// walked.
pub(super) fn person_conversations(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
) -> Result<BTreeSet<EntityId>> {
    let mut rooms = BTreeSet::new();
    let written = vault.store.port_edges(
        txn,
        &person,
        EdgeDirection::In,
        Some(EdgeKind::AuthoredBy),
        None,
    )?;
    for edge in written {
        let message = edge?.target;
        if vault.get_entity_type_in_txn(txn, &message)? != Some(ENTITY_TYPE_MESSAGE) {
            continue;
        }
        let belongs = vault.store.port_edges(
            txn,
            &message,
            EdgeDirection::Out,
            Some(EdgeKind::BelongsTo),
            None,
        )?;
        for edge in belongs {
            let room = edge?.target;
            if vault.get_entity_type_in_txn(txn, &room)? == Some(ENTITY_TYPE_CONVERSATION) {
                rooms.insert(room);
            }
        }
    }
    Ok(rooms)
}

/// `person`'s selected words in `conversation` now, read in `txn`; `None`
/// when no word of theirs counts.
pub(super) fn select(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    person: EntityId,
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
    let room_imported = body.extra.contains_key(crate::memory::IMPORTED_SOURCE_KEY);
    let mut read = Read {
        person,
        room_imported,
        markers: vec![(b'c', conversation, marker_byte(room_marker))],
        parts: Vec::new(),
        newest: record.learned_at,
    };
    read.turns(vault, txn, conversation)?;
    let own_thread = !room_imported
        && own_room(&body, person)
        && read
            .parts
            .iter()
            .all(|part| part.part.speaker != TrainingSpeaker::OtherHuman && !part.part.imported);
    let mut worlds = BTreeSet::from([room_world]);
    let mut messages = Vec::new();
    for mut part in read.parts {
        part.part.own_thread = own_thread;
        if !training_source_counts_turn(&part.part) {
            continue;
        }
        let Some(world) = part.world else {
            continue;
        };
        worlds.insert(world);
        messages.push(SelectedMessage {
            id: part.id,
            speaker: part.part.speaker,
            text: part.text,
        });
    }
    if !messages
        .iter()
        .any(|message| message.speaker == TrainingSpeaker::Person)
    {
        return Ok(None);
    }
    let revision = source_revision(person, conversation, &read.markers, &messages);
    Ok(Some(TrainingSelection {
        source: conversation,
        person,
        worlds,
        messages,
        revision,
        newest: read.newest,
    }))
}

/// One MESSAGE read, classified, before the room's own-thread judgment.
struct ReadPart {
    id: EntityId,
    part: TrainingPart,
    text: String,
    world: Option<EntityId>,
}

/// One room's read: every row's deletion marker, every visible part.
struct Read {
    person: EntityId,
    room_imported: bool,
    markers: Vec<(u8, EntityId, u8)>,
    parts: Vec<ReadPart>,
    newest: u64,
}

impl Read {
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
            self.messages(vault, txn, turn, turn_stamp(&record.body))?;
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
            let speaker = speaker_of(fields.author, &writers, stamp, self.person);
            let imported = stamp.is_none_or(|stamp| stamp.imported)
                || self.room_imported
                || (fields.author != WitnessMessageBodyAuthor::System && writers.is_empty());
            let world = row_world(vault, txn, id, &record)?;
            let part = TrainingPart {
                speaker,
                imported,
                visible: fields.visible,
                carries_metadata: fields.metadata,
                own_thread: false,
            };
            read.push((
                fields.order,
                ReadPart {
                    id,
                    part,
                    text: fields.content,
                    world,
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
    /// The PERSON the witness door stamped, when the writer was one.
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

/// Who spoke a message: the person only when its one writer is them and its
/// TURN stamps no other PERSON.
fn speaker_of(
    author: WitnessMessageBodyAuthor,
    writers: &BTreeSet<EntityId>,
    stamp: Option<TurnStamp>,
    person: EntityId,
) -> TrainingSpeaker {
    match author {
        WitnessMessageBodyAuthor::User => {
            let theirs = writers.len() == 1
                && writers.contains(&person)
                && stamp.is_some_and(|stamp| stamp.actor.is_none_or(|actor| actor == person));
            if theirs {
                TrainingSpeaker::Person
            } else {
                TrainingSpeaker::OtherHuman
            }
        }
        WitnessMessageBodyAuthor::Companion => TrainingSpeaker::Agent,
        WitnessMessageBodyAuthor::System => TrainingSpeaker::System,
    }
}

/// Whether the room can be the person's own thread: a direct or agent room
/// that names no member but them.
fn own_room(body: &ConversationBody, person: EntityId) -> bool {
    matches!(
        body.kind,
        ConversationKind::Direct | ConversationKind::Agent
    ) && body.member_ids.iter().all(|member| *member == person)
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

/// The digest of the exact snapshot: the person and room, every row's
/// deletion marker in read order, then each selected message's id, speaker
/// and text.
fn source_revision(
    person: EntityId,
    room: EntityId,
    markers: &[(u8, EntityId, u8)],
    messages: &[SelectedMessage],
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new_derive_key(SOURCE_REVISION_CONTEXT);
    digest.update(person.as_bytes());
    digest.update(room.as_bytes());
    for (kind, id, marker) in markers {
        digest.update(&[*kind]);
        digest.update(id.as_bytes());
        digest.update(&[*marker]);
    }
    for message in messages {
        digest.update(message.id.as_bytes());
        digest.update(&[u8::from(message.speaker == TrainingSpeaker::Person)]);
        digest.update(&(message.text.len() as u64).to_le_bytes());
        digest.update(message.text.as_bytes());
    }
    *digest.finalize().as_bytes()
}
