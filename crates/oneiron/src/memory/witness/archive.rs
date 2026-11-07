//! Archive restore of witnessed MESSAGE rows (FIX 7777).
//!
//! A whole-vault archive carries every MESSAGE as evidence, and an import
//! brings it back as imported evidence, never as a local witness: no actor
//! is bound, no `AuthoredBy` edge is minted, and no session, wake, stream or
//! reply receipt is written. The body is typed `import.archive` and marked
//! `metadata.import.source = "archive"`; the source's type and its
//! `AuthoredBy` bylines ride inert in `metadata.import`. The TURN and
//! CONVERSATION it joins carry `import_source = "archive"`, and a TURN's
//! `actor` byline is kept as `import_actor`. A body or container an import
//! already marked stays as it is, so a restored vault exported and
//! imported again is unchanged.
//!
//! The import door names whose words the archive holds ([`ArchiveSpeakers`],
//! FIX 15412). With [`ArchiveSpeakers::Own`] every author and speaker stays
//! as above. With [`ArchiveSpeakers::Foreign`] a `user` or `companion`
//! MESSAGE speaks as a `counterparty`, its original author kept inert as
//! `metadata.import.source_author`, and its TURN, with every conversational
//! TURN the archive carries without a MESSAGE, speaks as one too
//! (`foreign_speech`); a `system` row stays one. An import's own marked rows
//! take the same change before they are kept as they are. Every MESSAGE,
//! every TURN a MESSAGE joins, every conversational TURN without one and
//! the CONVERSATION of each also carries one local admission fact, that
//! this copy came in as a foreign archive's words: `metadata.import.speakers
//! = "foreign"` on a MESSAGE, `import_speakers = "foreign"` on a TURN or
//! CONVERSATION. Own never writes it. The readers that decide whose words a
//! row holds read it ([`admitted_foreign`]), never the source string the
//! row keeps, and a copy one choice made never matches the other's.
//!
//! [`ArchivedMessageAdmission`] is the archive put's capability, as
//! `gate::WitnessMessageAuthorization` is the witness put's: its one
//! constructor proves the bytes are a canonical envelope an import marked.

use std::collections::{BTreeSet, HashSet};

use oneiron_contracts::affect::Vad;
use rmpv::Value;

use super::codec::{IMPORTED_SOURCE_KEY, ImportStamp, import_stamp};
use super::foreign_speech::{
    ForeignTurn, TURN_KEY_ACTOR, TURN_KEY_IMPORT_ACTOR, speak_as_counterparty,
};
use crate::Vault;
use crate::batch::export::ArchiveSpeakers;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::gate::WitnessMessageBodyAuthor;
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_MESSAGE, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::store::witness_message_body::{
    IMPORT_KEY_SOURCE_IMPORT, METADATA_KEY_IMPORT, WITNESS_AUTHOR_COMPANION,
    WITNESS_AUTHOR_COUNTERPARTY, WITNESS_AUTHOR_USER,
};
use crate::temporal::TimeRange;

/// The import source an archive restore stamps on the MESSAGE rows and
/// containers it brings back.
pub(crate) const ARCHIVE_IMPORT_SOURCE: &str = "archive";

/// The type an archive-restored MESSAGE carries, beside the transcript
/// importer's `import.<source>`.
const ARCHIVE_MESSAGE_TYPE: &str = "import.archive";

/// The prefix every imported MESSAGE type carries.
const IMPORTED_MESSAGE_TYPE_PREFIX: &str = "import.";

const BODY_KEY_AUTHOR: &str = "author";
const BODY_KEY_TYPE: &str = "type";
const BODY_KEY_CONTENT: &str = "content";
const BODY_KEY_METADATA: &str = "metadata";
const BODY_KEY_IS_VISIBLE: &str = "is_visible";

const IMPORT_KEY_SOURCE: &str = "source";
/// The type the source vault gave the row.
const IMPORT_KEY_SOURCE_TYPE: &str = "source_type";
/// The author a foreign archive's row had before it spoke as a
/// counterparty (FIX 15412): provenance only, never a local author.
const IMPORT_KEY_SOURCE_AUTHOR: &str = "source_author";
/// The `AuthoredBy` targets the source vault linked the row to, as hex
/// ids: provenance only, never a local author.
const IMPORT_KEY_AUTHORED_BY: &str = "authored_by";
/// The local admission fact in a MESSAGE's `metadata.import` (FIX 15412):
/// this copy came in as a foreign archive's words.
const IMPORT_KEY_SPEAKERS: &str = "speakers";
/// The same fact in a TURN's or CONVERSATION's body, beside its
/// `import_source`.
const CONTAINER_KEY_IMPORT_SPEAKERS: &str = "import_speakers";
/// The value the admission fact carries.
const FOREIGN_SPEAKERS: &str = "foreign";

/// One archived MESSAGE body the archive put may stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArchivedMessageAdmission {
    body: Vec<u8>,
}

impl ArchivedMessageAdmission {
    /// The proven body bytes, and nothing else.
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
}

/// One archived membership link of a MESSAGE, with the value fields the
/// archive carries for it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ArchivedMessageLink {
    pub(crate) target: EntityId,
    pub(crate) weight: f32,
    pub(crate) created_at: u64,
    pub(crate) vad: Vad,
}

/// One archived MESSAGE as the import restores it: its imported body
/// ([`archived_message_body`]), its times, and its two membership links.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ArchivedMessage<'a> {
    pub(crate) id: EntityId,
    pub(crate) body: &'a [u8],
    pub(crate) occurred: TimeRange,
    pub(crate) learned_at: u64,
    pub(crate) turn: ArchivedMessageLink,
    pub(crate) conversation: ArchivedMessageLink,
}

fn malformed(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidWitnessMessageBody(reason))
}

fn container_refused(reason: &'static str) -> Error {
    Error::Record(RecordError::InvalidConversationBody(reason))
}

fn decode(bytes: &[u8]) -> Option<Vec<(Value, Value)>> {
    let mut cursor = bytes;
    match rmpv::decode::read_value(&mut cursor) {
        Ok(Value::Map(entries)) if cursor.is_empty() => Some(entries),
        _ => None,
    }
}

fn encode(entries: Vec<(Value, Value)>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| malformed("an archived MESSAGE body is not encodable"))?;
    Ok(out)
}

fn entry<'v>(entries: &'v [(Value, Value)], key: &str) -> Option<&'v Value> {
    entries
        .iter()
        .find(|(name, _)| name.as_str() == Some(key))
        .map(|(_, value)| value)
}

/// Whether a MESSAGE's envelope entries are marked imported: an
/// `import.<source>` type and a non-empty `metadata.import.source`.
fn import_marked(entries: &[(Value, Value)]) -> bool {
    let typed = entry(entries, BODY_KEY_TYPE)
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.starts_with(IMPORTED_MESSAGE_TYPE_PREFIX));
    let sourced = entry(entries, BODY_KEY_METADATA)
        .and_then(|metadata| match metadata {
            Value::Map(metadata) => entry(metadata, METADATA_KEY_IMPORT),
            _ => None,
        })
        .and_then(|import| match import {
            Value::Map(import) => entry(import, IMPORT_KEY_SOURCE),
            _ => None,
        })
        .and_then(Value::as_str)
        .is_some_and(|source| !source.is_empty());
    typed && sourced
}

/// Whether `key` in `entries` carries the foreign admission fact.
fn carries_foreign(entries: &[(Value, Value)], key: &str) -> bool {
    entry(entries, key).and_then(Value::as_str) == Some(FOREIGN_SPEAKERS)
}

/// Writes the foreign admission fact under `key` in `entries` (FIX 15412):
/// an entry already under `key` takes it, never a second entry. Whether
/// `entries` changed.
fn mark_foreign(entries: &mut Vec<(Value, Value)>, key: &str) -> bool {
    let mut found = false;
    let mut changed = false;
    for (name, value) in &mut *entries {
        if name.as_str() == Some(key) {
            found = true;
            if value.as_str() != Some(FOREIGN_SPEAKERS) {
                *value = Value::from(FOREIGN_SPEAKERS);
                changed = true;
            }
        }
    }
    if !found {
        entries.push((Value::from(key), Value::from(FOREIGN_SPEAKERS)));
        changed = true;
    }
    changed
}

/// Whether a MESSAGE's import provenance, the value of its
/// `metadata.import`, says the copy came in as a foreign archive's words
/// (FIX 15412).
pub(crate) fn import_provenance_foreign(import: &Value) -> bool {
    match import {
        Value::Map(import) => carries_foreign(import, IMPORT_KEY_SPEAKERS),
        _ => false,
    }
}

/// Whether row `body` of `entity_type` came in as a foreign archive's words
/// (FIX 15412): a MESSAGE by its `metadata.import.speakers`, a TURN or
/// CONVERSATION by its `import_speakers`. A body that does not decode, or a
/// row of another type, carries no such fact.
pub(crate) fn admitted_foreign(entity_type: u8, body: &[u8]) -> bool {
    let Some(entries) = decode(body) else {
        return false;
    };
    match entity_type {
        ENTITY_TYPE_MESSAGE => entry(&entries, BODY_KEY_METADATA)
            .and_then(|metadata| match metadata {
                Value::Map(metadata) => entry(metadata, METADATA_KEY_IMPORT),
                _ => None,
            })
            .is_some_and(import_provenance_foreign),
        ENTITY_TYPE_TURN | ENTITY_TYPE_CONVERSATION => {
            carries_foreign(&entries, CONTAINER_KEY_IMPORT_SPEAKERS)
        }
        _ => false,
    }
}

/// The body an archived MESSAGE comes back with: `source`, its archived
/// body, typed `import.archive`, with `metadata.import` naming the source
/// `archive`, the source's type and `bylines`, the targets of its archived
/// `AuthoredBy` edges. A value the source metadata kept under `import`
/// moves to `metadata.import.source_import`; its other metadata stays. A
/// body an import already marked comes back unchanged.
///
/// With [`ArchiveSpeakers::Foreign`] (FIX 15412) a `user` or `companion`
/// row speaks as a `counterparty` first, its original author kept as
/// `metadata.import.source_author`, and every row carries the foreign
/// admission fact `metadata.import.speakers`; a marked row takes both too,
/// keeping a source author it already names and never a second fact. A
/// `counterparty` or `system` row keeps its author.
///
/// # Errors
/// [`RecordError::InvalidWitnessMessageBody`] when `source` is not a
/// canonical envelope, or the marked body is not one (a metadata bound).
pub(crate) fn archived_message_body(
    source: &[u8],
    bylines: &[EntityId],
    speakers: ArchiveSpeakers,
) -> Result<Vec<u8>> {
    let author = crate::gate::validate_canonical_witness_message_body(source)?;
    let mut entries = decode(source).ok_or_else(|| malformed("an archived MESSAGE body"))?;
    let foreign = speakers == ArchiveSpeakers::Foreign;
    let source_author = match (speakers, author) {
        (ArchiveSpeakers::Foreign, WitnessMessageBodyAuthor::User) => Some(WITNESS_AUTHOR_USER),
        (ArchiveSpeakers::Foreign, WitnessMessageBodyAuthor::Companion) => {
            Some(WITNESS_AUTHOR_COMPANION)
        }
        _ => None,
    };
    if source_author.is_some() {
        for (name, value) in &mut entries {
            if name.as_str() == Some(BODY_KEY_AUTHOR) {
                *value = Value::from(WITNESS_AUTHOR_COUNTERPARTY);
            }
        }
    }
    if import_marked(&entries) {
        if !foreign {
            return Ok(source.to_vec());
        }
        if !keep_foreign_provenance(&mut entries, source_author)? && source_author.is_none() {
            return Ok(source.to_vec());
        }
        let body = encode(entries)?;
        crate::gate::validate_canonical_witness_message_body(&body)?;
        return Ok(body);
    }
    let source_type = entry(&entries, BODY_KEY_TYPE)
        .and_then(Value::as_str)
        .ok_or_else(|| malformed("an archived MESSAGE body carries no type"))?
        .to_owned();
    let mut provenance = vec![
        (
            Value::from(IMPORT_KEY_SOURCE),
            Value::from(ARCHIVE_IMPORT_SOURCE),
        ),
        (
            Value::from(IMPORT_KEY_SOURCE_TYPE),
            Value::from(source_type),
        ),
    ];
    if let Some(source_author) = source_author {
        provenance.push((
            Value::from(IMPORT_KEY_SOURCE_AUTHOR),
            Value::from(source_author),
        ));
    }
    if foreign {
        provenance.push((
            Value::from(IMPORT_KEY_SPEAKERS),
            Value::from(FOREIGN_SPEAKERS),
        ));
    }
    if !bylines.is_empty() {
        provenance.push((
            Value::from(IMPORT_KEY_AUTHORED_BY),
            Value::Array(
                bylines
                    .iter()
                    .map(|byline| Value::from(byline.to_hex()))
                    .collect(),
            ),
        ));
    }
    let mut metadata = match entries
        .iter()
        .position(|(name, _)| name.as_str() == Some(BODY_KEY_METADATA))
    {
        Some(at) => match entries.remove(at).1 {
            Value::Map(metadata) => metadata,
            _ => return Err(malformed("an archived MESSAGE's metadata is not a map")),
        },
        None => Vec::new(),
    };
    if let Some(at) = metadata
        .iter()
        .position(|(name, _)| name.as_str() == Some(METADATA_KEY_IMPORT))
    {
        let (_, earlier) = metadata.remove(at);
        provenance.push((Value::from(IMPORT_KEY_SOURCE_IMPORT), earlier));
    }
    metadata.push((Value::from(METADATA_KEY_IMPORT), Value::Map(provenance)));
    for (name, value) in &mut entries {
        if name.as_str() == Some(BODY_KEY_TYPE) {
            *value = Value::from(ARCHIVE_MESSAGE_TYPE);
        }
    }
    // The canonical envelope keeps `metadata` just before `is_visible`.
    let at = entries
        .iter()
        .position(|(name, _)| name.as_str() == Some(BODY_KEY_IS_VISIBLE))
        .ok_or_else(|| malformed("an archived MESSAGE body carries no visibility"))?;
    entries.insert(at, (Value::from(BODY_KEY_METADATA), Value::Map(metadata)));
    let body = encode(entries)?;
    crate::gate::validate_canonical_witness_message_body(&body)?;
    Ok(body)
}

/// Keeps in a marked MESSAGE's `metadata.import` the foreign admission fact
/// and `author`, the author the row had before it spoke as a counterparty,
/// unless that already names one: a row brought in twice keeps the first
/// source's author and one fact, never a second. Whether the provenance
/// changed.
fn keep_foreign_provenance(entries: &mut [(Value, Value)], author: Option<&str>) -> Result<bool> {
    let refused = || malformed("a marked MESSAGE's import provenance is not a map");
    let Some(Value::Map(metadata)) = entries
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some(BODY_KEY_METADATA))
        .map(|(_, metadata)| metadata)
    else {
        return Err(refused());
    };
    let Some(Value::Map(import)) = metadata
        .iter_mut()
        .find(|(name, _)| name.as_str() == Some(METADATA_KEY_IMPORT))
        .map(|(_, import)| import)
    else {
        return Err(refused());
    };
    let mut changed = false;
    if let Some(author) = author
        && !import
            .iter()
            .any(|(name, _)| name.as_str() == Some(IMPORT_KEY_SOURCE_AUTHOR))
    {
        import.push((Value::from(IMPORT_KEY_SOURCE_AUTHOR), Value::from(author)));
        changed = true;
    }
    Ok(mark_foreign(import, IMPORT_KEY_SPEAKERS) || changed)
}

/// The archive put's capability for `body`: a canonical envelope an import
/// marked.
fn admit_archived_message(body: &[u8]) -> Result<ArchivedMessageAdmission> {
    crate::gate::validate_canonical_witness_message_body(body)?;
    let entries = decode(body).ok_or_else(|| malformed("an archived MESSAGE body"))?;
    if !import_marked(&entries) {
        return Err(malformed(
            "an archived MESSAGE is restored only as imported evidence",
        ));
    }
    Ok(ArchivedMessageAdmission {
        body: body.to_vec(),
    })
}

/// The body an archived TURN or CONVERSATION that MESSAGE rows join comes
/// back with: `source`, stamped `import_source = "archive"`, a TURN's
/// `actor` byline kept as `import_actor`. A container an import already
/// stamped comes back unchanged.
///
/// With [`ArchiveSpeakers::Foreign`] (FIX 15412) a TURN speaks as a
/// counterparty first, as its MESSAGE rows do ([`speak_as_counterparty`]
/// with the host's `assistant_display_names`), a stamped one too, and the
/// TURN or CONVERSATION carries the foreign admission fact
/// `import_speakers`, once.
///
/// # Errors
/// [`RecordError::InvalidConversationBody`] when `source` is not a map, or
/// its import stamp is malformed.
pub(crate) fn archived_container_body(
    entity_type: u8,
    source: &[u8],
    speakers: ArchiveSpeakers,
    assistant_display_names: &[String],
) -> Result<Vec<u8>> {
    let foreign = speakers == ArchiveSpeakers::Foreign;
    let stamped = match import_stamp(source) {
        ImportStamp::Imported(_) if !foreign => return Ok(source.to_vec()),
        ImportStamp::Imported(_) => true,
        ImportStamp::Malformed => {
            return Err(container_refused(
                "an import source must be one non-empty string",
            ));
        }
        ImportStamp::Live => false,
    };
    let mut entries = decode(source)
        .ok_or_else(|| container_refused("an archived MESSAGE container is not a map"))?;
    let relabelled = foreign
        && entity_type == ENTITY_TYPE_TURN
        && speak_as_counterparty(&mut entries, assistant_display_names) == ForeignTurn::Relabelled;
    if !stamped {
        if entity_type == ENTITY_TYPE_TURN {
            for (name, _) in &mut entries {
                if name.as_str() == Some(TURN_KEY_ACTOR) {
                    *name = Value::from(TURN_KEY_IMPORT_ACTOR);
                }
            }
        }
        entries.push((
            Value::from(IMPORTED_SOURCE_KEY),
            Value::from(ARCHIVE_IMPORT_SOURCE),
        ));
    }
    let marked = foreign && mark_foreign(&mut entries, CONTAINER_KEY_IMPORT_SPEAKERS);
    if stamped && !relabelled && !marked {
        return Ok(source.to_vec());
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| container_refused("an archived MESSAGE container is not encodable"))?;
    Ok(out)
}

/// Whether an archived TURN no MESSAGE row joins speaks (FIX 15412): its
/// body is a map with a speaker [`speak_as_counterparty`] reads as a
/// person, an assistant or a counterparty, with the host's
/// `assistant_display_names`. A system notice, a tool row, a task artifact
/// with no speaker or a body that is not a map does not.
pub(crate) fn archived_turn_speaks(source: &[u8], assistant_display_names: &[String]) -> bool {
    decode(source).is_some_and(|mut entries| {
        speak_as_counterparty(&mut entries, assistant_display_names) != ForeignTurn::NotSpeech
    })
}

/// The body an archived TURN no MESSAGE row joins comes back with under
/// [`ArchiveSpeakers::Foreign`] (FIX 15412): a conversational TURN, its
/// words inline, speaks as a counterparty ([`speak_as_counterparty`] with
/// the host's `assistant_display_names`), is stamped
/// `import_source = "archive"` unless an import already stamped it, and
/// carries the foreign admission fact `import_speakers`, once. A TURN that
/// does not speak ([`archived_turn_speaks`]) comes back as it is. Under
/// [`ArchiveSpeakers::Own`] the archive brings every such TURN back as it is.
///
/// # Errors
/// [`RecordError::InvalidConversationBody`] when its import stamp is
/// malformed.
pub(crate) fn archived_inline_turn_body(
    source: &[u8],
    assistant_display_names: &[String],
) -> Result<Vec<u8>> {
    let stamp = import_stamp(source);
    if stamp == ImportStamp::Malformed {
        return Err(container_refused(
            "an import source must be one non-empty string",
        ));
    }
    let Some(mut entries) = decode(source) else {
        return Ok(source.to_vec());
    };
    let relabelled = match speak_as_counterparty(&mut entries, assistant_display_names) {
        ForeignTurn::NotSpeech => return Ok(source.to_vec()),
        ForeignTurn::Unchanged => false,
        ForeignTurn::Relabelled => true,
    };
    let live = stamp == ImportStamp::Live;
    if live {
        entries.push((
            Value::from(IMPORTED_SOURCE_KEY),
            Value::from(ARCHIVE_IMPORT_SOURCE),
        ));
    }
    let marked = mark_foreign(&mut entries, CONTAINER_KEY_IMPORT_SPEAKERS);
    if !live && !relabelled && !marked {
        return Ok(source.to_vec());
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| container_refused("an archived TURN is not encodable"))?;
    Ok(out)
}

/// The body under [`ArchiveSpeakers::Foreign`] (FIX 15412) of an archived
/// CONVERSATION no MESSAGE row joins and a TURN that speaks
/// ([`archived_turn_speaks`]) is a child of: `source`, carrying the
/// foreign admission fact `import_speakers`, once, its import stamp or its
/// absence kept. A body that is not a map comes back as it is.
///
/// # Errors
/// [`RecordError::InvalidConversationBody`] when its import stamp is
/// malformed.
pub(crate) fn archived_inline_conversation_body(source: &[u8]) -> Result<Vec<u8>> {
    if import_stamp(source) == ImportStamp::Malformed {
        return Err(container_refused(
            "an import source must be one non-empty string",
        ));
    }
    let Some(mut entries) = decode(source) else {
        return Ok(source.to_vec());
    };
    if !mark_foreign(&mut entries, CONTAINER_KEY_IMPORT_SPEAKERS) {
        return Ok(source.to_vec());
    }
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| container_refused("an archived CONVERSATION is not encodable"))?;
    Ok(out)
}

/// The stored body of container `id`, a row of `entity_type` an import
/// stamped.
fn imported_container(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
) -> Result<Vec<u8>> {
    let record = store
        .port_entity_record(txn, id)?
        .filter(|record| record.entity_type == entity_type)
        .ok_or_else(|| malformed("an archived MESSAGE's container is not here"))?;
    if import_stamp(&record.body) == ImportStamp::Live {
        return Err(malformed(
            "an archived MESSAGE never joins a live turn or conversation",
        ));
    }
    Ok(record.body)
}

impl Vault {
    /// Restores one archived MESSAGE in the import's writer (FIX 7777): the
    /// row through the archive put, its `PartOf` and `BelongsTo` links with
    /// their archived value fields, and its content's text posting. Its
    /// TURN and CONVERSATION are already here, both stamped imported; the
    /// TURN's speaker admits the row's author, and no other MESSAGE of the
    /// TURN holds its order. Nothing binds an actor or mints authorship.
    ///
    /// # Errors
    /// The admission's refusal; [`RecordError::InvalidWitnessMessageBody`]
    /// for a container that is absent, live, of another type, of another
    /// speaker, or whose order is taken; storage faults.
    pub(crate) fn restore_archived_message_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        message: &ArchivedMessage<'_>,
    ) -> Result<()> {
        let admission = admit_archived_message(message.body)?;
        let turn = imported_container(&self.store, wtxn, &message.turn.target, ENTITY_TYPE_TURN)?;
        imported_container(
            &self.store,
            wtxn,
            &message.conversation.target,
            ENTITY_TYPE_CONVERSATION,
        )?;
        if !super::turn_admits_message_bodies(&turn, &[admission.body()])? {
            return Err(malformed(
                "an archived MESSAGE's author is not its turn's speaker",
            ));
        }
        let order = super::witness_message_order(admission.body())?;
        if super::taken_witness_message_order(
            &self.store,
            wtxn,
            &message.turn.target,
            &BTreeSet::from([order]),
            &HashSet::new(),
        )?
        .is_some()
        {
            return Err(malformed(
                "an archived MESSAGE's order is taken in its turn",
            ));
        }
        let content = decode(admission.body())
            .and_then(|entries| {
                entry(&entries, BODY_KEY_CONTENT)
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        let mut batch = self
            .batch_in()
            .put_archived_message(
                &message.id,
                message.occurred,
                message.learned_at,
                &admission,
            )
            .edge_with_created_at_and_vad(
                &message.id,
                EdgeKind::PartOf,
                &message.turn.target,
                message.turn.weight,
                message.turn.created_at,
                message.turn.vad,
            )
            .edge_with_created_at_and_vad(
                &message.id,
                EdgeKind::BelongsTo,
                &message.conversation.target,
                message.conversation.weight,
                message.conversation.created_at,
                message.conversation.vad,
            );
        if !content.is_empty() {
            batch = batch.text(&message.id, &[(BODY_KEY_CONTENT, content.as_str())]);
        }
        batch.apply(wtxn)?;
        Ok(())
    }
}
