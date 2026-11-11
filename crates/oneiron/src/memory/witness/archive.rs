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
//! [`ArchivedMessageAdmission`] is the archive put's capability, as
//! `gate::WitnessMessageAuthorization` is the witness put's: its one
//! constructor proves the bytes are a canonical envelope an import marked.

use std::collections::{BTreeSet, HashSet};

use oneiron_contracts::affect::Vad;
use rmpv::Value;

use super::codec::{IMPORTED_SOURCE_KEY, ImportStamp, import_stamp};
use crate::Vault;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::{Error, RecordError, Result};
use crate::ports::EntityStoreRead;
use crate::registry::{ENTITY_TYPE_CONVERSATION, ENTITY_TYPE_TURN};
use crate::store::Store;
use crate::store::witness_message_body::{IMPORT_KEY_SOURCE_IMPORT, METADATA_KEY_IMPORT};
use crate::temporal::TimeRange;

/// The import source an archive restore stamps on the MESSAGE rows and
/// containers it brings back.
pub(crate) const ARCHIVE_IMPORT_SOURCE: &str = "archive";

/// The type an archive-restored MESSAGE carries, beside the transcript
/// importer's `import.<source>`.
const ARCHIVE_MESSAGE_TYPE: &str = "import.archive";

/// The prefix every imported MESSAGE type carries.
const IMPORTED_MESSAGE_TYPE_PREFIX: &str = "import.";

const BODY_KEY_TYPE: &str = "type";
const BODY_KEY_CONTENT: &str = "content";
const BODY_KEY_METADATA: &str = "metadata";
const BODY_KEY_IS_VISIBLE: &str = "is_visible";

const IMPORT_KEY_SOURCE: &str = "source";
/// The type the source vault gave the row.
const IMPORT_KEY_SOURCE_TYPE: &str = "source_type";
/// The `AuthoredBy` targets the source vault linked the row to, as hex
/// ids: provenance only, never a local author.
const IMPORT_KEY_AUTHORED_BY: &str = "authored_by";

/// The refusal of an archived row that carries the source-audience key
/// (fix list row 16256): an archive restores imported evidence, never a
/// source landing's row, and never drops the key to make one fit.
const ARCHIVED_STAMP: &str =
    "an archived row carries no source_audience_required; only a source landing stamps it";

/// A native TURN's PERSON byline, and the inert key an archive restore
/// keeps it under.
const TURN_KEY_ACTOR: &str = "actor";
const TURN_KEY_IMPORT_ACTOR: &str = "import_actor";

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

/// The body an archived MESSAGE comes back with: `source`, its archived
/// body, typed `import.archive`, with `metadata.import` naming the source
/// `archive`, the source's type and `bylines`, the targets of its archived
/// `AuthoredBy` edges. A value the source metadata kept under `import`
/// moves to `metadata.import.source_import`; its other metadata stays. A
/// body an import already marked comes back unchanged.
///
/// # Errors
/// [`RecordError::InvalidWitnessMessageBody`] when `source` is not a
/// canonical envelope, or the marked body is not one (a metadata bound).
pub(crate) fn archived_message_body(source: &[u8], bylines: &[EntityId]) -> Result<Vec<u8>> {
    if crate::source_audience::body_names_obligation(source) {
        return Err(malformed(ARCHIVED_STAMP));
    }
    crate::gate::validate_canonical_witness_message_body(source)?;
    let mut entries = decode(source).ok_or_else(|| malformed("an archived MESSAGE body"))?;
    if import_marked(&entries) {
        return Ok(source.to_vec());
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

/// The archive put's capability for `body`: a canonical envelope an import
/// marked.
fn admit_archived_message(body: &[u8]) -> Result<ArchivedMessageAdmission> {
    if crate::source_audience::body_names_obligation(body) {
        return Err(malformed(ARCHIVED_STAMP));
    }
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
/// # Errors
/// [`RecordError::InvalidConversationBody`] when `source` is not a map, or
/// its import stamp is malformed.
pub(crate) fn archived_container_body(entity_type: u8, source: &[u8]) -> Result<Vec<u8>> {
    if crate::source_audience::body_names_obligation(source) {
        return Err(container_refused(ARCHIVED_STAMP));
    }
    match import_stamp(source) {
        ImportStamp::Imported(_) => return Ok(source.to_vec()),
        ImportStamp::Malformed => {
            return Err(container_refused(
                "an import source must be one non-empty string",
            ));
        }
        ImportStamp::Live => {}
    }
    let mut entries = decode(source)
        .ok_or_else(|| container_refused("an archived MESSAGE container is not a map"))?;
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
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &Value::Map(entries))
        .map_err(|_| container_refused("an archived MESSAGE container is not encodable"))?;
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
