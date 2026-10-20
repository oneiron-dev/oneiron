//! A NOTE document's actor carriers in its Loro history (FIX 6072): every
//! engine stamp's actor and every authorship record's, split out and put
//! back through the shared projection
//! ([`crate::store::checkpoint_payload::loro`]). Every other operation of
//! the NOTE schema names no one: its identity and title, its body text, its
//! pins and the deletes of its maps. An operation outside that schema, or a
//! message that is no engine stamp, keeps its whole group under the
//! vault-wide seal. A stamp or authorship record whose actor did not open
//! reads as no one, never as an actor some binding of its peer names, and
//! the record stays (Engine R2).
//!
//! A live document is its slot's group: its full snapshot, then its pending
//! updates. A proposal document is a group of its own; one whose fork no one
//! decided stays under the vault-wide seal, as its fork record goes when its
//! opener does not open (Engine and lead pick), and so does one that is no
//! value-only proposal (a switched-away head kept by a run review). A
//! shallow or state-only snapshot stays there too (Engine R3).

use ::loro::{
    ContainerID, ContainerType, EncodedBlobMode, JsonMapOp, JsonOp, JsonOpContent, JsonTextOp,
    LoroDoc, LoroValue, ValueOrContainer,
};

use super::super::document::NoteDocument;
use super::super::documents::NOTE_PROPOSAL_DOC;
use super::super::side_keys::HexPair;
use super::super::{NoteActor, NoteAuthorship, NotePin};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::side_table::SideKey;
use crate::store::checkpoint_payload::loro::{
    self as shared, LoroActorCodec, OpenedRow, SHALLOW, Split, SplitRow, SplitValue,
};
use crate::store::checkpoint_payload::rows::{
    self, ActorPart, Captured, OwnerRef, RoundTripPolicy, RowLocator, TypedRow, Unresolved,
};

/// The round trip a NOTE's live document takes (Engine R1): the same
/// history, in containers Loro may encode anew. No row keeps a digest of
/// these bytes: the head row, the head-document markers, the title index
/// (a normalized title), the pin index (a serialized pin), the landing
/// receipts (head ids) and the delete preview (frontiers) name versions and
/// values, never a container, so a restore has none to derive again.
const LIVE_ROUND_TRIP: RoundTripPolicy = RoundTripPolicy::HistoryEquivalent;

/// The round trip a NOTE proposal document takes (Engine R1). Its fork
/// record names a frontier and its bundle names fork ids, never these
/// bytes, so a restore has no digest to derive again.
const PROPOSAL_ROUND_TRIP: RoundTripPolicy = RoundTripPolicy::HistoryEquivalent;

/// The root containers of a NOTE document.
const META: &str = "note";
const BODY: &str = "body";
const PINS: &str = "pins";
const AUTHORSHIP: &str = "authorship";

/// The engine stamp of an admitted operation: `oneiron.note/v1 actor=<id>`.
const STAMP: &str = "oneiron.note/v1 actor=";
/// The engine stamp of a mask on write, which names no one.
const MASK_STAMP: &str = "oneiron.note/v1 mask_on_write";
/// The program-edit stamp: `note:v1:<action>:actor=<id>`.
const PROGRAM_STAMP: &str = "note:v1:";
const PROGRAM_ACTOR: &str = ":actor=";

/// The path of a stamp's actor in its message.
const STAMP_ACTOR: &str = "actor";
/// The path of an authorship record's actor in its record.
const AUTHORSHIP_ACTOR: &str = "NoteAuthorship.actor";

/// A commit message that is no NOTE engine stamp.
const NOT_A_STAMP: &str = "a NOTE commit message that is no engine stamp";
/// An authorship record that does not read, or does not spell back.
const AUTHORSHIP_UNREAD: &str = "a NOTE authorship record that does not spell back";
/// A pin value that does not read as a NOTE pin.
const PIN_UNREAD: &str = "a NOTE pin that does not read";
/// An operation outside the NOTE document's schema.
const OUTSIDE_SCHEMA: &str = "a NOTE document operation outside its schema";
/// A proposal whose fork no one decided: its record goes with its opener.
const PENDING_PROPOSAL: &str = "a NOTE proposal no one decided, whose fork goes with its opener";
/// A proposal document that holds pins or authorship: no value-only one.
const NOT_VALUE_ONLY: &str = "a NOTE proposal document that is no value-only proposal";

/// A NOTE document's actor carriers.
struct NoteActors;

impl LoroActorCodec for NoteActors {
    const FAMILY: &'static str = "note";

    fn split_message(&self, message: &str) -> Split<String> {
        if message == MASK_STAMP {
            return Ok(SplitValue::kept(message.to_owned()));
        }
        let (head, token) = cut_stamp(message).ok_or(NOT_A_STAMP)?;
        if token == ERASED_CALL_IDENTITY {
            return Ok(SplitValue::kept(message.to_owned()));
        }
        let actor = hex_id(token).ok_or(NOT_A_STAMP)?;
        Ok(SplitValue {
            no_one: format!("{head}{ERASED_CALL_IDENTITY}"),
            actors: vec![(STAMP_ACTOR.to_owned(), actor)],
        })
    }

    fn fill_message(&self, no_one: &str, path: &str, actor: EntityId) -> Result<String> {
        let (head, token) = cut_stamp(no_one).ok_or_else(rows::bad_part)?;
        if path != STAMP_ACTOR || token != ERASED_CALL_IDENTITY {
            return Err(rows::bad_part());
        }
        Ok(format!("{head}{}", actor.to_hex()))
    }

    fn split_map_insert(
        &self,
        container: &ContainerID,
        key: &str,
        value: &LoroValue,
    ) -> Split<LoroValue> {
        if is_root(container, META, ContainerType::Map) {
            return match (key, value) {
                ("id" | "title", LoroValue::String(_)) => Ok(SplitValue::kept(value.clone())),
                _ => Err(OUTSIDE_SCHEMA),
            };
        }
        if is_root(container, PINS, ContainerType::Map) {
            let LoroValue::String(pin) = value else {
                return Err(PIN_UNREAD);
            };
            serde_json::from_str::<NotePin>(pin.as_str()).map_err(|_| PIN_UNREAD)?;
            return Ok(SplitValue::kept(value.clone()));
        }
        if !is_root(container, AUTHORSHIP, ContainerType::Map) {
            return Err(OUTSIDE_SCHEMA);
        }
        let record = stored_authorship(key, value).ok_or(AUTHORSHIP_UNREAD)?;
        let Some(actor) = record.actor.id() else {
            return Ok(SplitValue::kept(value.clone()));
        };
        let no_one = NoteAuthorship {
            actor: NoteActor::Erased,
            ..record
        };
        let no_one = serde_json::to_string(&no_one).map_err(|_| AUTHORSHIP_UNREAD)?;
        Ok(SplitValue {
            no_one: LoroValue::from(no_one),
            actors: vec![(AUTHORSHIP_ACTOR.to_owned(), actor)],
        })
    }

    fn fill_map_insert(
        &self,
        container: &ContainerID,
        key: &str,
        no_one: &LoroValue,
        path: &str,
        actor: EntityId,
    ) -> Result<LoroValue> {
        if !is_root(container, AUTHORSHIP, ContainerType::Map) || path != AUTHORSHIP_ACTOR {
            return Err(rows::bad_part());
        }
        let record = stored_authorship(key, no_one).filter(|r| r.actor == NoteActor::Erased);
        let record = record.ok_or_else(rows::bad_part)?;
        let record = NoteAuthorship {
            actor: NoteActor::Actor(actor),
            ..record
        };
        let value = serde_json::to_string(&record).map_err(|_| rows::bad_part())?;
        Ok(LoroValue::from(value))
    }

    fn keep_op(&self, op: &JsonOp) -> std::result::Result<(), &'static str> {
        let maps = [META, PINS, AUTHORSHIP];
        match &op.content {
            JsonOpContent::Text(JsonTextOp::Insert { .. } | JsonTextOp::Delete { .. })
                if is_root(&op.container, BODY, ContainerType::Text) =>
            {
                Ok(())
            }
            JsonOpContent::Map(JsonMapOp::Delete { .. })
                if maps
                    .iter()
                    .any(|name| is_root(&op.container, name, ContainerType::Map)) =>
            {
                Ok(())
            }
            _ => Err(OUTSIDE_SCHEMA),
        }
    }
}

/// A NOTE engine stamp cut before its actor token, which ends it: the head
/// (`oneiron.note/v1 actor=`, or `note:v1:<action>:actor=` for an action of
/// lower-case letters and underscores) and the token.
fn cut_stamp(message: &str) -> Option<(&str, &str)> {
    let head = if message.starts_with(STAMP) {
        STAMP.len()
    } else {
        let rest = message.strip_prefix(PROGRAM_STAMP)?;
        let (action, _) = rest.split_once(PROGRAM_ACTOR)?;
        let named = action.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_');
        if action.is_empty() || !named {
            return None;
        }
        PROGRAM_STAMP.len() + action.len() + PROGRAM_ACTOR.len()
    };
    Some(message.split_at(head))
}

/// An id in its one canonical spelling.
fn hex_id(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// Whether `container` is the root container `name` of kind `kind`.
fn is_root(container: &ContainerID, name: &str, kind: ContainerType) -> bool {
    match container {
        ContainerID::Root {
            name: root,
            container_type,
        } => root.as_str() == name && *container_type == kind,
        ContainerID::Normal { .. } => false,
    }
}

/// A stored authorship record under `key`, when it reads, names the
/// operation its key does and spells its own bytes back.
fn stored_authorship(key: &str, value: &LoroValue) -> Option<NoteAuthorship> {
    let LoroValue::String(value) = value else {
        return None;
    };
    let record: NoteAuthorship = serde_json::from_str(value.as_str()).ok()?;
    let spelled = serde_json::to_string(&record).ok()?;
    (spelled == value.as_str() && record.operation.to_hex() == key).then_some(record)
}

/// The rows of one document group, a full snapshot then its updates, as
/// one document: the rows import with nothing pending.
fn group_doc(rows: &[&[u8]]) -> Option<LoroDoc> {
    let doc = LoroDoc::new();
    for row in rows {
        let status = doc.import(row).ok()?;
        if status.pending.is_some() {
            return None;
        }
    }
    Some(doc)
}

/// The NOTE a document names as its own identity.
fn named_note(doc: &LoroDoc) -> Option<EntityId> {
    match doc.get_map(META).get("id")? {
        ValueOrContainer::Value(LoroValue::String(id)) => hex_id(id.as_str()),
        _ => None,
    }
}

/// The NOTE whose document a snapshot is: its identity, when it reads as
/// that NOTE's document. A slot nothing else claims is the NOTE's own
/// document when the snapshot names it.
pub(crate) fn snapshot_note(snapshot: &[u8]) -> Option<EntityId> {
    let doc = group_doc(&[snapshot])?;
    let note = named_note(&doc)?;
    NoteDocument::from_loro(note, doc).ok()?.view().ok()?;
    Some(note)
}

/// Refuses a group unless it is one document of `note`: its identity names
/// `note` (another NOTE is two owners), and it reads as a NOTE document, its
/// pins and authorship records included.
fn note_group(note: EntityId, rows: &[&[u8]]) -> std::result::Result<(), Unresolved> {
    let doc = group_doc(rows).ok_or(Unresolved::Undecodable)?;
    if named_note(&doc) != Some(note) {
        return Err(Unresolved::SharedOwners);
    }
    let doc = NoteDocument::from_loro(note, doc).map_err(|_| Unresolved::Undecodable)?;
    doc.view().map_err(|_| Unresolved::Undecodable)?;
    Ok(())
}

/// Splits one live NOTE document group of `note`: its full snapshot, then
/// its updates in replay order.
pub(crate) fn split_live(
    note: EntityId,
    rows: &[&[u8]],
) -> std::result::Result<Vec<SplitRow>, Unresolved> {
    note_group(note, rows)?;
    shared::split_loro(rows, &NoteActors, LIVE_ROUND_TRIP)
}

/// Whether `content` is a NOTE document row's split.
pub(crate) fn frames_live(content: &[u8]) -> bool {
    shared::frames::<NoteActors>(content)
}

/// Rebuilds one live NOTE document group from its opened rows: a full
/// history of `note`'s document, every actor that did not open erased.
pub(crate) fn join_live(note: EntityId, rows: &[OpenedRow<'_>]) -> Result<Vec<Vec<u8>>> {
    let joined = shared::join_loro(rows, &NoteActors)?.rows;
    let bytes: Vec<&[u8]> = joined.iter().map(Vec::as_slice).collect();
    note_group(note, &bytes).map_err(|_| rows::bad_part())?;
    Ok(joined)
}

/// Refuses `bytes` unless it is a full NOTE document snapshot that reads as
/// the document of the NOTE it names.
pub(crate) fn check_live_snapshot(bytes: &[u8]) -> Result<()> {
    full_snapshot(bytes)?;
    let note = snapshot_note(bytes).ok_or_else(rows::bad_part)?;
    note_group(note, &[bytes]).map_err(|_| rows::bad_part())
}

/// Refuses `bytes` unless it is a full, not shallow, snapshot blob.
fn full_snapshot(bytes: &[u8]) -> Result<()> {
    let meta = LoroDoc::decode_import_blob_meta(bytes, true).map_err(|_| rows::bad_part())?;
    let doc = group_doc(&[bytes]).ok_or_else(rows::bad_part)?;
    if meta.mode != EncodedBlobMode::Snapshot || doc.is_shallow() {
        return Err(rows::bad_part());
    }
    Ok(())
}

/// One NOTE proposal document, under its NOTE: a decided or unforked full
/// value-only proposal splits as a group of its own, kept exactly as stored
/// when its history names no one; a shallow one, an undecided fork's and
/// one that is no value-only proposal stay under the vault-wide seal, named
/// with the NOTE.
pub(crate) fn capture_proposal(
    out: &mut Captured,
    note: EntityId,
    undecided: bool,
    row: TypedRow<HexPair, Vec<u8>>,
) {
    let owner = OwnerRef::entity(&note);
    let shape = proposal_shape(note, undecided, &row.bytes);
    let outcome = shape.and_then(|()| {
        shared::split_loro(&[row.bytes.as_slice()], &NoteActors, PROPOSAL_ROUND_TRIP)
    });
    match outcome.map(|mut split| split.pop()) {
        Ok(Some(split)) if split.atoms.is_empty() => out.exact(owner, row.at, row.bytes),
        Ok(Some(split)) => shared::place(out, owner, row.at, split),
        Ok(None) => out.unclassified(row.at, Some(owner), Unresolved::Undecodable),
        Err(reason) => out.unclassified(row.at, Some(owner), reason),
    }
}

/// Whether a proposal document is one a split takes: a full history, not an
/// undecided fork's, `note`'s document, and value-only (no pins, no
/// authorship), as a proposal's contract holds it.
fn proposal_shape(
    note: EntityId,
    undecided: bool,
    snapshot: &[u8],
) -> std::result::Result<(), Unresolved> {
    let doc = group_doc(&[snapshot]).ok_or(Unresolved::Undecodable)?;
    if doc.is_shallow() {
        return Err(Unresolved::ActorSplit(SHALLOW));
    }
    if undecided {
        return Err(Unresolved::ActorSplit(PENDING_PROPOSAL));
    }
    if named_note(&doc) != Some(note) {
        return Err(Unresolved::SharedOwners);
    }
    let doc = NoteDocument::from_loro(note, doc).map_err(|_| Unresolved::Undecodable)?;
    let view = doc.view().map_err(|_| Unresolved::Undecodable)?;
    if !view.pins.is_empty() || !view.authorship.is_empty() {
        return Err(Unresolved::ActorSplit(NOT_VALUE_ONLY));
    }
    Ok(())
}

/// The NOTE a proposal row's key leads with.
fn proposal_note(at: &RowLocator) -> Result<EntityId> {
    let key = at.key.strip_prefix(NOTE_PROPOSAL_DOC.decl().prefix);
    let key = key.and_then(HexPair::decode_key).ok_or_else(rows::bad_part)?;
    Ok(key.0.0)
}

/// Refuses a proposal row unless it is a full value-only document of the
/// NOTE its key leads with.
pub(crate) fn check_proposal(at: &RowLocator, bytes: &[u8]) -> Result<()> {
    full_snapshot(bytes)?;
    proposal_shape(proposal_note(at)?, false, bytes).map_err(|_| rows::bad_part())
}

/// A proposal document rebuilt from its content and the actors that
/// opened: a full value-only document of the NOTE its key leads with.
pub(crate) fn join_proposal(
    at: &RowLocator,
    content: &[u8],
    parts: &[&ActorPart],
) -> Result<Vec<u8>> {
    let atoms = shared::opened_atoms(parts)?;
    let mut joined = shared::join_loro(&[OpenedRow { content, atoms }], &NoteActors)?.rows;
    let bytes = joined.pop().ok_or_else(rows::bad_part)?;
    check_proposal(at, &bytes)?;
    Ok(bytes)
}
