//! The non-Loro sync rows (KS7-3a), each placed with its family's own
//! codec: a thin-residence item's cached blob and document, a pending text
//! edit, a pending NOTE request and the sync queue's rows. The Loro bytes
//! of a window's snapshot and updates, and of a queued window update, are
//! split a window at a time ([`super::operations`]); one row alone stays
//! unclassified. A cached document's and a pending edit's are their entity
//! document's history, whose stamps only that document's own split takes
//! out, so each stays under the vault-wide seal, named with its entity.

use super::{CapturedSyncRow, Placement, SyncCarrier, SyncPayloadOwners, SyncUnclassified};
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::note::{NoteChange, NoteOperation, PendingNoteRequest};
use crate::side_table::{
    SYNC_QD_E, SYNC_QN_E, SYNC_RESIDENCE_ITEM_BLOB, SYNC_RESIDENCE_ITEM_DOCUMENT,
};
use crate::store::checkpoint_payload::rows::{OwnerRef, RowDb, RowLocator, bad_part};
use crate::sync::transport::{DocumentFrame, TAG_DOCUMENT, decode_document, document_sub_tags};

/// A cached document or a pending edit: Loro bytes of an entity document.
const DOCUMENT_STAMPS: &str =
    "an entity document's Loro bytes, whose stamps only its own split takes out";

/// An id in its one canonical spelling.
pub(super) fn named(hex: &str) -> Option<EntityId> {
    EntityId::from_hex(hex).ok().filter(|id| id.to_hex() == hex)
}

/// The id `key` names after `prefix`, with nothing after it.
pub(super) fn id_after(key: &[u8], prefix: &[u8]) -> Option<EntityId> {
    named(std::str::from_utf8(key.strip_prefix(prefix)?).ok()?)
}

/// The id `key` names after `prefix`, and what follows its `:`.
pub(super) fn pair_after<'k>(key: &'k [u8], prefix: &[u8]) -> Option<(EntityId, &'k str)> {
    let rest = std::str::from_utf8(key.strip_prefix(prefix)?).ok()?;
    let (id, tail) = rest.split_once(':')?;
    Some((named(id)?, tail))
}

/// A stored document frame: its tag, then the frame.
pub(super) fn frame(value: &[u8]) -> Option<DocumentFrame<'_>> {
    match value.split_first() {
        Some((&TAG_DOCUMENT, frame)) => decode_document(frame).ok(),
        _ => None,
    }
}

/// Where one captured row goes.
pub(super) fn place(row: &CapturedSyncRow<'_>, owners: &dyn SyncPayloadOwners) -> Placement {
    match row.carrier {
        SyncCarrier::WindowSnapshot | SyncCarrier::WindowUpdate => {
            Placement::unclassified(None, SyncUnclassified::PendingLoroProjection)
        }
        SyncCarrier::ResidenceItem => residence_item(row.key, row.value, owners),
        SyncCarrier::PendingEdit => pending_edit(row.key, row.value, owners),
        SyncCarrier::PendingNoteOperation => pending_note(row.key, row.value),
        SyncCarrier::SyncQueue => crate::sync::queue::checkpoint::place(row.key, row.value),
    }
}

/// A cached item's rows: its blob is its entity's own row, placed by its
/// kind as the entity getter places that kind; its document is the
/// entity's document, which must name the item.
fn residence_item(key: &[u8], value: &[u8], owners: &dyn SyncPayloadOwners) -> Placement {
    if let Some(id) = id_after(key, SYNC_RESIDENCE_ITEM_BLOB.prefix) {
        return super::owners::entity_row(owners.owner_entity(id), value, owners);
    }
    let Some(id) = id_after(key, SYNC_RESIDENCE_ITEM_DOCUMENT.prefix) else {
        return Placement::unclassified(None, SyncUnclassified::Undecodable);
    };
    let names_item = frame(value).is_some_and(|frame| {
        frame.entity == id
            && matches!(
                frame.kind,
                document_sub_tags::STATE | document_sub_tags::UPDATE
            )
    });
    document_row(owners.owner_entity(id), names_item)
}

/// A pending edit: an update frame of the entity its key names, at the
/// sequence its key names (eight lowercase hex digits).
fn pending_edit(key: &[u8], value: &[u8], owners: &dyn SyncPayloadOwners) -> Placement {
    let Some((id, seq)) = pair_after(key, SYNC_QD_E.prefix) else {
        return Placement::unclassified(None, SyncUnclassified::Undecodable);
    };
    let sequenced = u32::from_str_radix(seq, 16).is_ok_and(|seq_no| format!("{seq_no:08x}") == seq);
    let names_entity = frame(value)
        .is_some_and(|frame| frame.entity == id && frame.kind == document_sub_tags::UPDATE);
    document_row(owners.owner_entity(id), sequenced && names_entity)
}

/// An entity document's row, named with its entity: its Loro history goes
/// whole with that document's own split, never sealed here.
fn document_row(id: EntityId, whole: bool) -> Placement {
    let reason = if whole {
        SyncUnclassified::ActorSplit(DOCUMENT_STAMPS)
    } else {
        SyncUnclassified::Undecodable
    };
    Placement::unclassified(Some(OwnerRef::entity(&id)), reason)
}

/// A pending NOTE request: its NOTE's own, held only while what it cites
/// is. Its command names no actor (the host takes that from its session).
fn pending_note(key: &[u8], value: &[u8]) -> Placement {
    let Some((note, request)) = pair_after(key, SYNC_QN_E.prefix) else {
        return Placement::unclassified(None, SyncUnclassified::Undecodable);
    };
    let owner = OwnerRef::entity(&note);
    match note_request(note, request, value) {
        Some(dependencies) => Placement::owned(owner, dependencies),
        None => Placement::unclassified(Some(owner), SyncUnclassified::Undecodable),
    }
}

/// The owners a request of `note` holds only while they do: a citation's
/// claim and its source document. `None` unless `value` is the queued
/// envelope of that NOTE's request `request`, whose frame is the command as
/// admitted (FIX 2375).
fn note_request(note: EntityId, request: &str, value: &[u8]) -> Option<Vec<OwnerRef>> {
    let queued = PendingNoteRequest::decode(value)?.frame;
    let frame = frame(queued)
        .filter(|frame| frame.entity == note && frame.kind == document_sub_tags::NOTE_OPS)?;
    let operation = NoteOperation::decode(frame.payload).ok()?;
    if operation.request_id.to_hex() != request {
        return None;
    }
    Some(match operation.change {
        NoteChange::Cite { pin } => vec![
            OwnerRef::entity(&pin.claim),
            OwnerRef::entity(&pin.document),
        ],
        NoteChange::Edit { .. } | NoteChange::SetTitle { .. } => Vec::new(),
    })
}

/// Refuses an opened row unless it reads as one this projection seals: a
/// cached item's entity blob, or a NOTE request's frame.
pub(super) fn check(at: &RowLocator, value: &[u8]) -> Result<()> {
    let blob = || {
        id_after(&at.key, SYNC_RESIDENCE_ITEM_BLOB.prefix).is_some()
            && EntityMetadataHeader::parse(value).is_some()
    };
    let request = || {
        pair_after(&at.key, SYNC_QN_E.prefix)
            .is_some_and(|(note, request)| note_request(note, request, value).is_some())
    };
    if at.db == RowDb::SyncState && at.path.is_empty() && (blob() || request()) {
        Ok(())
    } else {
        Err(bad_part())
    }
}
