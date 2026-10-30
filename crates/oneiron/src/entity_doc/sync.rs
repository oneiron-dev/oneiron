//! The sync text plane's canonical adapter (FIX 8871, 8872, 8873). A
//! non-NOTE record's text on the sync plane is its entity document where one
//! stands: the head, its slot rows and their generation keys, read durable
//! inside each writer and written through [`storage::persist_scanned`], so a
//! peer's text and a local edit keep the head's counters, revisions, index
//! and tagging duties as every other write does.
//!
//! A MESSAGE with no document yet is born lazily by the writer that needs
//! one, through the MESSAGE birth's own semantics: its canonical text, at its
//! own time, naming no one. The birth's operations take a peer derived from
//! the record, so every machine's sync birth of the same row is the same
//! operations and their documents join; the stream and quote births are the
//! doors that name an author. A peer's whole document, its birth included,
//! is carried here instead; one of another birth than the document held here
//! stands apart, as a carried MESSAGE document of another incarnation does.
//!
//! A record of any other kind with no document has no birth here: its text
//! stays in the sequence rows of its own slot (a snapshot and updates keyed
//! by sequence), where the sync plane has always kept it, and is read there.
//!
//! A sync write is admitted whatever its text holds (FIX 8872, KEEP TODAY):
//! the owner's scan runs as configured, a key the lift places goes to custody
//! and is marked, and a hit no rule places stays, recorded. No hit refuses.

use heed::{RoTxn, RwTxn};
use loro::{CommitOptions, ExportMode, LoroDoc};

use super::doc_actor::DocActor;
use super::document::{BIRTH, BODY, Birth, META, map_insert_bytes, stamp_with};
use super::prose_admission::{LandedProse, admit_landed};
use super::storage::{self, Head};
use super::verbs::{Admitted, admitted_text_in_txn};
use super::{EntityDoc, TextField, invalid};
use crate::batch::secret_scan::{
    CarrierText, Lifted, LiftedKeys, mark_carrier_text_in_txn, scan_content_in_txn,
};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, GateError, Result};
use crate::ports::{DocumentRowStore, DocumentSlot, EntityStoreMaintenance, EntityStoreRead};
use crate::registry::ENTITY_TYPE_MESSAGE;
use crate::sync::documents::storage as sequence_rows;
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};

/// The domain a lazy birth's peer is derived in.
const BIRTH_PEER_CONTEXT: &str = "oneiron.sync-text.birth-peer.v1";
/// The row a sync edit's prose links are receipted under.
const SYNC_EDIT_ROW: &str = "sync.document.edit_text";
/// The slot a sync edit's prose is read in.
const SYNC_EDIT_SLOT: &str = "/insert";
/// Where the lift's own marks name a document's keys.
const PLACE: &str = "document";
/// The first reason code of the write door's secret refusal.
const DETECTED: &str = "gate.secret_scan.detected";
/// The refusal a write to a record with no text plane meets, as the
/// migration door words it.
const NO_TEXT: &str = "this record kind does not carry editable text";

/// A record's text as the sync plane reads it.
pub(crate) struct SyncText {
    /// The durable text: its entity document's, or its sequence rows'.
    pub(crate) doc: LoroDoc,
    /// The slot its rows sit in.
    pub(crate) slot: DocumentSlot,
}

/// One scalar edit of a record's text, by an authenticated actor.
pub(crate) struct SyncEdit<'a> {
    pub(crate) actor: WriteActor,
    pub(crate) at: u64,
    /// Unicode scalar position.
    pub(crate) start: usize,
    /// Unicode scalars deleted from `start`.
    pub(crate) delete: usize,
    pub(crate) insert: &'a str,
}

/// What a sync edit committed.
pub(crate) struct SyncEdited {
    /// The edit's own operations, for its peers; never its document's birth.
    pub(crate) update: Vec<u8>,
    /// The edit's journal sequence: the head generation it left, or the
    /// sequence its update took in the record's sequence rows.
    pub(crate) sequence: u64,
    landed: Vec<LandedProse>,
}

impl SyncEdited {
    /// Receipts the edit's unresolved prose links, once its write has
    /// committed (FIX 1227).
    pub(crate) fn land(&self, vault: &Vault) {
        admit_landed(vault, SYNC_EDIT_ROW, &self.landed);
    }
}

/// `entity`'s durable text in `txn`: its document, or the sequence rows of a
/// record of a kind with no birth here; `None` for a MESSAGE not yet born.
pub(crate) fn sync_text_in(
    vault: &Vault,
    txn: &RoTxn<'_>,
    entity: &EntityId,
) -> Result<Option<SyncText>> {
    Ok(match plane_in(vault, txn, entity)? {
        Plane::Document(head) => Some(SyncText {
            doc: storage::load(&vault.store, txn, &head)?.doc,
            slot: DocumentSlot::from_hex(&head.document)?,
        }),
        Plane::SequenceRows => Some(SyncText {
            doc: sequence_rows::load(vault, txn, *entity)?,
            slot: DocumentSlot::of(*entity),
        }),
        Plane::Unborn => None,
    })
}

/// Applies `edit` to `entity`'s document in the caller's writer (FIX 8873):
/// the actor is checked as it stands here, the document takes a fresh peer
/// bound to it, the inserted prose is admitted before any operation holds it
/// (FIX 2371), and the commit carries the actor's stamp and made_by receipt.
/// A record's sequence rows take the edit as their next update.
pub(crate) fn edit_sync_text_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    edit: &SyncEdit<'_>,
) -> Result<SyncEdited> {
    let actor = edit.actor;
    super::forks::validate_actor(vault, txn, actor)?;
    // A shared vault's role and record scope (FIX 9846).
    vault.authorize_shared_content_write_in_txn(txn, *entity, &actor)?;
    let mut h = match plane_in(vault, txn, entity)? {
        Plane::Document(h) => h,
        Plane::Unborn => birth_in_txn(vault, txn, entity)?,
        Plane::SequenceRows => return edit_sequence_rows_in_txn(vault, txn, entity, edit),
    };
    let mut doc = storage::load(&vault.store, txn, &h)?;
    let before = doc.doc.oplog_vv();
    let lifted = if LiftedKeys::names_a_handle(edit.insert) {
        super::lift::lifted_keys_in_txn(&vault.store, txn, &h)?
    } else {
        LiftedKeys::default()
    };
    let text = admitted_in_txn(vault, txn, entity, edit.insert, &lifted)?;
    doc.doc
        .set_peer_id(LoroDoc::new().peer_id())
        .map_err(|_| invalid("document peer rotation"))?;
    super::forks::bind_actor(vault, txn, &doc, actor, edit.at)?;
    let (start, delete) = (edit.start, edit.delete);
    doc.edit_with(actor, edit.at, &[], |body| {
        body.delete(start, delete)
            .map_err(|_| invalid("sync text delete"))?;
        body.insert(start, &text.stored)
            .map_err(|_| invalid("sync text insert"))
    })?;
    storage::persist_scanned(
        vault,
        txn,
        entity,
        &mut h,
        &doc,
        Some(&before),
        synced(None),
    )?;
    let update = doc
        .doc
        .export(ExportMode::updates(&before))
        .map_err(|_| invalid("sync text update export"))?;
    let slot = SYNC_EDIT_SLOT.to_owned();
    let landed = (!edit.insert.is_empty())
        .then(|| LandedProse::anchored(actor, slot, &doc, start, &text, &lifted));
    Ok(SyncEdited {
        update,
        sequence: h.generation,
        landed: landed.into_iter().collect(),
    })
}

/// Joins a peer's operations `update` to `entity`'s document in the caller's
/// writer. Each operation keeps its own peer and stamp; this vault is never
/// named its author. Where no MESSAGE document stands, a whole document is
/// carried here as a state is, and operations that build on a birth take
/// this vault's own birth of the same row first; a record's sequence rows
/// take the update as their next one. `masked` is the re-masked copy text a
/// copy edit landed from: the scan reads it in place of the document's
/// text. Whether the text moved.
pub(crate) fn join_sync_update_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    update: &[u8],
    masked: Option<&str>,
) -> Result<bool> {
    let (mut h, whole) = match plane_in(vault, txn, entity)? {
        Plane::Document(h) => (h, whole_document(update)),
        Plane::Unborn => match whole_document(update) {
            Some(carried) => {
                replace_sync_text_in_txn(vault, txn, entity, carried)?;
                return Ok(true);
            }
            None => (birth_in_txn(vault, txn, entity)?, None),
        },
        Plane::SequenceRows => {
            return join_sequence_rows_in_txn(vault, txn, entity, update, masked);
        }
    };
    let doc = storage::load(&vault.store, txn, &h)?;
    let before = doc.doc.oplog_vv();
    // Operations after a birth build on it, so a whole document this one
    // does not hold is another birth of the same text: it stands apart.
    if whole.is_some_and(|whole| !before.includes_vv(&whole.oplog_vv())) {
        return Err(invalid("sync text of another document birth"));
    }
    import_whole(&doc.doc, update)?;
    if doc.doc.oplog_vv() == before {
        return Ok(false);
    }
    storage::persist_scanned(
        vault,
        txn,
        entity,
        &mut h,
        &doc,
        Some(&before),
        synced(masked),
    )?;
    Ok(true)
}

/// Replaces `entity`'s document with `staged`, a peer's state with this
/// vault's pending updates replayed on it, in the caller's writer. The caller
/// checked that it covers the durable text. A state with no operations is no
/// document and installs nothing. A MESSAGE with no head takes it under a
/// new one, carried, not born here; a record's sequence rows take it as
/// their snapshot.
pub(crate) fn replace_sync_text_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    staged: LoroDoc,
) -> Result<()> {
    if staged.oplog_vv().is_empty() {
        return Ok(());
    }
    let head = match plane_in(vault, txn, entity)? {
        Plane::Document(h) => Some(h),
        Plane::Unborn => None,
        Plane::SequenceRows => {
            return replace_sequence_rows_in_txn(vault, txn, entity, &staged);
        }
    };
    let doc = EntityDoc::from_loro(staged)?;
    if doc.birth().entity != entity.to_hex() {
        return Err(invalid("sync text state of another document"));
    }
    let mut h = match head {
        Some(h) => h,
        None => carried_head_in_txn(vault, txn, entity)?,
    };
    storage::persist_scanned(vault, txn, entity, &mut h, &doc, None, synced(None))?;
    if doc.doc.is_shallow() {
        vault.store.port_document_shallow_since_put(
            txn,
            DocumentSlot::from_hex(&h.document)?,
            &doc.doc.shallow_since_vv().encode(),
        )?;
    }
    Ok(())
}

fn head_in(vault: &Vault, txn: &RoTxn<'_>, entity: &EntityId) -> Result<Option<Head>> {
    if !storage::has_record_head(&vault.store, txn, entity)? {
        return Ok(None);
    }
    storage::head(&vault.store, txn, entity).map(Some)
}

/// Where a record's text on the sync plane is read and written.
enum Plane {
    /// Its entity document, under this head.
    Document(Head),
    /// A MESSAGE with no document yet: the writer that needs one births it.
    Unborn,
    /// The sequence rows of its own slot: a record of a kind with no birth
    /// here that holds no document.
    SequenceRows,
}

/// The one routing rule of every sync reader and writer: a head means the
/// document; no head means the MESSAGE birth for a MESSAGE, and the
/// sequence rows for every other kind.
fn plane_in(vault: &Vault, txn: &RoTxn<'_>, entity: &EntityId) -> Result<Plane> {
    if let Some(head) = head_in(vault, txn, entity)? {
        return Ok(Plane::Document(head));
    }
    Ok(
        if vault.get_entity_type_in_txn(txn, entity)? == Some(ENTITY_TYPE_MESSAGE) {
            Plane::Unborn
        } else {
            Plane::SequenceRows
        },
    )
}

/// [`edit_sync_text_in_txn`] on `entity`'s sequence rows: the prose is
/// admitted as a document edit's is, the edit takes a fresh peer bound to
/// the actor, and its commit carries the actor's stamp and made_by receipt,
/// all in the operations the rows store and the peers receive.
fn edit_sequence_rows_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    edit: &SyncEdit<'_>,
) -> Result<SyncEdited> {
    let doc = sequence_rows::load(vault, txn, *entity)?;
    let before = doc.oplog_vv();
    let lifted = if LiftedKeys::names_a_handle(edit.insert) {
        LiftedKeys::of_in_txn(&vault.store, txn, [doc.get_text(BODY).to_string()])?
    } else {
        LiftedKeys::default()
    };
    let text = admitted_in_txn(vault, txn, entity, edit.insert, &lifted)?;
    doc.set_peer_id(LoroDoc::new().peer_id())
        .map_err(|_| invalid("document peer rotation"))?;
    crate::typed_body::bind_peer(vault, txn, doc.peer_id(), edit.actor, edit.at)?;
    let body = doc.get_text(BODY);
    body.delete(edit.start, edit.delete)
        .map_err(|_| invalid("sync text delete"))?;
    body.insert(edit.start, &text.stored)
        .map_err(|_| invalid("sync text insert"))?;
    stamp_with(&doc, edit.actor, edit.at, "edit", &[])?;
    let update = doc
        .export(ExportMode::updates(&before))
        .map_err(|_| invalid("sync text update export"))?;
    let sequence = append_sequence_update_in_txn(vault, txn, entity, &doc, &update, None)?;
    // No document stands to read the insert in its place: its own links are
    // read on their own.
    let landed = (!edit.insert.is_empty())
        .then(|| LandedProse::whole(edit.actor, SYNC_EDIT_SLOT.to_owned(), &text.said));
    Ok(SyncEdited {
        update,
        sequence: u64::from(sequence),
        landed: landed.into_iter().collect(),
    })
}

/// [`join_sync_update_in_txn`] on `entity`'s sequence rows: `update` imports
/// whole on their text and lands as their next update. Whether it moved.
fn join_sequence_rows_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    update: &[u8],
    masked: Option<&str>,
) -> Result<bool> {
    let doc = sequence_rows::load(vault, txn, *entity)?;
    let before = doc.oplog_vv();
    sequence_rows::import_complete(&doc, update)?;
    if doc.oplog_vv() == before {
        return Ok(false);
    }
    append_sequence_update_in_txn(vault, txn, entity, &doc, update, masked)?;
    Ok(true)
}

/// [`replace_sync_text_in_txn`] on `entity`'s sequence rows: `staged`,
/// scanned, replaces them as a shallow snapshot.
fn replace_sequence_rows_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    staged: &LoroDoc,
) -> Result<()> {
    scan_sequence_text_in_txn(vault, txn, entity, &staged.get_text(BODY).to_string())?;
    sequence_rows::snapshot(vault, txn, *entity, staged, true)
}

/// Appends `update`, whose operations `doc` now holds, as the next update of
/// `entity`'s sequence rows, once the sync scan has read `masked`, else
/// `doc`'s text. The sequence the update took.
fn append_sequence_update_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    doc: &LoroDoc,
    update: &[u8],
    masked: Option<&str>,
) -> Result<u32> {
    let text = doc.get_text(BODY).to_string();
    scan_sequence_text_in_txn(vault, txn, entity, masked.unwrap_or(&text))?;
    sequence_rows::append(vault, txn, *entity, update)
}

fn content() -> TextField {
    TextField::MapField("content".to_owned())
}

/// The lazy birth of a record's text, before it is persisted.
struct Born {
    doc: EntityDoc,
    /// The row's body with its text replaced by the document pointer.
    pointer: Vec<u8>,
}

/// The birth `entity`'s text takes when no document stands for it: an atomic
/// MESSAGE's canonical content at its own time, born as a stream or quote
/// births it but naming no one. `None` for any other record.
fn born_in(vault: &Vault, txn: &RoTxn<'_>, entity: &EntityId) -> Result<Option<Born>> {
    let Some(raw) = vault.store.port_entity_raw(txn, entity)? else {
        return Ok(None);
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        return Ok(None);
    };
    if header.entity_type != ENTITY_TYPE_MESSAGE {
        return Ok(None);
    }
    let Some((text, pointer)) = split_content(&raw[ENTITY_METADATA_HEADER_LEN..], entity) else {
        return Ok(None);
    };
    let doc = unattributed(seeded(entity)?, entity, &text, header.occurred_start)?;
    Ok(Some(Born { doc, pointer }))
}

/// A canonical MESSAGE body's content, and the body with it replaced by the
/// document pointer, as the MESSAGE birth writes it.
fn split_content(body: &[u8], entity: &EntityId) -> Option<(String, Vec<u8>)> {
    crate::gate::validate_canonical_witness_message_body(body).ok()?;
    let rmpv::Value::Map(mut fields) =
        rmpv::decode::read_value(&mut std::io::Cursor::new(body)).ok()?
    else {
        return None;
    };
    let slot = fields
        .iter()
        .position(|(key, _)| key.as_str() == Some("content"))?;
    let (_, value) = fields.remove(slot);
    let text = value.as_str()?.to_owned();
    fields.push((
        rmpv::Value::from("entity_doc_ref"),
        rmpv::Value::from(entity.to_hex()),
    ));
    let mut pointer = Vec::new();
    rmpv::encode::write_value(&mut pointer, &rmpv::Value::Map(fields)).ok()?;
    Some((text, pointer))
}

/// A fresh document whose peer is derived from `entity`.
fn seeded(entity: &EntityId) -> Result<LoroDoc> {
    let key = blake3::derive_key(BIRTH_PEER_CONTEXT, entity.as_bytes());
    let mut peer = [0u8; 8];
    peer.copy_from_slice(&key[..8]);
    let doc = LoroDoc::new();
    doc.set_peer_id(u64::from_be_bytes(peer) >> 1)
        .map_err(|_| invalid("document birth peer"))?;
    Ok(doc)
}

/// A birth that names no one: no stamp and no receipt, at the record's time.
fn unattributed(doc: LoroDoc, entity: &EntityId, text: &str, at: u64) -> Result<EntityDoc> {
    doc.set_record_timestamp(true);
    let birth = Birth {
        entity: entity.to_hex(),
        actor: DocActor::Erased,
        at,
    };
    map_insert_bytes(&doc.get_map(META), BIRTH, &birth.encode()?)?;
    doc.get_text(BODY)
        .insert(0, text)
        .map_err(|_| invalid("document birth text"))?;
    let timestamp = i64::try_from(at).map_err(|_| invalid("document timestamp overflow"))?;
    doc.commit_with(CommitOptions::new().timestamp(timestamp));
    EntityDoc::from_loro(doc)
}

/// Persists `entity`'s lazy birth in the caller's writer, as the MESSAGE
/// birth persists it. A sync birth names no one, whoever is live here: every
/// machine's sync birth of one row is then the same operations under the
/// same peer, and the births join. Naming an author is the stream and quote
/// births' work.
fn birth_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, entity: &EntityId) -> Result<Head> {
    let born = born_in(vault, txn, entity)?.ok_or(invalid(NO_TEXT))?;
    vault
        .store
        .port_entity_document_pointer_put(txn, entity, &born.pointer)?;
    let mut head = Head {
        entity: entity.to_hex(),
        incarnation: EntityId::now().to_hex(),
        document: entity.to_hex(),
        field: content(),
        generation: 0,
        pending: 0,
        birth_frontier: Some(born.doc.frontier()),
    };
    storage::persist_scanned(vault, txn, entity, &mut head, &born.doc, None, synced(None))?;
    Ok(head)
}

/// The head a peer's document takes here for a MESSAGE that holds none:
/// the document its row names, or, for a row still holding its text, its
/// own id, its row then naming it.
fn carried_head_in_txn(vault: &Vault, txn: &mut RwTxn<'_>, entity: &EntityId) -> Result<Head> {
    let raw = vault
        .store
        .port_entity_raw(txn, entity)?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_MESSAGE {
        return Err(invalid(NO_TEXT));
    }
    let body = &raw[ENTITY_METADATA_HEADER_LEN..];
    let document = match pointer_of(body) {
        Some(document) => document,
        None => {
            let (_, pointer) = split_content(body, entity).ok_or(invalid(NO_TEXT))?;
            vault
                .store
                .port_entity_document_pointer_put(txn, entity, &pointer)?;
            entity.to_hex()
        }
    };
    Ok(Head {
        entity: entity.to_hex(),
        incarnation: EntityId::now().to_hex(),
        document,
        field: content(),
        generation: 0,
        pending: 0,
        birth_frontier: None,
    })
}

/// The document a pointer row's body names, when it names one.
fn pointer_of(mut body: &[u8]) -> Option<String> {
    let rmpv::Value::Map(fields) = rmpv::decode::read_value(&mut body).ok()? else {
        return None;
    };
    fields
        .into_iter()
        .find(|(key, _)| key.as_str() == Some("entity_doc_ref"))
        .and_then(|(_, value)| value.as_str().map(str::to_owned))
}

/// `insert` as the document takes it: admitted as a local write's prose is
/// (FIX 2371), or, where the write door's scan refuses a hit it cannot
/// place, as written, for the sync scan to mark and record (FIX 8872).
fn admitted_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    insert: &str,
    lifted: &LiftedKeys,
) -> Result<Admitted> {
    match admitted_text_in_txn(vault, txn, *entity, insert, lifted, &mut Lifted::default()) {
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. }))
            if reason_codes.first() == Some(&DETECTED) =>
        {
            Ok(Admitted {
                stored: lifted.resolved(insert).unwrap_or_else(|| insert.to_owned()),
                said: insert.to_owned(),
            })
        }
        admitted => admitted,
    }
}

/// `update` as a document of its own, when it is one: it holds every
/// operation it builds on, a birth among them.
fn whole_document(update: &[u8]) -> Option<LoroDoc> {
    let doc = LoroDoc::new();
    doc.import(update)
        .ok()
        .filter(|status| status.pending.is_none())?;
    (!doc.oplog_vv().is_empty()).then_some(doc)
}

fn import_whole(doc: &LoroDoc, bytes: &[u8]) -> Result<()> {
    let status = doc.import(bytes).map_err(|_| invalid("sync text bytes"))?;
    if status.pending.is_some() {
        return Err(invalid("sync text has pending dependencies"));
    }
    Ok(())
}

/// The sync plane's scan of a write's text (FIX 8872, KEEP TODAY), in place
/// of the write door's: `masked` when a copy edit landed from it, else the
/// document's own text. The owner's switch runs it as configured. A hit the
/// lift screened before is marked again, as the door marks it; any other
/// hit goes to custody and is marked where the lift's rules place it, and
/// one they do not place stays, recorded. No hit refuses the write.
fn synced(
    masked: Option<&str>,
) -> impl FnOnce(&Vault, &mut RwTxn<'_>, &EntityId, &Head, &str) -> Result<bool> + '_ {
    move |vault: &Vault, txn: &mut RwTxn<'_>, entity: &EntityId, h: &Head, text: &str| {
        let store = &vault.store;
        let read = masked.unwrap_or(text);
        if scan_content_in_txn(store, txn, read.as_bytes()).is_ok() {
            return Ok(false);
        }
        if masked.is_none()
            && super::lift::screened_in_txn(store, txn, h, text)?.is_some_and(|screened| {
                scan_content_in_txn(store, txn, screened.as_bytes()).is_ok()
            })
        {
            return Ok(true);
        }
        mark_hits_in_txn(vault, txn, entity, read)?;
        Ok(false)
    }
}

/// The sync scan of a text bound for a record's sequence rows: [`synced`]'s,
/// with no document lift to screen it. No hit refuses the write.
fn scan_sequence_text_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    read: &str,
) -> Result<()> {
    if scan_content_in_txn(&vault.store, txn, read.as_bytes()).is_ok() {
        return Ok(());
    }
    mark_hits_in_txn(vault, txn, entity, read)
}

/// Sends each key of `read`, a sync write's text, to custody and marks it
/// where the lift's rules place it; a hit they do not place stays, recorded.
fn mark_hits_in_txn(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    read: &str,
) -> Result<()> {
    if let CarrierText::Unplaceable(reason) =
        mark_carrier_text_in_txn(vault, txn, *entity, PLACE, read.as_bytes())?
    {
        tracing::warn!(
            entity = %entity.to_hex(),
            reason,
            "sync: a document's text keeps a secret hit no rule places; the write stands"
        );
    }
    Ok(())
}
