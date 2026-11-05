//! A private scratch candidate for the selected record/document transport.
//!
//! Preparation joins the actual current local document before projecting its
//! record body. This is data for ordinary admission, not permission to persist.

use heed::RwTxn;
use loro::VersionVector;

use super::CarriedRecordDocument;
use crate::EntityId;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_doc::carried::{CarriedDocument, DocumentMerge};
use crate::entity_doc::storage::{self, ENTITY_DOC_HEAD, Head};
use crate::entity_doc::{EntityDoc, invalid};
use crate::error::{Error, Result};
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot, EntityStoreRead, UpdateSeq};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::side_table::HexId;
use crate::sync::SelectedRecordDocument;

mod install;
pub(super) use install::{
    AdmittedRecordDocument, InstalledRecordDocument, PendingRecordDocument,
    install_record_document_in_txn,
};

/// A preparation that wrote neither the pointer nor its document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RecordDocumentStand {
    Conflict,
    Refused(&'static str),
}

pub(crate) enum RecordDocumentPreparation<'selected, 'carrier> {
    Candidate(RecordDocumentCandidate<'selected, 'carrier>),
    /// The selected import returned or another import is current now.
    TransportEnded,
    /// The local native head stands; no pointer or document was written.
    Stands(RecordDocumentStand),
}

/// Both record views, read and joined in one actual applying writer.
/// No constructor accepts arbitrary logical bytes, an actor or a permission.
pub(crate) struct RecordDocumentCandidate<'selected, 'carrier> {
    selected: &'selected SelectedRecordDocument<'carrier>,
    prior_raw: Option<Vec<u8>>,
    prior_head: Option<Vec<u8>>,
    prior_documents: Vec<(DocumentSlot, [u8; 32])>,
    prior_logical: Option<Vec<u8>>,
    local_snapshot: Option<Vec<u8>>,
    logical: Vec<u8>,
    head: Head,
    document: EntityDoc,
    before: Option<VersionVector>,
    left_document: Option<String>,
    deferred_purge: Option<DocumentMerge>,
    native_sources: super::native_sources::NativeSourceReview,
}

impl<'selected, 'carrier> RecordDocumentCandidate<'selected, 'carrier> {
    pub(crate) fn prepare_in_txn(
        selected: &'selected SelectedRecordDocument<'carrier>,
        txn: &mut RwTxn<'_>,
    ) -> Result<RecordDocumentPreparation<'selected, 'carrier>> {
        let vault = selected.vault();
        let store = &vault.store;
        if !selected.recheck_transport_in_txn(store, txn)? {
            return Ok(RecordDocumentPreparation::TransportEnded);
        }
        let source = selected.head();
        if source.refinement_origin().is_some() && selected.refinement_source().is_none() {
            return Ok(RecordDocumentPreparation::Stands(
                RecordDocumentStand::Conflict,
            ));
        }
        let entity = source.entity()?;
        if crate::ports::removed_in_txn(store, txn, &entity)? {
            return Ok(RecordDocumentPreparation::Stands(
                RecordDocumentStand::Refused("erased here"),
            ));
        }
        let incoming = source.document(selected.raw(), selected.snapshot())?;
        let incoming_inventory =
            crate::entity_doc::native_skill_state::inspect_inventory(&incoming)?;
        let prior_raw = store.port_entity_raw(txn, &entity)?.map(|raw| raw.to_vec());
        let prior_head = storage::record_head_bytes(store, txn, &entity)?;
        let local = ENTITY_DOC_HEAD.get(store, txn, &HexId(entity))?;
        // Even an absent head has physical slots: sequence rows may appear
        // after preparation in this same writer. A Switch also names its
        // destination independently of the old head's slot.
        let mut slots = vec![DocumentSlot::of(entity)];
        let destination = DocumentSlot::from_hex(&source.native().document)?;
        if !slots.contains(&destination) {
            slots.push(destination);
        }
        if let Some(head) = &local {
            let held = storage::document_slot(head)?;
            if !slots.contains(&held) {
                slots.push(held);
            }
        }
        let mut prior_documents = slots
            .into_iter()
            .map(|slot| Ok((slot, document_rows_digest(store, txn, slot)?)))
            .collect::<Result<Vec<_>>>()?;
        let mut local_snapshot = None;
        let (head, document, before, left_document, deferred_purge, prior_logical) = match local {
            None => {
                // An unheaded BODY is independent text, never retrospectively
                // bound to the sender's map field. Keep its real sequence route
                // and choose separate physical storage if the native id is used.
                let sequence_document = store
                    .port_document_present(txn, DocumentSlot::of(entity))?
                    .then(|| entity.to_hex());
                let storage_document =
                    storage::free_document_storage(store, txn, &source.native().document)?;
                // No native head is not a claim that the revision ledger
                // is empty. Its actual generic bindings remain untouched.
                let prior_logical = prior_raw.as_ref().and_then(|raw| {
                    EntityMetadataHeader::parse(raw)
                        .filter(|header| header.entity_type == ENTITY_TYPE_SKILL)
                        .map(|_| raw[ENTITY_METADATA_HEADER_LEN..].to_vec())
                });
                let native = source.native();
                let head = Head {
                    entity: native.entity.clone(),
                    incarnation: native.incarnation.clone(),
                    document: native.document.clone(),
                    storage_document,
                    sequence_document,
                    field: source.field().clone(),
                    generation: 0,
                    pending: 0,
                    // The sender's birth frontier stays separate source
                    // evidence, never a local birth of this carried doc.
                    birth_frontier: None,
                };
                (head, incoming, None, None, None, prior_logical)
            }
            Some(mut head) => {
                let raw = prior_raw
                    .as_deref()
                    .ok_or(Error::CorruptedIndex("record document head without entity"))?;
                let header = EntityMetadataHeader::parse(raw)
                    .ok_or(Error::CorruptedIndex("record document owner header"))?;
                if header.entity_type != ENTITY_TYPE_SKILL || head.entity != entity.to_hex() {
                    return Err(Error::CorruptedIndex("record document owner mismatch"));
                }
                let native = source.native();
                if head.incarnation != native.incarnation || head.field != *source.field() {
                    return Ok(RecordDocumentPreparation::Stands(
                        RecordDocumentStand::Conflict,
                    ));
                }
                // Updates may carry a birth projection too. Read the birth
                // from the fully replayed document, not its snapshot's cache.
                let document = EntityDoc::from_loro(storage::load(store, txn, &head)?.doc)?;
                crate::entity_doc::metadata::require_retained_record_metadata(
                    &document,
                    &head.field,
                )?;
                if document.birth().entity != head.entity {
                    return Err(Error::CorruptedIndex("record document birth owner"));
                }
                let prior_logical = Some(storage::body_with_document(
                    &head.field,
                    &raw[ENTITY_METADATA_HEADER_LEN..],
                    &document,
                )?);
                let held = local_native(&head, &document);
                let switched = native.replaces(&held);
                if head.document != native.document && !switched {
                    return Ok(RecordDocumentPreparation::Stands(
                        RecordDocumentStand::Conflict,
                    ));
                }
                // Preserve the ordinary owned-row identity check. Only
                // the actual Switch may change its pointer spelling.
                if raw.get(..ENTITY_METADATA_HEADER_LEN)
                    != selected.raw().get(..ENTITY_METADATA_HEADER_LEN)
                    || !same_pointer_body(raw, selected.raw(), switched, &native.document)?
                {
                    return Ok(RecordDocumentPreparation::Stands(
                        RecordDocumentStand::Refused("record core differs from its native head"),
                    ));
                }
                if document.birth().at != incoming.birth().at {
                    return Ok(RecordDocumentPreparation::Stands(
                        RecordDocumentStand::Refused("record document birth differs"),
                    ));
                }
                if switched && !shares_switch_base(native, &document, &incoming) {
                    return Ok(RecordDocumentPreparation::Stands(
                        RecordDocumentStand::Conflict,
                    ));
                }
                // Preserve the actual local retained operations before join
                // or purge. A version vector and the current logical body
                // cannot stand in for these source inputs later.
                local_snapshot = Some(document.export_snapshot()?);
                let before = document.doc.oplog_vv();
                if !document
                    .doc
                    .import(selected.snapshot())
                    .is_ok_and(|status| status.pending.is_none())
                {
                    return Ok(RecordDocumentPreparation::Stands(
                        RecordDocumentStand::Refused(
                            "snapshot does not join this vault's document",
                        ),
                    ));
                }
                let document = EntityDoc::from_loro(document.doc)?;
                super::retained::require_retained_extension(&incoming, &document)?;
                let local = EntityDoc::from_snapshot(
                    local_snapshot
                        .as_deref()
                        .ok_or(invalid("local document snapshot"))?,
                )?;
                super::retained::require_retained_extension(&local, &document)?;
                crate::entity_doc::metadata::require_retained_record_metadata(
                    &document,
                    &head.field,
                )?;
                if document.birth().entity != head.entity
                    || document.birth().at != incoming.birth().at
                {
                    return Ok(RecordDocumentPreparation::Stands(
                        RecordDocumentStand::Refused("record document birth differs"),
                    ));
                }
                let mut deferred_purge = None;
                let document = if !switched && native.purges(&held) {
                    match crate::entity_doc::carried::purged_at_carried_floor(
                        vault, txn, &entity, &head, &document, native, &incoming,
                    )? {
                        Ok(shallow) => shallow,
                        Err(waits) => {
                            // As on the existing carried-document path,
                            // a deferred purge does not discard joined ops.
                            deferred_purge = Some(waits);
                            document
                        }
                    }
                } else {
                    document
                };
                let left = if switched {
                    let previous = storage::document_slot(&head)?.to_hex();
                    head.storage_document =
                        storage::free_document_storage(store, txn, &native.document)?;
                    head.document = native.document.clone();
                    Some(previous)
                } else {
                    None
                };
                (
                    head,
                    document,
                    Some(before),
                    left,
                    deferred_purge,
                    prior_logical,
                )
            }
        };
        let destination = storage::document_slot(&head)?;
        if !prior_documents.iter().any(|(slot, _)| *slot == destination) {
            prior_documents.push((destination, document_rows_digest(store, txn, destination)?));
        }
        if let Some(local) = local_snapshot.as_deref() {
            let local = EntityDoc::from_snapshot(local)?;
            let local = crate::entity_doc::native_skill_state::inspect_inventory(&local)?;
            // This scratch selection is still data for the original phases.
            // Only their closed source continuation may publish the result.
            crate::entity_doc::native_skill_state::reconcile_settlement(
                &document,
                &local,
                &incoming_inventory,
            )?;
        }
        let logical = storage::body_with_document(
            source.field(),
            &selected.raw()[ENTITY_METADATA_HEADER_LEN..],
            &document,
        )?;
        crate::skill::decode_skill_record(&logical)?;
        let native_sources = super::native_sources::review_in_txn(
            vault,
            txn,
            source,
            selected.raw(),
            selected.snapshot(),
            selected.refinement_source(),
            prior_raw
                .as_deref()
                .zip(prior_head.as_deref())
                .zip(local_snapshot.as_deref())
                .map(|((raw, head), snapshot)| (raw, head, snapshot)),
            (&head, &document),
        )?;
        Ok(RecordDocumentPreparation::Candidate(Self {
            selected,
            prior_raw,
            prior_head,
            prior_documents,
            prior_logical,
            local_snapshot,
            logical,
            head,
            document,
            before,
            left_document,
            deferred_purge,
            native_sources,
        }))
    }

    /// Recheck before ordinary staging, not against a previously returned
    /// import or a head another operation replaced in this same writer.
    pub(crate) fn recheck_in_txn(&self, txn: &mut RwTxn<'_>) -> Result<bool> {
        self.recheck_with_row_in_txn(txn, self.prior_raw.as_deref())
    }

    /// After the ordinary put staged its original physical row, but before
    /// installing the native document. The pre-put row may have been absent;
    /// only this selected transport's exact row is expected now. This checks
    /// data binding, not recipient admission or permission to install.
    pub(crate) fn recheck_staged_in_txn(&self, txn: &mut RwTxn<'_>) -> Result<bool> {
        self.recheck_with_row_in_txn(txn, Some(self.selected.raw()))
    }

    fn recheck_with_row_in_txn(
        &self,
        txn: &mut RwTxn<'_>,
        expected_raw: Option<&[u8]>,
    ) -> Result<bool> {
        let store = &self.selected.vault().store;
        if !self.selected.recheck_transport_in_txn(store, txn)? {
            return Ok(false);
        }
        let entity = self.selected.head().entity()?;
        if store.port_entity_raw(txn, &entity)?.as_deref() != expected_raw
            || storage::record_head_bytes(store, txn, &entity)? != self.prior_head
        {
            return Ok(false);
        }
        // Erasure and retained-history writes, including new unheaded
        // sequence rows, need not change the encoded head or logical text.
        for (slot, prior) in &self.prior_documents {
            if document_rows_digest(store, txn, *slot)? != *prior {
                return Ok(false);
            }
        }
        self.native_sources
            .recheck_in_txn(self.selected.vault(), txn)
    }

    /// Apply the sync text law to this joined candidate using only the
    /// actual current local head's lift evidence. This scans and marks text;
    /// it does not admit a native operation or install either record view.
    pub(crate) fn scan_native_text_in_txn(
        &self,
        store: &crate::store::Store,
        txn: &mut RwTxn<'_>,
    ) -> Result<()> {
        if store.env.path() != self.selected.vault().store.env.path()
            || !self.recheck_in_txn(txn)?
        {
            return Err(Error::InvariantViolation(
                "record document candidate changed before text scan",
            ));
        }
        let prior = self
            .prior_head
            .as_deref()
            .map(storage::decode::<Head>)
            .transpose()?;
        let text = zeroize::Zeroizing::new(self.document.text());
        let vault = self.selected.vault();
        let entity = self.entity()?;
        if crate::entity_doc::sync::scan_synced_text_in_txn(
            vault,
            txn,
            &entity,
            prior.as_ref(),
            &text,
            None,
        )? {
            // The enclosing writer rolls this mark back with any refused
            // record phase, as it does the sync scan's other custody writes.
            crate::entity_doc::lift::remark_entity_text_in_txn(vault, txn, &entity, &text)?;
        }
        Ok(())
    }

    pub(crate) fn applies_to(
        &self,
        store: &crate::store::Store,
        entity: &EntityId,
        data: &[u8],
    ) -> bool {
        std::ptr::eq(store, &self.selected.vault().store)
            && self.entity().is_ok_and(|selected| selected == *entity)
            && self.logical_body() == data
    }

    pub(crate) fn applying_store(&self) -> &crate::store::Store {
        &self.selected.vault().store
    }

    pub(crate) fn entity(&self) -> Result<EntityId> {
        self.selected.head().entity()
    }

    pub(crate) fn physical_raw(&self) -> &[u8] {
        self.selected.raw()
    }

    pub(crate) fn logical_body(&self) -> &[u8] {
        &self.logical
    }

    /// The local logical body BEFORE the incoming operations joined, never
    /// the updated final record returned as an overwrite's prior.
    pub(crate) fn logical_prior_body(&self) -> Option<&[u8]> {
        self.prior_logical.as_deref()
    }

    pub(crate) fn source(&self) -> &CarriedRecordDocument {
        self.selected.head()
    }

    /// Exact incoming retained bytes, still bound to the selected transport.
    /// Decoding these bytes supplies data, not native write permission.
    pub(crate) fn source_snapshot(&self) -> &[u8] {
        self.selected.snapshot()
    }

    /// Historical exact bytes bound to this selected import. Shape and hash
    /// do not admit them or create a receiver's permanent origin.
    pub(crate) fn refinement_source(&self) -> Option<&super::RefinementOriginSource> {
        self.selected.refinement_source()
    }

    /// The actual local snapshot BEFORE join or purge, with all of its
    /// retained operations. An absent local head supplies no native snapshot.
    pub(crate) fn local_snapshot(&self) -> Option<&[u8]> {
        self.local_snapshot.as_deref()
    }

    pub(crate) fn local_head_bytes(&self) -> Option<&[u8]> {
        self.prior_head.as_deref()
    }

    pub(super) fn native_sources(&self) -> &super::native_sources::NativeSourceReview {
        &self.native_sources
    }

    /// A copy for retained-schema/source/secret admission. The caller gets
    /// no interior-mutable handle to this candidate's joined document.
    pub(crate) fn joined_snapshot(&self) -> Result<Vec<u8>> {
        self.document.export_snapshot()
    }
}

fn local_native(head: &Head, document: &EntityDoc) -> CarriedDocument {
    CarriedDocument {
        entity: head.entity.clone(),
        document: head.document.clone(),
        incarnation: head.incarnation.clone(),
        version: document.doc.oplog_vv().encode(),
        shallow: if document.doc.is_shallow() {
            document.doc.shallow_since_vv().to_vv().encode()
        } else {
            Vec::new()
        },
        switched: None,
    }
}

fn shares_switch_base(native: &CarriedDocument, local: &EntityDoc, incoming: &EntityDoc) -> bool {
    native
        .switched
        .as_ref()
        .and_then(|from| crate::entity_doc::document::decode_frontier(&from.base).ok())
        .is_some_and(|base| {
            incoming.doc.frontiers_to_vv(&base).is_some()
                && (local.doc.frontiers_to_vv(&base).is_some()
                    || incoming.doc.oplog_vv().includes_vv(&local.doc.oplog_vv()))
        })
}

fn same_pointer_body(old: &[u8], incoming: &[u8], switched: bool, document: &str) -> Result<bool> {
    let old = &old[ENTITY_METADATA_HEADER_LEN..];
    let incoming = &incoming[ENTITY_METADATA_HEADER_LEN..];
    if !switched {
        return Ok(old == incoming);
    }
    let mut cursor = old;
    let rmpv::Value::Map(mut fields) = rmpv::decode::read_value(&mut cursor)
        .map_err(|_| Error::CorruptedIndex("document pointer row"))?
    else {
        return Err(Error::CorruptedIndex("document pointer row"));
    };
    let mut pointers = fields
        .iter_mut()
        .filter(|(key, _)| key.as_str() == Some("entity_doc_ref"));
    let (_, pointer) = pointers.next().ok_or(invalid("document pointer missing"))?;
    *pointer = rmpv::Value::from(document);
    if !cursor.is_empty() || pointers.next().is_some() {
        return Err(Error::CorruptedIndex("document pointer row"));
    }
    let mut moved = Vec::new();
    rmpv::encode::write_value(&mut moved, &rmpv::Value::Map(fields))
        .map_err(|_| invalid("document pointer encoding"))?;
    Ok(moved == incoming)
}

/// Fingerprint the actual stored rows, not a re-encoded Loro snapshot. No
/// token, source authority or durable format is made from this local read.
fn document_rows_digest(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    slot: DocumentSlot,
) -> Result<[u8; 32]> {
    let mut digest = blake3::Hasher::new();
    for row in DocumentRow::ALL {
        let bytes = store.port_document_row(txn, slot, row)?;
        digest_bytes(&mut digest, bytes.as_deref());
    }
    for update in store.port_document_updates(txn, slot)? {
        match update
            .seq
            .ok_or(Error::CorruptedIndex("document update key"))?
        {
            UpdateSeq::Sequence(sequence) => {
                digest.update(&[0]);
                digest.update(&sequence.to_be_bytes());
            }
            UpdateSeq::Generation(generation) => {
                digest.update(&[1]);
                digest.update(&generation.to_be_bytes());
            }
        }
        digest_bytes(&mut digest, Some(&update.bytes));
    }
    Ok(*digest.finalize().as_bytes())
}

fn digest_bytes(digest: &mut blake3::Hasher, bytes: Option<&[u8]>) {
    match bytes {
        None => {
            digest.update(&[0]);
        }
        Some(bytes) => {
            digest.update(&[1]);
            digest.update(&bytes.len().to_be_bytes());
            digest.update(bytes);
        }
    }
}
