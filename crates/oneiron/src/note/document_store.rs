//! Actor-bound NOTE editor verbs and atomic entity-document persistence.

use super::document::{
    NoteDocument, NoteDocumentView, NoteEdit, NoteEditOutcome, NotePin, NoteSpanResolution,
    frontier, invalid,
};
use super::pin_index::{NOTE_PIN_CITING, NOTE_PIN_CLAIM, NOTE_PIN_SOURCE};
use super::side_keys::HexHexHash;
use super::{NoteBody, NoteKind, encode_note_body};
use crate::error::Result;
use crate::memory::{EntityRefReceipt, Memory, MemoryError, MemoryResult};
use crate::ports::{DocumentRowStore, DocumentSlot};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE};
use crate::side_table::HexId;
use crate::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, WriteActor};

pub(super) fn key(id: EntityId) -> String {
    format!("d:e:{}", id.to_hex())
}

pub(super) fn load(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<NoteDocument> {
    let raw = vault
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(crate::Error::EntityNotFound)?;
    let header = crate::batch::EntityMetadataHeader::parse(&raw)
        .ok_or_else(|| invalid("NOTE entity header"))?;
    if header.entity_type != ENTITY_TYPE_NOTE {
        return Err(invalid("entity is not a NOTE"));
    }
    if vault.local_hard_delete_marker_exists_in_txn(txn, &id)? {
        return Err(invalid("NOTE was erased"));
    }
    super::verbs::note_core(vault, txn, id)?;
    let doc = super::storage::load(vault, txn, id)?;
    NoteDocument::from_loro(id, doc)
}

pub(super) fn persist(vault: &Vault, txn: &mut heed::RwTxn<'_>, doc: &NoteDocument) -> Result<()> {
    super::ensure_citations_ready(&vault.store, txn, doc.id)?;
    super::citation_erase::validate_pins(vault, txn, &doc.pins()?)?;
    // Keep the live NOTE projection valid, including after concurrent
    // batches merge. A refused commit leaves the durable document unchanged.
    let markdown = doc.view()?.markdown;
    super::validate_markdown(&markdown)?;
    if markdown.len() > super::document::MAX_NOTE_BYTES {
        return Err(invalid("NOTE body exceeds bound"));
    }
    if doc.snapshot()?.len() > super::operations::MAX_RECEIPT_PAYLOAD - 18 {
        return Err(invalid("NOTE snapshot exceeds wire bound"));
    }
    super::storage::snapshot(vault, txn, doc.id, &doc.doc, false)?;
    vault
        .batch_in()
        .text(&doc.id, &[("markdown", markdown.as_str())])
        .apply(txn)?;
    // Reverse pins preserve every cited source frontier, including when the
    // citation is in a different document. They are written with the body.
    super::pin_index::remove_citing(&vault.store, txn, doc.id)?;
    for pin in doc.pins()? {
        let value = NOTE_PIN_SOURCE.encode_value(&pin)?;
        let hash = blake3::hash(&value).to_hex().to_string();
        let index = HexHexHash(HexId(pin.document), HexId(doc.id), hash.clone());
        let index_bytes = NOTE_PIN_SOURCE.key_bytes(&index);
        NOTE_PIN_SOURCE.put(&vault.store, txn, &index, &pin)?;
        let claim_index = HexHexHash(HexId(pin.claim), HexId(doc.id), hash.clone());
        NOTE_PIN_CLAIM.put(&vault.store, txn, &claim_index, &index_bytes)?;
        let citing = HexHexHash(HexId(doc.id), HexId(pin.document), hash);
        NOTE_PIN_CITING.put(&vault.store, txn, &citing, &index_bytes)?;
    }
    Ok(())
}

impl Vault {
    /// Host-level access to live markdown and pins, like `Vault::get`.
    /// Viewer-facing code must use the scope-checked brief/lens render doors.
    pub fn note_document(&self, id: EntityId) -> Result<NoteDocumentView> {
        let txn = self.store.env.read_txn()?;
        load(self, &txn, id)?.view()
    }

    pub fn pin_note_span(
        &self,
        document: EntityId,
        claim: EntityId,
        start: usize,
        end: usize,
    ) -> Result<NotePin> {
        let txn = self.store.env.read_txn()?;
        if self.get_entity_type_in_txn(&txn, &claim)? != Some(ENTITY_TYPE_CLAIM) {
            return Err(invalid("citation target is not a CLAIM"));
        }
        let pin = load(self, &txn, document)?.pin(claim, start, end)?;
        super::citation_erase::validate_pins(self, &txn, std::slice::from_ref(&pin))?;
        Ok(pin)
    }

    pub fn resolve_note_pin(&self, pin: &NotePin) -> Result<NoteSpanResolution> {
        let txn = self.store.env.read_txn()?;
        super::citation_erase::validate_pins(self, &txn, std::slice::from_ref(pin))?;
        load(self, &txn, pin.document)?.resolve(pin)
    }
}

impl Memory<'_> {
    /// An agent-composed brief uses the pack's person-stamped contract. Its
    /// markdown and citations live in the vault, never behind an opaque URL.
    pub fn author_brief(
        &self,
        markdown: impl Into<String>,
        pins: &[NotePin],
    ) -> MemoryResult<EntityRefReceipt> {
        let markdown = markdown.into();
        let id = EntityId::now();
        let actor = WriteActor::new(self.actor(), self.actor_class());
        let body = encode_note_body(&NoteBody {
            kind: NoteKind::Plugin("brief".into()),
            author_ref: self.actor(),
            markdown: markdown.clone(),
            source_revision_ref: *id.as_bytes(),
        })?;
        self.with_verified_actor_write_txn(|txn| {
            if self.vault().brief_kind_contract_in_txn(txn)?.is_none() {
                return Err(invalid("brief kind is not person-stamped").into());
            }
            let doc = NoteDocument::birth(id, &markdown, &actor)?;
            for pin in pins {
                validate_pin_source(self.vault(), txn, pin)?;
                doc.add_pin(pin, &actor)?;
            }
            let now = crate::unix_seconds_now();
            self.vault()
                .batch_in()
                .put_authored_note(
                    &id,
                    &self.actor(),
                    TimeRange {
                        start: now,
                        end: now,
                    },
                    now,
                    &body,
                )
                .edge(&id, EdgeKind::AuthoredBy, &self.actor(), 1.0)
                .apply(txn)?;
            super::operations::record_authorship(
                &doc,
                &super::NoteAuthorship {
                    operation: EntityId::now(),
                    actor: self.actor(),
                    actor_class: self.actor_class().gate_actor_class().to_owned(),
                    grant: None,
                    command_hash: *blake3::hash(&body).as_bytes(),
                },
            )?;
            persist(self.vault(), txn, &doc)?;
            Ok(())
        })?;
        #[cfg(feature = "sync")]
        self.vault().notify_note_document(id);
        self.entity_ref_receipt(&id)
    }

    /// Adds an authenticated claim citation to this NOTE. Stable cursor data is
    /// checked against its actual pinned document before it enters the vault.
    pub fn cite_note_span(&self, note: EntityId, pin: &NotePin) -> MemoryResult<()> {
        self.apply_local_note_operation(
            note,
            &super::NoteOperation {
                request_id: EntityId::now(),
                change: super::NoteChange::Cite { pin: pin.clone() },
            },
        )
        .map(|_| ())
    }

    /// Free prose commits now. Cited spans go through the reviewed claim door.
    pub fn apply_note_ops(
        &self,
        note: EntityId,
        base: &[u8],
        edits: &[NoteEdit],
    ) -> MemoryResult<NoteEditOutcome> {
        Ok(self
            .apply_local_note_operation(
                note,
                &super::NoteOperation {
                    request_id: EntityId::now(),
                    change: super::NoteChange::Edit {
                        base: base.to_vec(),
                        edits: edits.to_vec(),
                    },
                },
            )?
            .outcome)
    }

    /// Compact only through a frontier no citation needs. Fail closed rather
    /// than silently dropping the history that makes a quote checkable.
    pub fn purge_note_history(&self, note: EntityId, through: &[u8]) -> MemoryResult<()> {
        self.with_verified_actor_write_txn(|txn| {
            require_note_writer(self, txn, note)?;
            let doc = load(self.vault(), txn, note)?;
            let through = frontier(through)?;
            let key_prefix = format!("{}:", note.to_hex()).into_bytes();
            for (_, pin) in NOTE_PIN_SOURCE.scan_from(&self.vault().store, txn, &key_prefix)? {
                pin.validate()?;
                match doc.doc.cmp_frontiers(&through, &frontier(&pin.frontier)?) {
                    Ok(Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)) => {}
                    _ => return Err(invalid("NOTE purge would pass a cited frontier").into()),
                }
            }
            let snapshot = doc
                .doc
                .export(loro::ExportMode::shallow_snapshot(&through))
                .map_err(|_| invalid("NOTE history purge failed"))?;
            let shallow = NoteDocument::load(note, &snapshot)?;
            super::storage::snapshot(self.vault(), txn, note, &shallow.doc, false)?;
            let slot = DocumentSlot::of(super::storage::slot(self.vault(), txn, note)?);
            self.vault().store.port_document_shallow_since_put(
                txn,
                slot,
                &shallow.doc.shallow_since_vv().to_vv().encode(),
            )?;
            Ok(())
        })
    }
}

pub(super) fn validate_pin_source(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    pin: &NotePin,
) -> Result<()> {
    pin.validate()?;
    super::citation_erase::validate_pins(vault, txn, std::slice::from_ref(pin))?;
    if vault.get_entity_type_in_txn(txn, &pin.claim)? != Some(ENTITY_TYPE_CLAIM) {
        return Err(invalid("citation target is not a CLAIM"));
    }
    let source = load(vault, txn, pin.document)?;
    // Admission proves the claimed source version, not merely that the same
    // quote happens to be present now. The live-fork path is limited to an
    // exact current frontier, including after an erasure rebuild.
    let source = source.fork_at(&pin.frontier)?;
    if !matches!(source.resolve(pin)?, NoteSpanResolution::Mapped { .. }) {
        return Err(invalid("citation quote does not match its source frontier"));
    }
    Ok(())
}

pub(super) fn require_note_writer(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> MemoryResult<()> {
    if memory
        .vault()
        .local_hard_delete_marker_exists_in_txn(txn, &id)?
    {
        return Err(invalid("NOTE was erased").into());
    }
    let (_, body) = super::verbs::note_core(memory.vault(), txn, id)?;
    if body.author_ref != memory.actor()
        && !super::proposals::automatic_edit_grant(
            memory.vault(),
            txn,
            id,
            crate::WriteActor::new(memory.actor(), memory.actor_class()),
        )?
    {
        if memory.actor_class() != EdgeActorClass::Human {
            return Err(MemoryError::bad_request_with(
                "NOTE edit requires its author or a bound owner",
                &[],
            ));
        }
        crate::memory::verify_owner_actor_binding_in_txn(memory.vault(), txn, memory.actor())?;
    }
    Ok(())
}
