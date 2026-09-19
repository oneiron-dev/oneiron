//! Actor-bound NOTE editor verbs and atomic entity-document persistence.

use super::document::{
    NoteDocument, NoteDocumentView, NoteEdit, NoteEditOutcome, NotePin, NoteSpanResolution,
    frontier, invalid,
};
use super::{NoteBody, NoteKind, decode_note_body, encode_note_body};
use crate::error::Result;
use crate::memory::{EntityRefReceipt, Memory, MemoryError, MemoryResult};
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE};
use crate::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, WriteActor};

pub(super) fn key(id: EntityId) -> String {
    format!("d:e:{}", id.to_hex())
}
fn pin_prefix(id: EntityId) -> String {
    format!("note.pin/source/{}:", id.to_hex())
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
    decode_note_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
    let doc = crate::sync::documents::storage::load(vault, txn, id)?;
    NoteDocument::from_loro(id, doc)
}

pub(super) fn persist(vault: &Vault, txn: &mut heed::RwTxn<'_>, doc: &NoteDocument) -> Result<()> {
    super::ensure_citations_ready(&vault.store, txn, doc.id)?;
    super::citation_erase::validate_pins(vault, txn, &doc.pins()?)?;
    // Keep the live three-key projection valid, including after concurrent
    // batches merge. A refused commit leaves the durable document unchanged.
    let markdown = doc.view()?.markdown;
    super::validate_markdown(&markdown)?;
    if markdown.len() > super::document::MAX_NOTE_BYTES {
        return Err(invalid("NOTE body exceeds bound"));
    }
    if doc.snapshot()?.len() > crate::sync::transport::MAX_DECODED_PAYLOAD_BYTES - 18 {
        return Err(invalid("NOTE snapshot exceeds wire bound"));
    }
    crate::sync::documents::storage::snapshot(vault, txn, doc.id, &doc.doc, false)?;
    // Reverse pins preserve every cited source frontier, including when the
    // citation is in a different document. They are written with the body.
    super::pin_index::remove_citing(&vault.store, txn, doc.id)?;
    for pin in doc.pins()? {
        let value = serde_json::to_vec(&pin).map_err(|_| invalid("NOTE pin encode"))?;
        let index = format!(
            "{}{}:{}",
            pin_prefix(pin.document),
            doc.id.to_hex(),
            blake3::hash(&value).to_hex()
        );
        vault.store.vault_meta.put(txn, index.as_bytes(), &value)?;
        let claim_index = format!(
            "note.pin/claim/{}:{}:{}",
            pin.claim.to_hex(),
            doc.id.to_hex(),
            blake3::hash(&value).to_hex()
        );
        vault
            .store
            .vault_meta
            .put(txn, claim_index.as_bytes(), index.as_bytes())?;
        let citing = format!(
            "note.pin/citing/{}:{}:{}",
            doc.id.to_hex(),
            pin.document.to_hex(),
            blake3::hash(&value).to_hex()
        );
        vault
            .store
            .vault_meta
            .put(txn, citing.as_bytes(), index.as_bytes())?;
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
            for row in self
                .vault()
                .store
                .vault_meta
                .prefix_iter(txn, pin_prefix(note).as_bytes())?
            {
                let (_, bytes) = row?;
                let pin: NotePin = serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("NOTE reverse pin corrupt"))?;
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
            crate::sync::documents::storage::snapshot(
                self.vault(),
                txn,
                note,
                &shallow.doc,
                false,
            )?;
            self.vault().store.sync_state.put(
                txn,
                &format!("ssv:e:{}", note.to_hex()),
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
    let doc = match source.doc.fork_at(&frontier(&pin.frontier)?) {
        Ok(doc) => doc,
        Err(_) if matches!(source.resolve(pin)?, NoteSpanResolution::Mapped { .. }) => {
            return Ok(());
        }
        Err(_) => return Err(invalid("citation frontier unavailable")),
    };
    if !matches!(
        (NoteDocument {
            doc,
            id: pin.document
        })
        .resolve(pin)?,
        NoteSpanResolution::Mapped { .. }
    ) {
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
    let raw = memory
        .vault()
        .store
        .entities
        .get(txn, id.as_bytes())?
        .ok_or(crate::Error::EntityNotFound)?;
    let body = raw
        .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
        .ok_or_else(|| invalid("NOTE header missing"))?;
    let body = decode_note_body(body)?;
    if body.author_ref != memory.actor() {
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
