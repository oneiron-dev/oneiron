//! Actor-bound NOTE editor verbs and atomic entity-document persistence.

use super::document::{
    NoteDocument, NoteDocumentView, NoteEdit, NoteEditOutcome, NotePin, NoteSpanResolution,
    frontier, invalid,
};
use super::pin_index::{NOTE_PIN_CITING, NOTE_PIN_CLAIM, NOTE_PIN_SOURCE};
use super::side_keys::HexHexHash;
use super::{NoteBody, NoteKind, encode_note_body};
use crate::batch::secret_scan::{
    Lifted, Part, SecretScanMode, admit_parts_in_txn, scan_content_in_txn, scan_write_payload,
    secret_scan_mode_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::entity_doc::PurgeReceipt;
use crate::error::Result;
use crate::memory::{EntityRefReceipt, Memory, MemoryError, MemoryResult};
use crate::ports::{DocumentRowStore, DocumentSlot};
use crate::provenance::birth::RowBirth;
use crate::provenance::made_by::MadeByClass;
use crate::registry::{ENTITY_TYPE_CLAIM, ENTITY_TYPE_NOTE};
use crate::side_table::HexId;
use crate::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, WriteActor};

/// The snapshot row's key, for a test that plants one by hand.
#[cfg(test)]
pub(super) fn key(id: EntityId) -> String {
    format!("d:e:{}", id.to_hex())
}

pub(super) fn load(vault: &Vault, txn: &heed::RoTxn<'_>, id: EntityId) -> Result<NoteDocument> {
    let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, &id)?
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

pub(super) fn persist_authoritative(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &NoteDocument,
) -> Result<()> {
    persist_structural(vault, txn, doc, true)?;
    super::title_index::replace_authoritative_document_in_txn(vault, txn, doc)
}

#[cfg(feature = "sync")]
pub(super) fn persist_replica(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &NoteDocument,
) -> Result<()> {
    super::title_index::remove_replica_projection_in_txn(vault, txn, doc.id)?;
    persist_structural(vault, txn, doc, false)
}

#[cfg(feature = "sync")]
pub(super) fn persist_recovered_document(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &NoteDocument,
) -> Result<()> {
    persist_structural(vault, txn, doc, false)
}

/// `masks`: this host's own write, whose live text a mask on write may
/// rewrite. A replica's or a recovered document's text keeps the plain door.
fn persist_structural(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &NoteDocument,
    masks: bool,
) -> Result<()> {
    super::ensure_citations_ready(&vault.store, txn, doc.id)?;
    super::citation_erase::validate_pins(vault, txn, &doc.pins()?)?;
    // The title lands beside the body, in the document and the title index,
    // so it is scanned as the body is, under the same switch, as an import's
    // titles are. So is each citation's quote, which the pin rows below keep:
    // its hash checks it, so no handle can stand in it. Both refuse before
    // the body's secrets are lifted.
    if secret_scan_mode_in_txn(&vault.store, txn)? == SecretScanMode::On {
        if let Some(title) = doc.title()? {
            scan_write_payload(title.as_bytes())?;
        }
        for pin in doc.pins()? {
            scan_write_payload(pin.quote_text.as_bytes())?;
        }
    }
    let masked = admit_body(vault, txn, doc, masks)?;
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
    // A masked document is stored without the history that held the value,
    // as a citation scrub stores one.
    super::storage::snapshot(vault, txn, doc.id, &doc.doc, masked)?;
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

/// The live text as the NOTE stores it (OF-067; ARCH-0069 #mask-on-write),
/// admitted before its snapshot, history, receipt or text index is written.
/// With the owner's switch on, each secret the batch door's text rules place
/// goes to custody and the live text keeps its handle. Without `masks` the
/// text keeps the plain door: its writer owns its bytes, so a hit refuses.
/// Returns whether the text changed.
fn admit_body(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    doc: &NoteDocument,
    masks: bool,
) -> Result<bool> {
    let mut text = doc.view()?.markdown;
    if !masks {
        scan_content_in_txn(&vault.store, txn, text.as_bytes())?;
        return Ok(false);
    }
    let masked = admit_parts_in_txn(
        vault,
        txn,
        doc.id,
        &mut [("text:markdown", Part::Text(&mut text))],
        &mut Lifted::default(),
    )?;
    if masked {
        doc.mask_body(&text)?;
    }
    Ok(masked)
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
        let kind = NoteKind::Plugin("brief".into());
        self.vault()
            .check_auto_note_birth(&kind, self.actor_class(), &markdown)?;
        let id = self.vault().new_entity_id()?;
        let actor = WriteActor::new(self.actor(), self.actor_class());
        let body = encode_note_body(&NoteBody {
            kind,
            author_ref: self.actor(),
            markdown: markdown.clone(),
            source_revision_ref: *id.as_bytes(),
        })?;
        self.with_actor_content_write_txn(|content| {
            if self
                .vault()
                .brief_kind_contract_in_txn(content.read())?
                .is_none()
            {
                return Err(invalid("brief kind is not person-stamped").into());
            }
            let doc = NoteDocument::birth(id, &markdown, &actor)?;
            for pin in pins {
                validate_pin_source(self.vault(), content.read(), pin)?;
                doc.add_pin(pin, &actor)?;
            }
            let now = self.vault().now_recorded_at();
            content.apply_batch(
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
                    .made_by(&id, brief_birth(actor, pins, now)),
            )?;
            content.update_note(id, |txn| {
                super::operations::record_authorship(
                    &doc,
                    &super::NoteAuthorship {
                        operation: self.vault().new_entity_id()?,
                        actor: self.actor(),
                        actor_class: self.actor_class().gate_actor_class().to_owned(),
                        grant: None,
                        command_hash: *blake3::hash(&body).as_bytes(),
                    },
                )?;
                persist_authoritative(self.vault(), txn, &doc)?;
                Ok(())
            })
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
                request_id: self.vault().new_entity_id()?,
                change: super::NoteChange::Cite { pin: pin.clone() },
            },
        )
        .map(|_| ())
    }

    /// Set editable NOTE metadata under the same actor and title gate as socket ops.
    pub fn set_note_title(
        &self,
        note: EntityId,
        title: impl Into<String>,
    ) -> MemoryResult<NoteEditOutcome> {
        Ok(self
            .apply_local_note_operation(
                note,
                &super::NoteOperation {
                    request_id: EntityId::now(),
                    change: super::NoteChange::SetTitle {
                        title: title.into(),
                    },
                },
            )?
            .outcome)
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
                    request_id: self.vault().new_entity_id()?,
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
    /// Discarding history is the ladder's erase (ARCH-0038): an Owner's own
    /// act, so writing the note is not enough.
    pub fn purge_note_history(&self, note: EntityId, through: &[u8]) -> MemoryResult<()> {
        self.purge_note_history_with(None, note, Some(through), None)
            .map(|_| ())
    }

    /// [`Self::purge_note_history`] as `owner`, whose proof is rechecked in the
    /// transaction that commits. Without `through` it erases up to the oldest
    /// pin, or up to the head when nothing pins the note. The receipt lands
    /// beside the entity-text purge receipts. A legal hold on the note refuses
    /// it (OF-470); with two or more live Owners it runs only through the
    /// vault's `erase` veto window ([`Vault::start_text_history_erase`],
    /// Docs Q05).
    pub fn purge_note_history_as(
        &self,
        owner: &AuthenticatedOwner,
        note: EntityId,
        through: Option<&[u8]>,
    ) -> MemoryResult<PurgeReceipt> {
        self.purge_note_history_with(Some(owner), note, through, None)
    }

    /// [`Self::purge_note_history_as`], claiming the completed `erase` act
    /// `act` in its writer.
    pub(crate) fn purge_note_history_for_act(
        &self,
        owner: &AuthenticatedOwner,
        note: EntityId,
        through: Option<&[u8]>,
        act: &str,
    ) -> MemoryResult<PurgeReceipt> {
        self.purge_note_history_with(Some(owner), note, through, Some(act))
    }

    fn purge_note_history_with(
        &self,
        owner: Option<&AuthenticatedOwner>,
        note: EntityId,
        requested: Option<&[u8]>,
        act: Option<&str>,
    ) -> MemoryResult<PurgeReceipt> {
        self.with_actor_content_write_txn(|content| {
            content.update_note(note, |txn| {
                if let Some(owner) = owner
                    && owner.revalidate_in_txn(self.vault(), txn)? != self.actor()
                {
                    return Err(MemoryError::new(
                        crate::memory::MEMORY_CODE_FORBIDDEN,
                        "the owner proof names another actor than this facade",
                        &[],
                    ));
                }
                require_note_writer(self, txn, note)?;
                crate::memory::verify_deletion_authority_in_txn(
                    self.vault(),
                    txn,
                    self.actor(),
                    self.actor_class(),
                )?;
                // A held note keeps its history (OF-470).
                self.vault()
                    .store
                    .reject_legal_hold_in_txn(txn, note.as_bytes())?;
                let receipt_id = self.vault().new_entity_id()?;
                crate::entity_doc::admit_history_erase_in_txn(
                    self.vault(),
                    txn,
                    &note,
                    requested,
                    act,
                    &receipt_id,
                )?;
                let doc = load(self.vault(), txn, note)?;
                let key_prefix = format!("{}:", note.to_hex()).into_bytes();
                let mut pins = Vec::new();
                for (_, pin) in NOTE_PIN_SOURCE.scan_from(&self.vault().store, txn, &key_prefix)? {
                    pin.validate()?;
                    pins.push(frontier(&pin.frontier)?);
                }
                let at_or_before = |a: &loro::Frontiers, b: &loro::Frontiers| {
                    matches!(
                        doc.doc.cmp_frontiers(a, b),
                        Ok(Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal))
                    )
                };
                let through = match requested {
                    Some(bytes) => frontier(bytes)?,
                    None if pins.is_empty() => doc.doc.oplog_frontiers(),
                    None => pins
                        .iter()
                        .find(|oldest| pins.iter().all(|pin| at_or_before(*oldest, pin)))
                        .cloned()
                        .ok_or_else(|| {
                            invalid("NOTE pins are causally incomparable; name a frontier")
                        })?,
                };
                if !pins.iter().all(|pin| at_or_before(&through, pin)) {
                    return Err(invalid("NOTE purge would pass a cited frontier").into());
                }
                let live_text_hash = *blake3::hash(doc.view()?.markdown.as_bytes()).as_bytes();
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
                let applied = through.encode();
                let receipt = PurgeReceipt {
                    receipt: receipt_id.to_hex(),
                    entity: note.to_hex(),
                    document: slot.to_hex(),
                    actor: self.actor().to_hex(),
                    requested: requested.map_or_else(|| applied.clone(), <[u8]>::to_vec),
                    applied,
                    at: self.vault().now_recorded_at(),
                    live_text_hash,
                };
                self.vault()
                    .put_text_purge_receipt_in_txn(txn, &note, receipt_id, &receipt)?;
                Ok(receipt)
            })
        })
    }
}

/// A brief is made from the claims and NOTEs its pins cite, read as their
/// quoted text. An agent's brief that cites nothing has no birth to name.
fn brief_birth(actor: WriteActor, pins: &[NotePin], at: u64) -> Option<RowBirth> {
    let cited: Vec<EntityId> = pins
        .iter()
        .flat_map(|pin| [pin.claim, pin.document])
        .collect();
    let quotes: Vec<&[u8]> = pins.iter().map(|pin| pin.quote_text.as_bytes()).collect();
    RowBirth::written(
        actor,
        MadeByClass::of_writer(actor.actor_class()),
        "note.author_brief",
        &cited,
        &quotes,
        at,
    )
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
