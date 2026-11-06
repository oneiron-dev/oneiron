//! Host-local history-free recovery of uncited NOTE values.
use std::collections::BTreeMap;

use super::document::{NoteDocument, invalid};
#[cfg(feature = "sync")]
use super::sync_rows::{NOTE_RECEIPT_BY_REQUEST, SYNC_AD_E, SYNC_NC_E, SYNC_QD_E};
use super::sync_rows::{SYNC_DS_E, SYNC_QN_E};
#[cfg(feature = "sync")]
use crate::ports::{DocumentRow, DocumentRowStore, DocumentSlot};
use crate::side_table::HexId;
use crate::{EntityId, Result, Vault};

/// `metadata`: every editable field the value carries, each one value in
/// the common encoding (FIX 7784).
pub(crate) fn rebuild(
    note: EntityId,
    text: &str,
    metadata: &BTreeMap<String, Vec<u8>>,
    authorship: &[super::NoteAuthorship],
) -> Result<loro::LoroDoc> {
    super::validate_markdown(text)?;
    let doc = super::documents::proposal_value(note, text, metadata)?;
    let mut previous = None;
    for record in authorship {
        if previous.is_some_and(|id| id >= record.operation) {
            return Err(invalid("recovery authorship duplicate or unordered"));
        }
        previous = Some(record.operation);
        doc.get_map("authorship")
            .insert(
                &record.operation.to_hex(),
                serde_json::to_string(&record.stored_for_note(note))
                    .map_err(|_| invalid("recovery authorship encode"))?,
            )
            .map_err(|_| invalid("recovery authorship insert"))?;
    }
    doc.commit(); // Fresh peer identity, not a replay of deterministic birth.
    NoteDocument::from_loro(note, doc.fork())?.view()?;
    Ok(doc)
}

pub(crate) fn guard(vault: &Vault, txn: &heed::RoTxn<'_>, note: EntityId) -> Result<()> {
    super::ensure_citations_ready(&vault.store, txn, note)?;
    if vault.local_hard_delete_marker_exists_in_txn(txn, &note)? {
        return Err(invalid("erased NOTE cannot be recovered"));
    }
    if SYNC_DS_E.contains(&vault.store, txn, &HexId(note))?
        || SYNC_QN_E
            .iter_from(&vault.store, txn, format!("{}:", note.to_hex()).as_bytes())?
            .next()
            .transpose()?
            .is_some()
        || super::citation_erase::NOTE_ERASE_AUTHORITY_FLOOR.contains(
            &vault.store,
            txn,
            &HexId(note),
        )?
        || super::citation_delete_scope_exists(&vault.store, txn, &note)?
    {
        return Err(invalid(
            "NOTE recovery requires authority or citation rebasing",
        ));
    }
    // A NOTE whose document this vault does not hold yet (its core arrived
    // first) has no citation to rebase (FIX 7783).
    if crate::ports::EntityStoreRead::port_entity_present(&vault.store, txn, &note)?
        && let Some(doc) = super::storage::stored_document(vault, txn, note)?
        && !NoteDocument::from_loro(note, doc)?.pins()?.is_empty()
    {
        return Err(invalid(
            "history-free NOTE recovery requires citation rebasing",
        ));
    }
    Ok(())
}

pub(crate) fn capture(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    note: EntityId,
) -> Result<loro::LoroDoc> {
    guard(vault, txn, note)?;
    Ok(super::document_store::load(vault, txn, note)?.doc)
}

/// A value's text, every editable field and its authorship (FIX 7784).
pub(crate) fn values(
    note: EntityId,
    doc: loro::LoroDoc,
) -> Result<(
    String,
    BTreeMap<String, Vec<u8>>,
    Vec<super::NoteAuthorship>,
)> {
    let doc = NoteDocument::from_loro(note, doc)?;
    let view = doc.view()?;
    if !view.pins.is_empty() {
        return Err(invalid(
            "history-free NOTE recovery requires citation rebasing",
        ));
    }
    Ok((view.markdown, doc.metadata()?, view.authorship))
}

/// Rebuilds a switched head's document where this vault has none: the head
/// pointer is set first, so the document lands in the head's slot.
#[cfg(feature = "sync")]
pub(crate) fn restore_head(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    head_and_seq: (EntityId, u64),
    text: &str,
    metadata: &BTreeMap<String, Vec<u8>>,
    authorship: &[super::NoteAuthorship],
) -> Result<()> {
    guard(vault, txn, note)?;
    super::documents::set_head(&vault.store, txn, note, head_and_seq.0, head_and_seq.1)?;
    let doc = NoteDocument::from_loro(note, rebuild(note, text, metadata, authorship)?)?;
    super::document_store::persist_recovered_document(vault, txn, &doc)
}

#[cfg(feature = "sync")]
pub(crate) fn restore(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    text: &str,
    metadata: &BTreeMap<String, Vec<u8>>,
    authorship: &[super::NoteAuthorship],
) -> Result<()> {
    guard(vault, txn, note)?;
    let authorship: Vec<_> = authorship
        .iter()
        .map(|record| record.stored_for_note(note))
        .collect();
    // A vault that holds no document of the NOTE yet (its core arrived
    // first) holds no previous value or provenance: the validated snapshot's
    // rebuilds it (FIX 7783).
    if let Some(held) = super::storage::stored_document(vault, txn, note)? {
        let held = NoteDocument::from_loro(note, held)?;
        let old = held.view()?;
        if old.markdown == text && held.metadata()? == *metadata && old.authorship == authorship {
            return Ok(());
        }
        // An erased twin keeps its record (ErasedWins); a live actor never
        // resurrects over an erased one.
        if old
            .authorship
            .iter()
            .any(|record| !authorship.iter().any(|kept| record.kept_by(kept)))
        {
            return Err(invalid("NOTE recovery would discard admitted provenance"));
        }
    }
    let doc = NoteDocument::from_loro(note, rebuild(note, text, metadata, &authorship)?)?;
    let key_prefix = format!("{}:", note.to_hex()).into_bytes();
    SYNC_QD_E.delete_from(&vault.store, txn, &key_prefix)?;
    SYNC_AD_E.delete_from(&vault.store, txn, &key_prefix)?;
    NOTE_RECEIPT_BY_REQUEST.delete_from(&vault.store, txn, &key_prefix)?;
    SYNC_NC_E.delete_from(&vault.store, txn, &key_prefix)?;
    let slot = DocumentSlot::of(super::storage::slot(vault, txn, note)?);
    let rows = [DocumentRow::ShallowSince, DocumentRow::UpdateSequence];
    vault.store.port_document_rows_delete(txn, slot, &rows)?;
    super::document_store::persist_recovered_document(vault, txn, &doc)
}
