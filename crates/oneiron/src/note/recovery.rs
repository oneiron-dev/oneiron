//! Host-local history-free recovery of uncited NOTE values.
use super::document::{NoteDocument, invalid};
#[cfg(feature = "sync")]
use super::sync_rows::{NOTE_RECEIPT_BY_REQUEST, SYNC_AD_E, SYNC_NC_E, SYNC_QD_E};
use super::sync_rows::{SYNC_DS_E, SYNC_QN_E};
use crate::side_table::HexId;
use crate::{EntityId, Result, Vault};

pub(crate) fn rebuild(
    note: EntityId,
    text: &str,
    authorship: &[super::NoteAuthorship],
) -> Result<loro::LoroDoc> {
    super::validate_markdown(text)?;
    let doc = super::documents::proposal_value(note, text)?;
    let mut previous = None;
    for record in authorship {
        if previous.is_some_and(|id| id >= record.operation) {
            return Err(invalid("recovery authorship duplicate or unordered"));
        }
        previous = Some(record.operation);
        doc.get_map("authorship")
            .insert(
                &record.operation.to_hex(),
                serde_json::to_string(record).map_err(|_| invalid("recovery authorship encode"))?,
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
    #[cfg(feature = "sync")]
    if crate::entity_doc::has_record_head(&vault.store, txn, &note)? {
        return Err(invalid(
            "generic EntityDoc recovery needs its own value adapter",
        ));
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
    if vault.store.entities.get(txn, note.as_bytes())?.is_some() {
        let doc = super::document_store::load(vault, txn, note)?;
        if !doc.pins()?.is_empty() {
            return Err(invalid(
                "history-free NOTE recovery requires citation rebasing",
            ));
        }
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

pub(crate) fn values(
    note: EntityId,
    doc: loro::LoroDoc,
) -> Result<(String, Vec<super::NoteAuthorship>)> {
    let view = NoteDocument::from_loro(note, doc)?.view()?;
    if !view.pins.is_empty() {
        return Err(invalid(
            "history-free NOTE recovery requires citation rebasing",
        ));
    }
    Ok((view.markdown, view.authorship))
}

/// Rebuilds a switched head's document where this vault has none: the head
/// pointer is set first, so the document lands in the head's slot.
#[cfg(feature = "sync")]
pub(crate) fn restore_head(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    head: EntityId,
    seq: u64,
    text: &str,
    authorship: &[super::NoteAuthorship],
) -> Result<()> {
    guard(vault, txn, note)?;
    super::documents::set_head(&vault.store, txn, note, head, seq)?;
    let doc = NoteDocument::from_loro(note, rebuild(note, text, authorship)?)?;
    super::document_store::persist(vault, txn, &doc)
}

#[cfg(feature = "sync")]
pub(crate) fn restore(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    note: EntityId,
    text: &str,
    authorship: &[super::NoteAuthorship],
) -> Result<()> {
    guard(vault, txn, note)?;
    let old = super::document_store::load(vault, txn, note)?.view()?;
    if old.markdown == text && old.authorship == authorship {
        return Ok(());
    }
    if old
        .authorship
        .iter()
        .any(|record| !authorship.contains(record))
    {
        return Err(invalid("NOTE recovery would discard admitted provenance"));
    }
    let doc = NoteDocument::from_loro(note, rebuild(note, text, authorship)?)?;
    let key_prefix = format!("{}:", note.to_hex()).into_bytes();
    SYNC_QD_E.delete_from(&vault.store, txn, &key_prefix)?;
    SYNC_AD_E.delete_from(&vault.store, txn, &key_prefix)?;
    NOTE_RECEIPT_BY_REQUEST.delete_from(&vault.store, txn, &key_prefix)?;
    SYNC_NC_E.delete_from(&vault.store, txn, &key_prefix)?;
    let slot = super::storage::slot(vault, txn, note)?;
    // ARCH-0023b document families: not ours, left exactly as they were.
    for prefix in ["ssv:e:", "m:u_seq:e:"] {
        vault
            .store
            .sync_state
            .delete(txn, &format!("{prefix}{}", slot.to_hex()))?;
    }
    super::document_store::persist(vault, txn, &doc)
}
