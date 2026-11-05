//! Native NOTE frontier bindings, sharing the physical envelope's own history.

use super::frontier::{FrontierEntry, decode_frontier};
use super::{DOC, FRONTIER, IDENTITY, RevisionRef, RevisionState, STATE};
use super::{
    doc_raw, put_state, reference, retain_frontier, save_doc, state, unix_millis_at, write_doc_row,
};
use crate::error::{Error, Result};
use crate::store::ManifestDbs;
use crate::{EntityId, Vault};
use loro::LoroDoc;

pub(crate) struct NoteCapture {
    pub(crate) changed: bool,
    pub(crate) published: bool,
    pub(crate) markdown: String,
}

pub(super) fn active_note(
    store: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    revision: RevisionRef,
) -> Result<Option<Vec<u8>>> {
    let Some(encoded) = FRONTIER.get(store, txn, &(*id, revision.0))? else {
        return Ok(None);
    };
    let native = FrontierEntry::decode(&encoded)?
        .committed_note(id, revision, &encoded)?
        .is_some();
    Ok(native.then_some(encoded))
}

fn envelope_reference(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    raw: &[u8],
) -> Result<RevisionRef> {
    let revision = match DOC.get(store, txn, id)? {
        Some(bytes) => {
            let doc = LoroDoc::from_snapshot(&bytes)
                .map_err(|_| Error::CorruptedIndex("entity document"))?;
            if doc_raw(&doc)? != raw {
                return Err(Error::CorruptedIndex("NOTE physical envelope history"));
            }
            let revision = reference(id, raw);
            if !FRONTIER.contains(store, txn, &(*id, revision.0))? {
                retain_frontier(store, txn, id, revision, &doc)?;
            }
            revision
        }
        None => {
            let revision = reference(id, raw);
            FRONTIER.put(
                store,
                txn,
                &(*id, revision.0),
                &FrontierEntry::PhysicalAlias.encode(),
            )?;
            revision
        }
    };
    IDENTITY.put(store, txn, &revision.0, id)?;
    Ok(revision)
}

/// Explicit citation can materialize a physical alias, just as the original
/// generic ensure door did. Native activation itself retains no raw copy.
pub(super) fn ensure_note_envelope(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    raw: &[u8],
    encoded: &[u8],
) -> Result<()> {
    let FrontierEntry::Note { row, .. } = FrontierEntry::decode(encoded)? else {
        return Err(Error::CorruptedIndex("NOTE frontier kind"));
    };
    if DOC.contains(store, txn, id)? {
        return Ok(());
    }
    if reference(id, raw) != row {
        return Err(Error::CorruptedIndex("NOTE physical alias mismatch"));
    }
    let doc = LoroDoc::new();
    write_doc_row(&doc, raw)?;
    retain_frontier(store, txn, id, row, &doc)?;
    save_doc(store, txn, id, &doc)
}

/// Appends genuine physical history without loading native prose or comparing
/// the physical row's ref with the native STATE ref.
pub(super) fn capture_note_envelope(
    store: &impl ManifestDbs,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    prior: Option<&[u8]>,
    new_raw: &[u8],
    current: &mut RevisionState,
    encoded: &[u8],
) -> Result<()> {
    let FrontierEntry::Note {
        slot,
        row,
        frontier,
    } = FrontierEntry::decode(encoded)?
    else {
        return Err(Error::CorruptedIndex("NOTE frontier kind"));
    };
    let doc = match DOC.get(store, txn, id)? {
        Some(bytes) => {
            LoroDoc::from_snapshot(&bytes).map_err(|_| Error::CorruptedIndex("entity document"))?
        }
        None => {
            let prior = prior.ok_or(Error::CorruptedIndex("revision without entity"))?;
            if reference(id, prior) != row {
                return Err(Error::CorruptedIndex("NOTE physical alias mismatch"));
            }
            let doc = LoroDoc::new();
            write_doc_row(&doc, prior)?;
            retain_frontier(store, txn, id, row, &doc)?;
            doc
        }
    };
    write_doc_row(&doc, new_raw)?;
    let row = reference(id, new_raw);
    if !FRONTIER.contains(store, txn, &(*id, row.0))? {
        retain_frontier(store, txn, id, row, &doc)?;
    }
    save_doc(store, txn, id, &doc)?;
    let next_encoded = FrontierEntry::Note {
        slot,
        row,
        frontier,
    }
    .encode();
    let next = reference(id, &next_encoded);
    FRONTIER.put(store, txn, &(*id, next.0), &next_encoded)?;
    IDENTITY.put(store, txn, &next.0, id)?;
    if current.indexed == current.live {
        current.indexed = next;
    } else {
        super::super::pending_index::retarget_revision(store, txn, id, current.live, next)?;
        super::super::phonetic::retarget_revision(store, txn, id, current.live, next)?;
    }
    current.live = next;
    current.has_doc = true;
    put_state(store, txn, id, current)
}

/// Called after the canonical snapshot and floor rows land, still under the
/// same writer. Ordinary edits keep indexed; a cut never strands indexed below
/// its actual stored slot's floor. Generic physical history is not a cut target.
pub(crate) fn capture_native_note_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<NoteCapture> {
    let store = &vault.store;
    let slot = crate::note::documents::head_in(store, txn, id)?.0;
    let stored = crate::note::revision::stored_slot_in_txn(store, txn, id, slot)?
        .ok_or(Error::CorruptedIndex("NOTE indexed slot missing"))?;
    let markdown = stored.doc.get_text("body").to_string();
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &id)?
        .ok_or(Error::EntityNotFound)?;
    let row = envelope_reference(store, txn, &id, &raw)?;
    let frontier = stored.doc.oplog_frontiers().encode();
    let encoded = FrontierEntry::Note {
        slot,
        row,
        frontier: &frontier,
    }
    .encode();
    let next = reference(&id, &encoded);
    let mut current = state(store, txn, &id)?.unwrap_or(RevisionState {
        live: row,
        indexed: row,
        changed_at_ms: unix_millis_at(std::time::SystemTime::now()),
        has_doc: false,
    });
    let activated = active_note(store, txn, &id, current.live)?.is_some();
    let changed = current.live != next;
    let mut indexed_retained = false;
    let mut retired = Vec::new();
    let mut slots = std::collections::BTreeMap::from([(slot, Some(stored))]);
    for (key, value) in FRONTIER.scan_from(store, txn, id.as_bytes())? {
        let Some((at_slot, _, at)) =
            FrontierEntry::decode(&value)?.committed_note(&id, RevisionRef(key.1), &value)?
        else {
            continue;
        };
        if !slots.contains_key(&at_slot) {
            slots.insert(
                at_slot,
                crate::note::revision::stored_slot_in_txn(store, txn, id, at_slot)?,
            );
        }
        let at = decode_frontier(at)?;
        let stored = slots.get(&at_slot).and_then(Option::as_ref);
        if key.1 == current.indexed.0 {
            indexed_retained = stored.is_some_and(|stored| stored.retains(&at));
        }
        if stored.is_some_and(|stored| stored.cut_past(&at)) {
            retired.push(key);
        }
    }
    let published = !activated || !indexed_retained;
    let same_input = if published {
        let selected =
            crate::note::revision::row_with_markdown_in_txn(store, txn, &raw, markdown.clone())?;
        match super::read_entity_revision_in_txn(vault, txn, &id, super::super::ReadMode::Indexed) {
            Ok(Some(before)) => {
                before.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                    == selected.get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
            }
            Ok(None) | Err(Error::EntityNotFound) => false,
            Err(error) => return Err(error),
        }
    } else {
        true
    };
    let held_vector = store.vectors.get(txn, id.as_bytes())?.is_some();
    FRONTIER.put(store, txn, &(id, next.0), &encoded)?;
    IDENTITY.put(store, txn, &next.0, &id)?;
    if changed {
        current.changed_at_ms = unix_millis_at(std::time::SystemTime::now());
    }
    current.live = next;
    current.has_doc = true;
    if published {
        current.indexed = next;
        super::super::pending_index::clear(store, txn, &id)?;
        super::super::phonetic::clear_phonetic(store, txn, &id)?;
        if !same_input {
            super::super::idle::drop_vector_state(vault, txn, &id)?;
        }
        if !same_input || !held_vector {
            super::super::vector_refill::REFILL.put(store, txn, &id, &())?;
        }
    }
    put_state(store, txn, &id, &current)?;
    for key in retired {
        if key.1 != next.0 {
            FRONTIER.delete(store, txn, &key)?;
            IDENTITY.delete(store, txn, &key.1)?;
        }
    }
    Ok(NoteCapture {
        changed,
        published,
        markdown,
    })
}

/// Completes a forced publication after its actual Text batch succeeded.
pub(crate) fn finish_native_note_publication_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
) -> Result<()> {
    let store = &vault.store;
    let current = STATE.get(store, txn, &id)?.ok_or(Error::EntityNotFound)?;
    let raw = super::read_entity_revision_in_txn(vault, txn, &id, super::super::ReadMode::Indexed)?
        .ok_or(Error::EntityNotFound)?;
    let codes = super::super::phonetic::take_phonetic(
        store,
        txn,
        &id,
        current.indexed,
        raw[0],
        &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
    )?;
    crate::batch::delete_from_phonetic_postings(store, txn, &id)?;
    crate::batch::apply_phonetic(store, txn, id, &codes)?;
    crate::tagging::mark_on_publication_in_txn(vault, txn, &id, raw[0])?;
    crate::embed::mark_on_publication_in_txn(vault, txn, &id, raw[0])?;
    crate::dreamer_wake::mark_on_publication_in_txn(store, txn, &id)
}
