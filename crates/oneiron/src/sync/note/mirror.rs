//! Snapshot-consistent NOTE packing and selective-export closure.
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::sync::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use crate::sync::types::WindowKey;

pub(crate) fn refresh(vault: &Vault, doc: &LoroDoc, window: &WindowKey) -> Result<bool> {
    let ids = vault.entities_in_learned_range(
        window.start_timestamp().ok_or(invalid("NOTE window"))?,
        window.end_timestamp().ok_or(invalid("NOTE window"))?,
    )?;
    let mut state = State::default();
    let txn = vault.store.env.read_txn()?;
    let mut local = BTreeSet::new();
    let mut removed = BTreeSet::new();
    for (key, raw) in rows(doc, "entities")? {
        if EntityMetadataHeader::parse(&raw)
            .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_NOTE)
        {
            let note = id(&key)?;
            if raw.len() > ENTITY_METADATA_HEADER_LEN {
                state.cores.entry(note).or_insert(raw);
            }
            if blocked(vault, &txn, doc, &note)? {
                removed.insert(note);
            }
        }
    }
    for note in ids {
        let Some(raw) = vault.store.entities.get(&txn, note.as_bytes())? else {
            continue;
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_NOTE)
        {
            continue;
        }
        local.insert(note);
        if blocked(vault, &txn, doc, &note)? {
            removed.insert(note);
        } else {
            state.cores.insert(note, raw.to_vec());
        }
    }
    // Only trusted local workflows are exported. Untrusted inbox or carried
    // peer rows are never promoted or replayed as local review decisions.
    for note in state.cores.keys() {
        if blocked(vault, &txn, doc, note)? {
            removed.insert(*note);
        }
    }
    state.cores.retain(|note, _| !removed.contains(note));
    for note in local.difference(&removed) {
        let prefix = format!("note_proposal_doc:v1:{}:", note.to_hex());
        // The head's document rides the text plane, never a window.
        let (head, _) = crate::note::documents::head_in(&vault.store, &txn, *note)?;
        for row in vault.store.sync_state.prefix_iter(&txn, &prefix)? {
            let (key, raw) = row?;
            let fork = id(&key[prefix.len()..])?;
            if fork == head {
                continue;
            }
            state.docs.insert(
                (*note, fork),
                crate::note::documents::proposal_text(*note, &raw)?,
            );
        }
        state.heads.insert(*note, *note);
    }
    for row in vault.store.vault_meta.prefix_iter(&txn, b"note_fork:v1:")? {
        let (key, raw) = row?;
        let fork: NoteFork = unpack(&raw)?;
        if !state.cores.contains_key(&fork.note) {
            continue;
        }
        if key != metadata_key(b"note_fork:v1:", fork.fork) {
            return Err(invalid("NOTE stored fork key"));
        }
        state.forks.insert(fork.fork, fork);
    }
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&txn, b"note_receipt:v1:")?
    {
        let (key, raw) = row?;
        let receipt: NoteLandingReceipt = unpack(&raw)?;
        if !state.cores.contains_key(&receipt.note) {
            continue;
        }
        if key != metadata_key(b"note_receipt:v1:", receipt.id) {
            return Err(invalid("NOTE stored receipt key"));
        }
        state.receipts.insert(receipt.id, receipt);
    }
    let scope = state.cores.keys().copied().collect();
    for row in vault
        .store
        .vault_meta
        .prefix_iter(&txn, b"note_proposal:v1:")?
    {
        let (key, raw) = row?;
        let bundle: NoteReviewBundle = unpack(&raw)?;
        let notes = bundle_notes(&bundle);
        if notes.is_disjoint(&scope) {
            continue;
        }
        if !notes.is_subset(&scope) {
            return Err(invalid("NOTE proposal crosses window or deletion scope"));
        }
        if key != metadata_key(b"note_proposal:v1:", bundle.id) {
            return Err(invalid("NOTE stored proposal key"));
        }
        state.bundles.insert(bundle.id, bundle);
    }
    if state.cores.is_empty() && removed.is_empty() && !is_native(doc) {
        return Ok(false);
    }
    state.drop_deleted(&removed);
    state.validate()?;
    // Never commit while the read transaction is held: Observer A opens a writer.
    drop(txn);
    let mut changed = false;
    for note in removed {
        map_delete(&doc.get_map("entities"), &note.to_hex())?;
        changed = true;
    }
    for (note, raw) in &state.cores {
        if map_get_bytes(&doc.get_map("entities"), &note.to_hex()).as_deref()
            != Some(raw.as_slice())
        {
            map_insert_bytes(&doc.get_map("entities"), &note.to_hex(), raw)?;
            changed = true;
        }
    }
    changed |= state.write(doc)?;
    // Once present, old snapshot set-ops can retain rejected/deleted fork text.
    // Every transport export must use the history-free outer window frontier.
    crate::sync::window::require_history_free_window(vault, window)?;
    if changed {
        doc.commit_with(loro::CommitOptions::new().origin(crate::sync::bridge::BRIDGE_ORIGIN));
    }
    Ok(changed)
}

/// Copy only complete workflows whose NOTE owners already passed selection.
/// A partial bundle is an error, not permission to leak its shared explainer.
pub(crate) fn copy_selected(vault: &Vault, source: &LoroDoc, out: &LoroDoc) -> Result<()> {
    if !is_native(source) {
        return Ok(());
    }
    let mut state = codec::read(source)?;
    let txn = vault.store.env.read_txn()?;
    let mut keep = BTreeSet::new();
    for (key, _) in rows(out, "entities")? {
        let note = id(&key)?;
        if state.cores.contains_key(&note) && !blocked(vault, &txn, source, &note)? {
            keep.insert(note);
        } else if state.cores.contains_key(&note) {
            map_delete(&out.get_map("entities"), &key)?;
        }
    }
    state.retain(&keep)?;
    state.validate()?;
    state.write(out)?;
    Ok(())
}
