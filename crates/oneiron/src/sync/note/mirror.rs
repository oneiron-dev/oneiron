//! Snapshot-consistent NOTE packing and selective-export closure.
use super::workflows::Judge;
use super::*;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::sync::loro_support::{map_delete, map_get_bytes, map_insert_bytes};
use crate::sync::types::WindowKey;
use crate::sync::window::Withhold;

pub(crate) fn refresh(vault: &Vault, doc: &LoroDoc, window: &WindowKey) -> Result<bool> {
    refresh_for(vault, doc, window, Withhold::Unknown)
}

/// [`refresh`] for the machine an export serves. A proved machine's detached
/// copy packs the NOTEs of the private worlds that machine may read; the
/// stored window and every other door keep off what an unknown destination
/// may not read.
pub(crate) fn refresh_for(
    vault: &Vault,
    doc: &LoroDoc,
    window: &WindowKey,
    withhold: Withhold<'_>,
) -> Result<bool> {
    // NOTE rows and their text-plane carriers live in the shared base month.
    // Every caller (reverse, ordinary export, snapshot export, selector) uses
    // this door, so none may contaminate a world-only document.
    if window.world().is_some() {
        return Ok(false);
    }
    let ids = vault.entities_in_learned_range(
        window.start_timestamp().ok_or(invalid("NOTE window"))?,
        window.end_timestamp().ok_or(invalid("NOTE window"))?,
    )?;
    let mut state = State::default();
    let tombstones = TombstoneIndex::build(&doc.get_map("tombstones"));
    let txn = vault.store.env.read_txn()?;
    let flagged = match withhold {
        Withhold::Worlds(_) | Withhold::Peer(_) => withhold.worlds_in(vault, &txn)?,
        Withhold::Nothing | Withhold::Unknown => Withhold::Unknown.worlds_in(vault, &txn)?,
    };
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
            if blocked(vault, &txn, &tombstones, &note)? {
                removed.insert(note);
            }
        }
    }
    for note in ids {
        let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &note)?
        else {
            continue;
        };
        if EntityMetadataHeader::parse(&raw)
            .is_none_or(|h| h.entity_type != crate::registry::ENTITY_TYPE_NOTE)
        {
            continue;
        }
        // A NOTE a device-only world keeps is never packed into a window
        // that does not already carry it.
        if !state.cores.contains_key(&note) && held(vault, &txn, &flagged, &note)? {
            continue;
        }
        local.insert(note);
        if blocked(vault, &txn, &tombstones, &note)? {
            removed.insert(note);
        } else {
            state.cores.insert(note, raw.to_vec());
        }
    }
    // Only trusted local workflows are exported. Untrusted inbox or carried
    // peer rows are never promoted or replayed as local review decisions.
    for note in state.cores.keys() {
        if blocked(vault, &txn, &tombstones, note)? {
            removed.insert(*note);
        }
    }
    state.cores.retain(|note, _| !removed.contains(note));
    // A bundle is no month's: it rides beside each NOTE here it holds a
    // member of, whole or as a projection, and never fails this window.
    let judge = Judge {
        vault,
        txn: &txn,
        tombstones: &tombstones,
        flagged: &flagged,
        selector: None,
    };
    state.assemble(&judge, &local, &removed)?;
    if state.cores.is_empty() && removed.is_empty() && !is_native(doc) {
        return Ok(false);
    }
    state.erase_actors_here(vault, &txn)?;
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

/// [`copy_selected`] for a door with no snapshot of its own: the NOTEs in
/// `out` are judged in a read transaction of their own. An admitted copy
/// keeps a peer's attachments only as this vault's own judgement lets them
/// ride; they stay advisory.
pub(crate) fn copy_judged(vault: &Vault, source: &LoroDoc, out: &LoroDoc) -> Result<()> {
    let ids = rows(out, "entities")?
        .iter()
        .map(|(key, _)| id(key))
        .collect::<Result<BTreeSet<_>>>()?;
    let txn = vault.store.env.read_txn()?;
    let flagged = crate::settings::device_local_worlds_at(
        vault,
        &txn,
        crate::claim::CallerLocality::OffDevice,
    )?;
    let selection = NoteSelection::judged_in(vault, &txn, &flagged, source, &ids, None)?;
    if !is_native(source) {
        return Ok(());
    }
    // A carried copy names no one this vault erased (FIX 3878).
    let mut state = codec::read(source)?;
    state.erase_actors_here(vault, &txn)?;
    drop(txn);
    copy_state(state, out, &selection)
}

/// Copy the workflows of the NOTEs in `out` but those `selection` drops, so
/// nothing is withheld after the export's own snapshot. A bundle another
/// NOTE also holds a member of rides whole only while `selection` lets that
/// NOTE ride as an attachment; else it is a projection onto `out`'s NOTEs,
/// with no other NOTE's value or the explainer they share (FIX 8878).
pub(crate) fn copy_selected(
    source: &LoroDoc,
    out: &LoroDoc,
    selection: &NoteSelection,
) -> Result<()> {
    if !is_native(source) {
        return Ok(());
    }
    copy_state(codec::read(source)?, out, selection)
}

/// [`copy_selected`] of `state`, the workflows a source carries.
fn copy_state(mut state: State, out: &LoroDoc, selection: &NoteSelection) -> Result<()> {
    let mut keep = BTreeSet::new();
    for (key, _) in rows(out, "entities")? {
        let note = id(&key)?;
        if state.cores.contains_key(&note) && !selection.drops(&note) {
            keep.insert(note);
        } else if state.cores.contains_key(&note) {
            map_delete(&out.get_map("entities"), &key)?;
        }
    }
    state.select(&keep, selection);
    state.validate()?;
    state.write(out)?;
    Ok(())
}
