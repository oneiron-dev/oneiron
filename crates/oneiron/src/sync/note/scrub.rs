//! Remove active NOTE carriers in the same window commit as a tombstone,
//! and a deleted NOTE's bundle attachments from every other live window.
use super::*;
use crate::sync::bridge::{BRIDGE_ORIGIN, Materializer};
use crate::sync::loro_support::{map_delete, map_insert_bytes};

pub(crate) fn deleted(doc: &LoroDoc, note: &EntityId) -> Result<()> {
    if !matches!(doc.get_value(), LoroValue::Map(roots) if MAPS.iter().any(|name| roots.contains_key(*name)))
    {
        return Ok(());
    }
    let mut keys = Vec::new();
    doc.get_map("documents").for_each(|key, _| {
        let parts: Vec<_> = key.split(':').collect();
        if parts.len() == 4 && EntityId::from_hex(parts[2]).ok().as_ref() == Some(note) {
            keys.push(key.to_owned());
        }
    });
    for key in keys {
        map_delete(&doc.get_map("documents"), &key)?;
    }
    let mut keys = Vec::new();
    doc.get_map("document_heads").for_each(|key, _| {
        if EntityId::from_hex(key).ok().as_ref() == Some(note) {
            keys.push(key.to_owned());
        }
    });
    for key in keys {
        map_delete(&doc.get_map("document_heads"), &key)?;
    }
    for (key, raw) in rows(doc, "head_move_receipts")? {
        let row: crate::recovery::CanonicalHeadMove = unpack(&raw)?;
        if row.entity_id == *note.as_bytes() {
            map_delete(&doc.get_map("head_move_receipts"), &key)?;
        }
    }
    for (key, raw) in rows(doc, "note_forks")? {
        let row: NoteFork = unpack(&raw)?;
        if row.note == *note {
            map_delete(&doc.get_map("note_forks"), &key)?;
        }
    }
    // The NOTE's attachments in a bundle of another NOTE's go too, and that
    // bundle stays a projection, not complete.
    attachments_deleted(doc, std::slice::from_ref(note))?;
    Ok(())
}

/// Takes the attachments of `notes` out of each review bundle `doc` holds:
/// a bundle that keeps another NOTE's member stays as a projection, not
/// complete, and one left empty goes. Every row is read before any is
/// written. Whether any changed.
fn attachments_deleted(doc: &LoroDoc, notes: &[EntityId]) -> Result<bool> {
    let mut changes = Vec::new();
    for (key, raw) in rows(doc, "note_proposals")? {
        let mut row: BundleCarrier = unpack(&raw)?;
        if !bundle_notes(&row.bundle)
            .iter()
            .any(|member| notes.contains(member))
        {
            continue;
        }
        row.bundle
            .waiting
            .retain(|fork| !notes.contains(&fork.note));
        row.bundle
            .landed
            .retain(|receipt| !notes.contains(&receipt.note));
        if row.bundle.waiting.is_empty() && row.bundle.landed.is_empty() {
            changes.push((key, None));
        } else {
            row.redact();
            changes.push((key, Some(pack(&row)?)));
        }
    }
    if changes.is_empty() {
        return Ok(false);
    }
    let proposals = doc.get_map("note_proposals");
    for (key, row) in &changes {
        if let Some(row) = row {
            map_insert_bytes(&proposals, key, row)?;
        } else {
            map_delete(&proposals, key)?;
        }
    }
    Ok(true)
}

/// Once the tombstones of `notes` committed in `window`, takes their
/// attachments out of the review bundles every other live window holds
/// (FIX 8878), as the tombstone took them out of `window`'s own. Each window
/// it changes commits under the materializer lock as a mirror of the delete,
/// so that window's local-update observer persists the change and routes it
/// outbound, as it routes every local change. Drop only: a window whose rows
/// do not read is logged, and keeps them until its next export. An id whose
/// stored row is another kind's is no NOTE, and is passed over.
pub(crate) fn deleted_elsewhere(
    vault: &Vault,
    window: &str,
    notes: impl IntoIterator<Item = EntityId>,
) {
    let notes = note_ids(vault, notes);
    if notes.is_empty() {
        return;
    }
    scrub_other_windows(vault, window, &notes, true);
}

/// [`deleted_elsewhere`] for a caller that holds the shared materializer
/// lock (Observer B's tombstone batch, FIX 12128): the same scrub, without
/// locking — the lock is not reentrant, so locking here would deadlock.
/// Each changed window still commits as a mirror of the delete, which that
/// window's observer skips by origin while persisting and routing it.
pub(crate) fn deleted_elsewhere_under_lock(
    vault: &Vault,
    window: &str,
    notes: impl IntoIterator<Item = EntityId>,
) {
    let notes = note_ids(vault, notes);
    if notes.is_empty() {
        return;
    }
    scrub_other_windows(vault, window, &notes, false);
}

/// The NOTEs among `notes`: an id whose stored row is another kind's is no
/// NOTE, and is passed over.
fn note_ids(vault: &Vault, notes: impl IntoIterator<Item = EntityId>) -> Vec<EntityId> {
    // Dropped before any window commits: Observer A opens a writer.
    let txn = vault.store.env.read_txn().ok();
    notes
        .into_iter()
        .filter(|id| {
            let kind = txn.as_ref().and_then(|txn| {
                crate::batch::stored_entity_type(&vault.store, txn, id)
                    .ok()
                    .flatten()
            });
            kind.is_none_or(|kind| kind == crate::registry::ENTITY_TYPE_NOTE)
        })
        .collect()
}

/// Scrubs a window that loads the review-bundle attachments of the NOTEs
/// this vault's markers delete (FIX 12129): a window closed while a NOTE
/// was deleted missed the delete's scrub of the other live windows. The
/// deletes are read from the vault's own `df:`/`dt:` markers — no pending
/// list is stored. Commits under `materializer` as a mirror of the deletes,
/// which the window's observer skips by origin while persisting and
/// routing it.
pub(crate) fn scrub_missed_note_deletes(
    vault: &Vault,
    materializer: &Materializer,
    doc: &LoroDoc,
) -> Result<()> {
    if !matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key("note_proposals")) {
        return Ok(());
    }
    let mut members = BTreeSet::new();
    for (_, raw) in rows(doc, "note_proposals")? {
        let row = unpack::<BundleCarrier>(&raw)?;
        members.extend(bundle_notes(&row.bundle));
    }
    if members.is_empty() {
        return Ok(());
    }
    let txn = vault.store.env.read_txn()?;
    let mut deleted = Vec::new();
    for member in &members {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, member)?;
        let kind = raw.as_deref().and_then(|raw| {
            crate::batch::EntityMetadataHeader::parse(raw).map(|header| header.entity_type)
        });
        if kind.is_some_and(|kind| kind != crate::registry::ENTITY_TYPE_NOTE) {
            continue;
        }
        if crate::deletion::row_deletion_marked(&vault.store, &txn, member, raw.as_deref())? {
            deleted.push(*member);
        }
    }
    // Dropped before the commit below: Observer A opens a writer.
    drop(txn);
    if deleted.is_empty() {
        return Ok(());
    }
    let _guard = materializer.lock();
    if attachments_deleted(doc, &deleted)? {
        doc.commit_with(loro::CommitOptions::new().origin(BRIDGE_ORIGIN));
    }
    Ok(())
}

fn scrub_other_windows(vault: &Vault, window: &str, notes: &[EntityId], take_lock: bool) {
    for loaded in vault.live_windows() {
        let holds_bundles = matches!(
            loaded.doc.get_value(),
            LoroValue::Map(roots) if roots.contains_key("note_proposals")
        );
        if loaded.key.as_str() == window || !holds_bundles {
            continue;
        }
        let Some((_, materializer, _)) = vault.live_window(&loaded.key) else {
            continue;
        };
        let _guard = take_lock.then(|| materializer.lock());
        match attachments_deleted(&loaded.doc, notes) {
            Ok(true) => {
                loaded
                    .doc
                    .commit_with(loro::CommitOptions::new().origin(BRIDGE_ORIGIN));
            }
            Ok(false) => {}
            Err(error) => tracing::warn!(
                window = %loaded.key.as_str(),
                kind = ?error.kind(),
                "a deleted NOTE's bundle attachments stay in this window until its next export"
            ),
        }
    }
}
