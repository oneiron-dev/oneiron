//! Remove active NOTE carriers in the same window commit as a tombstone,
//! and a deleted NOTE's bundle attachments from every other live window.
use super::*;
use crate::sync::bridge::BRIDGE_ORIGIN;
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
        row.bundle.waiting.retain(|fork| !notes.contains(&fork.note));
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
    let notes: Vec<EntityId> = {
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
    };
    if notes.is_empty() {
        return;
    }
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
        let _guard = materializer.lock();
        match attachments_deleted(&loaded.doc, &notes) {
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
