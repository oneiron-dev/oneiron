//! Remove active NOTE carriers in the same window commit as a tombstone.
use super::*;
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
    for (key, raw) in rows(doc, "note_proposals")? {
        let mut row: BundleCarrier = unpack(&raw)?;
        if !bundle_notes(&row.bundle).contains(note) {
            continue;
        }
        row.bundle.waiting.retain(|fork| fork.note != *note);
        row.bundle.landed.retain(|receipt| receipt.note != *note);
        if row.bundle.waiting.is_empty() && row.bundle.landed.is_empty() {
            map_delete(&doc.get_map("note_proposals"), &key)?;
        } else {
            row.redact();
            map_insert_bytes(&doc.get_map("note_proposals"), &key, &pack(&row)?)?;
        }
    }
    Ok(())
}
