//! Retained soft-delete headers on the standard forward recovery path.

use crate::error::Result;
use crate::{EntityId, Vault};
use loro::{LoroDoc, LoroValue, ValueOrContainer};

/// Only an exact header paired with a canonical user-delete tombstone qualifies.
/// Aliases, malformed values, hard deletes and local-only archives never qualify.
pub(crate) fn retained_soft_shell(doc: &LoroDoc, id: &EntityId) -> Option<(Vec<u8>, Vec<u8>)> {
    let key = id.to_hex();
    let Some(ValueOrContainer::Value(LoroValue::Binary(blob))) = doc.get_map("entities").get(&key)
    else {
        return None;
    };
    if blob.len() != crate::batch::ENTITY_METADATA_HEADER_LEN {
        return None;
    }
    let header = crate::batch::EntityMetadataHeader::parse(&blob)?;
    if crate::registry::validate_public_entity_type(header.entity_type).is_err()
        || header.occurred_start > header.occurred_end
    {
        return None;
    }

    let Some(ValueOrContainer::Value(LoroValue::Binary(value))) =
        doc.get_map("tombstones").get(&key)
    else {
        return None;
    };
    if crate::deletion::decode_tombstone_value(&value).reason
        != Some(crate::deletion::TombstoneReason::UserDelete)
    {
        return None;
    }
    let mut alias = false;
    doc.get_map("tombstones").for_each(|other, _| {
        if other != key && EntityId::from_hex(other).ok().as_ref() == Some(id) {
            alias = true;
        }
    });
    if alias {
        None
    } else {
        Some((blob.to_vec(), value.to_vec()))
    }
}

pub(crate) fn materialize_retained_shells(vault: &Vault, doc: &LoroDoc) -> Result<()> {
    let mut shells = Vec::new();
    doc.get_map("entities").for_each(|key, value| {
        if matches!(value, ValueOrContainer::Value(LoroValue::Binary(blob)) if blob.len() == crate::batch::ENTITY_METADATA_HEADER_LEN)
            && let Ok(id) = EntityId::from_hex(key)
            && let Some((blob, tombstone)) = retained_soft_shell(doc, &id) {
            shells.push((id, blob, tombstone));
        }
    });
    for (id, blob, tombstone) in shells {
        // Never resurrect after a local hard delete, even if a peer removed its
        // hard marker from the CRDT. The ordinary tombstone pass stays in charge.
        vault.with_write_txn(|txn| {
            if vault.local_hard_delete_marker_exists_in_txn(txn, &id)? {
                return Ok(());
            }
            crate::batch::restore_recovery_shell_in_txn(vault, txn, &id, &blob, &tombstone)
        })?;
    }
    Ok(())
}
