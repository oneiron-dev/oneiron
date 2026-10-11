//! Export-time withholding for worlds flagged device-only.
//!
//! Rows in a device-local world never leave the device that holds the flag
//! (DEC-0005). Packing skips them, but a claim packed while its world was
//! still portable stays resident in the stored window. Every claim of a world,
//! and every edge naming one, lives in that world's own windows
//! (`edge_worlds_match`), so an export door reads the flag when it runs and
//! ships nothing from a flagged world's window. The stored window is never
//! rewritten: clearing the flag ships it again on the next export.
//!
//! Cutting rows out of an export instead would need removal operations, and a
//! receiver materializes a bare edge removal as the deletion of its own stored
//! edge; that removal would also flow back here. For the same reason another
//! window that carries such a claim or edge out of residence (a base edge
//! admitted before its endpoint was known, or a raw local write) is withheld
//! whole too.

use std::collections::{BTreeSet, HashSet};

use heed::RoTxn;
use loro::{LoroDoc, LoroMap, VersionVector};

use super::super::bridge::parse_edge_key;
use super::super::loro_support::{export_updates_from, map_for_each_value_bytes};
use super::super::types::WindowKey;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;

/// Whether `key` is a window of a world flagged device-only on this device,
/// read against the flag as it stands now.
pub(in crate::sync) fn window_is_device_only(vault: &Vault, key: &WindowKey) -> Result<bool> {
    let Some(world) = key.world() else {
        return Ok(false);
    };
    let rtxn = vault.store.env.read_txn()?;
    Ok(crate::settings::device_only_worlds_in(&vault.store, &rtxn)?.contains(&world))
}

/// Whether a full-window send of `doc` ships nothing now: the window belongs
/// to a flagged world, or it carries a CLAIM of a flagged world or an edge
/// naming one.
pub fn window_withheld(vault: &Vault, key: &WindowKey, doc: &LoroDoc) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    let flagged = crate::settings::device_only_worlds_in(&vault.store, &rtxn)?;
    if flagged.is_empty() {
        return Ok(false);
    }
    if key.world().is_some_and(|world| flagged.contains(&world)) {
        return Ok(true);
    }
    let mut carried = false;
    let mut endpoints = BTreeSet::new();
    map_for_each_value_bytes(&doc.get_map("entities"), |_, blob| {
        carried |= blob.is_some_and(|raw| claim_in(raw, &flagged));
    });
    map_for_each_value_bytes(&doc.get_map("edges"), |key, _| {
        if let Some((src, _, tgt)) = parse_edge_key(key) {
            endpoints.extend([src, tgt]);
        }
    });
    if carried {
        return Ok(true);
    }
    for id in endpoints {
        if crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &rtxn, &id)?
            .is_some_and(|raw| claim_in(&raw, &flagged))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The export of a withheld window: an empty document's update, so no
/// operation of the live window (pending, concurrent or committed) rides it.
pub(super) fn withheld_window_update() -> Result<Vec<u8>> {
    export_updates_from(&LoroDoc::new(), &VersionVector::default())
}

/// Ids among `entities` and the endpoints of `edges` (wherever those rows
/// live) that a device-only world keeps on this device. A CLAIM carrier
/// naming a flagged world is withheld whatever its key or stored row says.
/// Read inside the caller's export transaction.
pub(in crate::sync) fn device_only_ids(
    vault: &Vault,
    rtxn: &RoTxn<'_>,
    entities: &LoroMap,
    edges: &LoroMap,
) -> Result<HashSet<EntityId>> {
    let flagged = crate::settings::device_only_worlds_in(&vault.store, rtxn)?;
    let mut withheld = HashSet::new();
    if flagged.is_empty() {
        return Ok(withheld);
    }
    let mut ids = BTreeSet::new();
    map_for_each_value_bytes(entities, |key, blob| {
        if let Ok(id) = EntityId::from_hex(key) {
            if blob.is_some_and(|raw| claim_in(raw, &flagged)) {
                withheld.insert(id);
            }
            ids.insert(id);
        }
    });
    map_for_each_value_bytes(edges, |key, _| {
        if let Some((src, _, tgt)) = parse_edge_key(key) {
            ids.extend([src, tgt]);
        }
    });
    for id in ids {
        if !withheld.contains(&id)
            && crate::settings::device_only_withholds(&vault.store, rtxn, &flagged, &id)?
        {
            withheld.insert(id);
        }
    }
    Ok(withheld)
}

fn claim_in(raw: &[u8], flagged: &BTreeSet<EntityId>) -> bool {
    EntityMetadataHeader::parse(raw)
        .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_CLAIM)
        && crate::claim::decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)
            .is_ok_and(|body| body.world.is_some_and(|world| flagged.contains(&world)))
}
