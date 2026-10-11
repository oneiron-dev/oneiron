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
//! edge; that removal would also flow back here.

use std::collections::{BTreeSet, HashSet};

use heed::RoTxn;
use loro::{LoroDoc, LoroMap};

use super::super::bridge::parse_edge_key;
use super::super::loro_support::{export_updates_from, map_for_each_value_bytes};
use super::super::types::WindowKey;
use crate::Vault;
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;

/// Whether `key` is a window of a world flagged device-only on this device,
/// read against the flag as it stands now.
pub fn window_is_device_only(vault: &Vault, key: &WindowKey) -> Result<bool> {
    let Some(world) = key.world() else {
        return Ok(false);
    };
    let rtxn = vault.store.env.read_txn()?;
    Ok(crate::settings::device_only_worlds_in(&vault.store, &rtxn)?.contains(&world))
}

/// The export of a withheld window: no operation and no state.
pub(super) fn withheld_window_update(doc: &LoroDoc) -> Result<Vec<u8>> {
    export_updates_from(doc, &doc.oplog_vv())
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
