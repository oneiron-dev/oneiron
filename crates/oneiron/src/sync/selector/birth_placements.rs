//! Birth placements on a copy to another vault (FIX 3656, Engine ruling A).
//!
//! A replicated TASK or SUMMARY lands unstamped (`stamp_put`), so a read
//! narrowed on worlds or facets keeps it out. A copy to another vault
//! therefore carries, beside each such row, the placement its stored birth
//! stamp holds ([`BirthPlacement`]), in the window's `row_birth_placements`
//! map: one entry per row, keyed by the row's canonical hex id. The entry
//! rides the same update bytes as its row, so whatever authenticates that
//! update covers both: the federation session that serves it, or the
//! guest-share envelope's signature over it. A row whose stamp is not one a
//! local birth door writes carries none.
//!
//! Admission reads the entries before it copies a row
//! (`admission::routing::Routes::plan`): an entry that does not decode, or
//! names no row the update carries as that kind, refuses the update, and a
//! guest's placement is remapped into the guest's foreign WORLD copy. The map
//! never enters the admitted bytes, and a member's update, first-party here,
//! takes none of it.

use std::collections::BTreeMap;

use loro::LoroDoc;

use crate::Vault;
use crate::batch::EntityMetadataHeader;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::federation::record_scope::{
    BirthPlacement, carries_birth_placement, stored_placement_in_txn,
};
use crate::sync::loro_support::{map_for_each_value_bytes, map_get_bytes, map_insert_bytes};

/// The window map that carries birth placements beside their rows.
const BIRTH_PLACEMENTS_MAP: &str = "row_birth_placements";

/// Writes into `doc`, a copy to another vault, the birth placement each TASK
/// and SUMMARY row it carries is stored at here, read in one snapshot. A row
/// not live here as the kind the copy carries, or with no stamp of the shape
/// a local birth door writes, carries none.
pub(super) fn carry_birth_placements(vault: &Vault, doc: &LoroDoc) -> Result<()> {
    let mut rows = Vec::new();
    map_for_each_value_bytes(&doc.get_map("entities"), |key, blob| {
        let Some(header) = blob.and_then(EntityMetadataHeader::parse) else {
            return;
        };
        if carries_birth_placement(header.entity_type)
            && let Some(id) = EntityId::from_hex(key).ok().filter(|id| id.to_hex() == key)
        {
            rows.push((id, header.entity_type));
        }
    });
    if rows.is_empty() {
        return Ok(());
    }
    let mut placements = Vec::with_capacity(rows.len());
    {
        let txn = vault.store.env.read_txn()?;
        for (id, kind) in rows {
            if let Some(placement) = stored_placement_in_txn(&vault.store, &txn, id, kind)? {
                placements.push((id, placement.encode()?));
            }
        }
    }
    if placements.is_empty() {
        return Ok(());
    }
    let map = doc.get_map(BIRTH_PLACEMENTS_MAP);
    for (id, bytes) in placements {
        map_insert_bytes(&map, &id.to_hex(), &bytes)?;
    }
    doc.commit();
    Ok(())
}

/// Each birth placement `remote`, a peer's update, carries, by row. An entry
/// whose key is not a canonical id, whose value is not a canonical
/// placement, or whose row the update does not carry as the placement's kind
/// refuses the update: a placement travels only beside its row.
pub(super) fn carried_placements(remote: &LoroDoc) -> Result<BTreeMap<EntityId, BirthPlacement>> {
    let entities = remote.get_map("entities");
    let mut carried = BTreeMap::new();
    let mut malformed = false;
    map_for_each_value_bytes(&remote.get_map(BIRTH_PLACEMENTS_MAP), |key, value| {
        let id = EntityId::from_hex(key).ok().filter(|id| id.to_hex() == key);
        let placement = value.and_then(BirthPlacement::decode);
        let kind = map_get_bytes(&entities, key)
            .as_deref()
            .and_then(EntityMetadataHeader::parse)
            .map(|header| header.entity_type);
        match (id, placement) {
            (Some(id), Some(placement)) if kind == Some(placement.kind) => {
                carried.insert(id, placement);
            }
            _ => malformed = true,
        }
    });
    if malformed {
        return Err(Error::InvalidClaimBody(
            "a carried birth placement is malformed or names no row the update carries",
        ));
    }
    Ok(carried)
}
