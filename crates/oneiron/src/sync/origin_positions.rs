//! Row-paired lifecycle helpers for optional same-vault origin-position data.
//!
//! These helpers are not a publisher or an importer. In particular, copying
//! a carrier never installs its position or grants a reader any authority.

use loro::{LoroDoc, LoroValue};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::record_scope::origin_positions::OriginPosition;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT};
use crate::sync::checkpoint_payload::{OwnerRef, Placement, SyncUnclassified};
use crate::sync::loro_support::{map_delete, map_get_bytes, map_insert_bytes};

pub(crate) const ORIGIN_POSITIONS_MAP: &str = "origin_positions";

fn has_positions(doc: &LoroDoc) -> bool {
    matches!(doc.get_value(), LoroValue::Map(roots) if roots.contains_key(ORIGIN_POSITIONS_MAP))
}

fn owner(key: &str) -> Option<EntityId> {
    EntityId::from_hex(key).ok().filter(|id| id.to_hex() == key)
}

/// The value beside its exact owner bytes and native body reference, if
/// present. This checks window data binding only, not canonical stored facts
/// or the authority of the connection that brought the value.
fn bound_position(doc: &LoroDoc, key: &str) -> Option<(OriginPosition, Vec<u8>)> {
    if !has_positions(doc) {
        return None;
    }
    let id = owner(key)?;
    let bytes = map_get_bytes(&doc.get_map(ORIGIN_POSITIONS_MAP), key)?;
    let position = OriginPosition::decode(&bytes)?;
    let carrier = map_get_bytes(&doc.get_map("entities"), key)?;
    if !position.binds_carrier(&id, &carrier) {
        return None;
    }
    let reference = crate::sync::asset_body::references::bound_in(doc, &id, &carrier)
        .map(|reference| reference.encode())
        .transpose()
        .ok()?;
    (position.row.file_reference == reference).then_some((position, bytes))
}

/// Copies optional data only for an own-machine projection, after that
/// projection copied its final entities and native body references. The
/// caller must not use this at a crossing to or from another vault.
/// Projected, masked, missing and otherwise changed owner bytes stay behind.
pub(in crate::sync) fn copy_for_own_machines(source: &LoroDoc, out: &LoroDoc) -> Result<()> {
    if !has_positions(source) {
        return Ok(());
    }
    for key in out.get_map("entities").keys() {
        let Some((position, bytes)) = bound_position(source, &key) else {
            continue;
        };
        let Some(carrier) = map_get_bytes(&out.get_map("entities"), &key) else {
            continue;
        };
        if map_get_bytes(&source.get_map("entities"), &key).as_deref() != Some(carrier.as_slice()) {
            continue;
        }
        let reference =
            crate::sync::asset_body::references::bound_in(out, &position.row.id, &carrier)
                .map(|reference| reference.encode())
                .transpose()?;
        if position.row.file_reference == reference {
            map_insert_bytes(&out.get_map(ORIGIN_POSITIONS_MAP), &key, &bytes)?;
        }
    }
    Ok(())
}

/// Removes data with its owner. The caller preserves the native pin-before-
/// delete, history-free replacement and bridge-commit order of that removal.
pub(in crate::sync) fn remove_carrier(doc: &LoroDoc, id: &EntityId) -> Result<bool> {
    if !has_positions(doc) {
        return Ok(false);
    }
    let map = doc.get_map(ORIGIN_POSITIONS_MAP);
    let key = id.to_hex();
    if map.get(&key).is_none() {
        return Ok(false);
    }
    map_delete(&map, &key)?;
    Ok(true)
}

/// Removes orphaned, malformed or byte-mismatched values after an egress
/// scrub drops or projects entities. The caller owns the same history-free
/// pin and commit as the entity scrub. No canonical position is installed.
pub(in crate::sync) fn drop_unbound(doc: &LoroDoc) -> Result<bool> {
    if !has_positions(doc) {
        return Ok(false);
    }
    let map = doc.get_map(ORIGIN_POSITIONS_MAP);
    let stale: Vec<String> = map
        .keys()
        .filter(|key| bound_position(doc, key).is_none())
        .map(|key| key.to_string())
        .collect();
    for key in &stale {
        map_delete(&map, key)?;
    }
    Ok(!stale.is_empty())
}

/// The entire value is payload under its row's owner, with its native source
/// rows as dependencies. Digests and scope fields never become a plaintext
/// Structure value. A facet id is a position, not necessarily a stored row.
/// The root's key is only the canonical row id.
pub(in crate::sync) fn checkpoint_entry(key: &str, bytes: &[u8]) -> Placement {
    let Some(id) = owner(key) else {
        return Placement::unclassified(None, SyncUnclassified::Undecodable);
    };
    let holder = OwnerRef::entity(&id);
    let Some(position) = OriginPosition::decode(bytes) else {
        return Placement::unclassified(Some(holder), SyncUnclassified::Undecodable);
    };
    if position.row.id != id
        || !matches!(
            position.row.kind,
            ENTITY_TYPE_ASSET | ENTITY_TYPE_ASSET_TEXT
        )
    {
        return Placement::unclassified(Some(holder), SyncUnclassified::Undecodable);
    }
    let dependencies: std::collections::BTreeSet<EntityId> =
        position.sources.iter().map(|source| source.id).collect();
    Placement::owned(holder, dependencies.iter().map(OwnerRef::entity).collect())
}
