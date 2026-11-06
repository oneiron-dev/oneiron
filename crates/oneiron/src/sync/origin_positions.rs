//! Row-paired lifecycle helpers for optional same-vault origin-position data.
//!
//! The source publisher reads canonical stored facts beside the real carrier.
//! Copying or publishing data never installs a position or grants authority.

use loro::{CommitOptions, LoroDoc, LoroValue};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::record_scope::origin_positions::{self as facts, OriginPosition};
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_ASSET_TEXT};
use crate::store::checkpoint_payload::rows::OwnerRef;
use crate::sync::checkpoint_payload::{Placement, SyncUnclassified};
use crate::sync::loro_support::{map_delete, map_get_bytes, map_insert_bytes};

mod import;
pub(crate) use import::VerifiedOriginPosition;
pub(in crate::sync) use import::{DeferredPositions, prepare};
pub use import::{OwnDevicePositionImport, prepare_own_device_push_positions};

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
    let bytes = map_get_bytes(&doc.get_map(ORIGIN_POSITIONS_MAP), key)?;
    let position = OriginPosition::decode(&bytes)?;
    holds_carrier(doc, key, &position).then_some((position, bytes))
}

fn holds_carrier(doc: &LoroDoc, key: &str, position: &OriginPosition) -> bool {
    let Some(id) = owner(key) else {
        return false;
    };
    let Some(carrier) = map_get_bytes(&doc.get_map("entities"), key) else {
        return false;
    };
    if !position.binds_carrier(&id, &carrier) {
        return false;
    }
    crate::sync::asset_body::references::bound_in(doc, &id, &carrier)
        .map(|reference| reference.encode())
        .transpose()
        .is_ok_and(|reference| position.row.file_reference == reference)
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

/// Mirrors the canonical stored position beside this real source-window
/// carrier. The caller commits with its normal bridge origin and vector.
/// Replacing or removing prior facts pins the window before their deletion.
pub(in crate::sync) fn mirror_local_position(
    vault: &crate::Vault,
    doc: &LoroDoc,
    window: &crate::sync::types::WindowKey,
    id: &EntityId,
) -> Result<bool> {
    if window.world().is_some() {
        return Ok(false);
    }
    let key = id.to_hex();
    let carrier = map_get_bytes(&doc.get_map("entities"), &key);
    let old = has_positions(doc)
        .then(|| map_get_bytes(&doc.get_map(ORIGIN_POSITIONS_MAP), &key))
        .flatten();
    if old.is_none()
        && !carrier.as_deref().is_some_and(|bytes| {
            crate::batch::EntityMetadataHeader::parse(bytes).is_some_and(|header| {
                matches!(
                    header.entity_type,
                    ENTITY_TYPE_ASSET | ENTITY_TYPE_ASSET_TEXT
                )
            })
        })
    {
        return Ok(false);
    }
    let next = match carrier {
        Some(carrier) => facts::capture_for_carrier(vault, id, &carrier)?
            .map(|position| position.encode())
            .transpose()?,
        None => None,
    };
    if old == next {
        return Ok(false);
    }
    if old.is_some() {
        crate::sync::window::require_history_free_window(vault, window)?;
    }
    match next {
        Some(bytes) => map_insert_bytes(&doc.get_map(ORIGIN_POSITIONS_MAP), &key, &bytes)?,
        None => {
            remove_carrier(doc, id)?;
        }
    }
    Ok(true)
}

/// Values whose captured birth (owner or source) no longer exists unchanged.
/// This reads no body, so an actor erase runs it after removing canonical
/// births, in that SAME writer, including sources from another window.
pub(in crate::sync) fn stale_birth_keys_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    doc: &LoroDoc,
) -> Result<Vec<String>> {
    if !has_positions(doc) {
        return Ok(Vec::new());
    }
    let mut stale = Vec::new();
    for key in doc.get_map(ORIGIN_POSITIONS_MAP).keys() {
        let Some((position, _)) = bound_position(doc, &key) else {
            stale.push(key.to_string());
            continue;
        };
        for row in std::iter::once(&position.row).chain(position.sources.iter()) {
            if facts::birth_digest_in_txn(vault, txn, &row.id)? != row.birth_digest {
                stale.push(key.to_string());
                break;
            }
        }
    }
    Ok(stale)
}

/// Drops facts that no longer match the current canonical stamp, complete
/// source set, facets, incarnation or checked body. Erased/replaced facts do
/// not survive just because their owner carrier's bytes remained unchanged.
/// The result-body pin precedes the read snapshot; the history pin precedes
/// every deletion. The normal export/persist caller owns later persistence.
pub(in crate::sync) fn scrub_stale(
    vault: &crate::Vault,
    doc: &LoroDoc,
    window: &crate::sync::types::WindowKey,
) -> Result<bool> {
    if !has_positions(doc) {
        return Ok(false);
    }
    let _bodies = vault.pin_all_result_bodies();
    let stale = {
        let txn = vault.store.env.read_txn()?;
        let mut stale = Vec::new();
        for key in doc.get_map(ORIGIN_POSITIONS_MAP).keys() {
            let keep = if let Some((position, _)) = bound_position(doc, &key) {
                facts::capture_in_txn(vault, &txn, &position.row.id)?.as_ref() == Some(&position)
            } else {
                false
            };
            if !keep {
                stale.push(key.to_string());
            }
        }
        stale
    };
    if stale.is_empty() {
        return Ok(false);
    }
    crate::sync::window::require_history_free_window(vault, window)?;
    let map = doc.get_map(ORIGIN_POSITIONS_MAP);
    for key in stale {
        map_delete(&map, &key)?;
    }
    doc.commit_with(CommitOptions::new().origin(crate::sync::bridge::BRIDGE_ORIGIN));
    Ok(true)
}

/// Removes the exact root keys selected in the actor erase's own snapshot.
/// The caller preserves the existing history pin, commit and resync order.
pub(in crate::sync) fn remove_keys(doc: &LoroDoc, keys: &[String]) -> Result<()> {
    if has_positions(doc) {
        let map = doc.get_map(ORIGIN_POSITIONS_MAP);
        for key in keys {
            map_delete(&map, key)?;
        }
    }
    Ok(())
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
