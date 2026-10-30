//! A window's `birth_scopes` map carries each replicated row's birth scope
//! beside its entity carrier (FIX 3656; Engine ruling 09:39 A), so a peer
//! stamps the row where it was born in the same import that brings it.
//!
//! Key: the owner's canonical (lowercase) hex id. Value: the typed stamp
//! `federation::record_scope::carried_birth_scope` encodes; the receiver's
//! record scope judges it before it stamps anything. A carrier travels only
//! with its owner: one whose entity carrier leaves the window leaves with it.

use loro::{LoroDoc, LoroValue, ValueOrContainer};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::sync::loro_support::{map_delete, map_get_bytes, map_insert_bytes};

/// The window map that carries row birth scopes.
pub(in crate::sync) const BIRTH_SCOPES_MAP: &str = "birth_scopes";

/// Mirrors `id`'s birth scope into `doc` beside its carrier. An equal
/// carrier stays; a different one is replaced, since the local stamp is the
/// authority for its own row. A row with no stamp that travels writes none.
/// Returns whether the map changed.
pub(in crate::sync) fn mirror_local_birth_scope(
    vault: &Vault,
    doc: &LoroDoc,
    id: &EntityId,
) -> Result<bool> {
    let rtxn = vault.store.env.read_txn()?;
    let Some(bytes) =
        crate::federation::record_scope::carried_birth_scope(&vault.store, &rtxn, *id)?
    else {
        return Ok(false);
    };
    let map = doc.get_map(BIRTH_SCOPES_MAP);
    let key = id.to_hex();
    if map_get_bytes(&map, &key).as_deref() == Some(bytes.as_slice()) {
        return Ok(false);
    }
    map_insert_bytes(&map, &key, &bytes)?;
    Ok(true)
}

/// The birth scope `doc` carries for `id`.
pub(in crate::sync) fn carried(doc: &LoroDoc, id: &EntityId) -> Option<Vec<u8>> {
    map_get_bytes(&doc.get_map(BIRTH_SCOPES_MAP), &id.to_hex())
}

/// Drops every birth scope carrier in `doc` whose entity carrier is gone.
/// Returns whether any went.
pub(in crate::sync) fn drop_orphan_birth_scopes(doc: &LoroDoc) -> Result<bool> {
    let entities = doc.get_map("entities");
    let map = doc.get_map(BIRTH_SCOPES_MAP);
    let orphans: Vec<String> = map
        .keys()
        .map(|key| key.to_string())
        .filter(|key| {
            !matches!(
                entities.get(key),
                Some(ValueOrContainer::Value(LoroValue::Binary(_)))
            )
        })
        .collect();
    for key in &orphans {
        map_delete(&map, key)?;
    }
    Ok(!orphans.is_empty())
}
