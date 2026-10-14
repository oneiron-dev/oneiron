//! Which artifacts hold which version bytes, on every vault (H125).
//!
//! The version chain and [`ASSET_REF`](super::store_keys::ASSET_REF) are local rows: a replica
//! holds neither for an artifact it received. The `blob.version` claims do replicate, so their
//! projection here is each vault's own view of which artifacts hold which bytes. Artifact delete
//! reads it to find a replicated artifact's bytes and to keep bytes another live artifact still
//! holds, and replicated ingest reads it to take back bytes a live artifact holds again.

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::side_table::{self, HexId, Raw, SideKey, SideTable};
use crate::store::Store;

use super::provenance::BLOB_VERSION_CLAIM_PREDICATE;
use super::store_keys::BLOB_ARTIFACT_CONTENT_HASH_LEN;
use super::versions::{KEY_CONTENT_HASH, blob_artifact_asset_entity_id};

type ContentHash = [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN];

/// The artifact each `blob.version` claim names, under the claim's content hash. Key: bytes32 +
/// id16 (claim); value: id16 (artifact). Kept at the claim put chokepoint for local and
/// replicated claims alike, and removed with the claim.
const VERSION_CLAIM: SideTable<(ContentHash, EntityId), EntityId, Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_VERSION_CLAIM);

/// The same rows keyed by artifact, so an artifact's delete reads its own bytes without a scan.
/// Key: id16 (artifact) + bytes32 + id16 (claim).
const CLAIMED_HASH: SideTable<(EntityId, ContentHash, EntityId), (), Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_CLAIMED_HASH);

/// The artifact and content hash `body` names, when it is a `blob.version` claim.
fn version_claim_reference(body: &ClaimBody) -> Option<(EntityId, ContentHash)> {
    if body.predicate != BLOB_VERSION_CLAIM_PREDICATE {
        return None;
    }
    let ClaimSubject::Entity(artifact) = body.subject else {
        return None;
    };
    let Value::Map(entries) = &body.value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| match (key.as_str(), value) {
            (Some(KEY_CONTENT_HASH), Value::Binary(hash)) => ContentHash::try_from(hash.as_slice())
                .ok()
                .map(|hash| (artifact, hash)),
            _ => None,
        })
}

/// Projects one claim put. Returns the keys written, for the claim's projection reverse index.
pub(crate) fn project_version_claim(
    store: &Store,
    txn: &mut RwTxn<'_>,
    claim: EntityId,
    body: &ClaimBody,
) -> Result<Vec<Vec<u8>>> {
    let Some((artifact, hash)) = version_claim_reference(body) else {
        return Ok(Vec::new());
    };
    VERSION_CLAIM.put(store, txn, &(hash, claim), &artifact)?;
    CLAIMED_HASH.put(store, txn, &(artifact, hash, claim), &())?;
    Ok(vec![
        VERSION_CLAIM.key_bytes(&(hash, claim)),
        CLAIMED_HASH.key_bytes(&(artifact, hash, claim)),
    ])
}

/// Removes the row at `key` from a claim's projection reverse index. `false` when the key
/// belongs to another projection.
pub(crate) fn remove_version_claim_projection(
    store: &Store,
    txn: &mut RwTxn<'_>,
    claim: EntityId,
    key: &[u8],
) -> Result<bool> {
    let corrupt = || Error::CorruptedIndex("claim projection reverse key");
    if let Some(tail) = key.strip_prefix(VERSION_CLAIM.decl().prefix) {
        let (hash, named) = <(ContentHash, EntityId)>::decode_key(tail).ok_or_else(corrupt)?;
        if named != claim {
            return Err(corrupt());
        }
        VERSION_CLAIM.delete(store, txn, &(hash, claim))?;
        return Ok(true);
    }
    if let Some(tail) = key.strip_prefix(CLAIMED_HASH.decl().prefix) {
        let (artifact, hash, named) =
            <(EntityId, ContentHash, EntityId)>::decode_key(tail).ok_or_else(corrupt)?;
        if named != claim {
            return Err(corrupt());
        }
        CLAIMED_HASH.delete(store, txn, &(artifact, hash, claim))?;
        return Ok(true);
    }
    Ok(false)
}

/// The content hashes the `blob.version` claims here name for `artifact`.
pub(super) fn claimed_hashes(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<Vec<ContentHash>> {
    let mut hashes = Vec::new();
    for row in CLAIMED_HASH.iter_from(store, txn, artifact.as_bytes())? {
        let ((_, hash, _), ()) = row?;
        if !hashes.contains(&hash) {
            hashes.push(hash);
        }
    }
    Ok(hashes)
}

/// Whether an artifact live here, other than `except`, holds the bytes under `hash`.
pub(super) fn held_by_live_artifact(
    store: &Store,
    txn: &RoTxn<'_>,
    hash: &ContentHash,
    except: Option<&EntityId>,
) -> Result<bool> {
    for row in VERSION_CLAIM.iter_from(store, txn, hash)? {
        let (_, artifact) = row?;
        if Some(&artifact) != except && artifact_is_live(store, txn, &artifact)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A stored artifact row with its body, under no delete this vault holds.
fn artifact_is_live(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Ok(false);
    };
    if raw.len() <= ENTITY_METADATA_HEADER_LEN || raw[0] != ENTITY_TYPE_BLOB_ARTIFACT {
        return Ok(false);
    }
    Ok(!crate::deletion::row_deletion_marked(
        store,
        txn,
        id,
        Some(raw),
    )?)
}

/// Fences an ASSET whose last artifact went: replicated ingest refuses its carrier, and the
/// export door scrubs that carrier from the live window and pins the window history-free.
pub(super) fn fence_released_asset(
    store: &Store,
    txn: &mut RwTxn<'_>,
    asset: &EntityId,
) -> Result<()> {
    crate::deletion::ROW_DELETION_FENCE.put(store, txn, &HexId(*asset), &Vec::new())
}

/// Lifts the fence on a replicated artifact ASSET whose bytes an artifact live here holds again:
/// the same bytes uploaded anew, or a version claim that arrived after its artifact's delete.
/// The caller has checked that no tombstone names the ASSET. A hard-delete marker stays final.
#[cfg(feature = "sync")]
pub(crate) fn readmit_held_asset_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    asset: &EntityId,
    body: &[u8],
) -> Result<()> {
    let key = HexId(*asset);
    if !crate::deletion::ROW_DELETION_FENCE.contains(store, txn, &key)?
        || crate::deletion::HARD_DELETE_MARKER.contains(store, txn, &key)?
    {
        return Ok(());
    }
    let hash: ContentHash = *blake3::hash(body).as_bytes();
    if blob_artifact_asset_entity_id(&hash)? != *asset
        || !held_by_live_artifact(store, txn, &hash, None)?
    {
        return Ok(());
    }
    crate::deletion::ROW_DELETION_FENCE.delete(store, txn, &key)?;
    Ok(())
}

#[cfg(test)]
mod tests;
