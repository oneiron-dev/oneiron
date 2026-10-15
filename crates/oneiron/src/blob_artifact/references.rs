//! Which artifacts hold which version bytes, on every vault (H125).
//!
//! The version chain and [`ASSET_REF`](super::store_keys::ASSET_REF) are local rows: a replica
//! holds neither for an artifact it received. The `blob.version` claims do replicate, so each
//! vault records here which artifacts hold which bytes, as their claims named them. Artifact
//! delete reads it to find a replicated artifact's bytes and to keep bytes another live artifact
//! still holds, and replicated ingest reads it to take back bytes a live artifact holds again.
//!
//! A pair lives from the first claim naming it until its artifact's delete, like the `asset_ref`
//! row it stands in for: deleting or rewriting a claim leaves it, so the artifact's later delete
//! still finds the bytes, even when the artifact has not arrived yet. A claim naming an artifact
//! already deleted here records nothing and settles its bytes at once.

use heed::{RoTxn, RwTxn};
use rmpv::Value;

use crate::batch::ENTITY_METADATA_HEADER_LEN;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::store::Store;

use super::provenance::BLOB_VERSION_CLAIM_PREDICATE;
use super::store_keys::BLOB_ARTIFACT_CONTENT_HASH_LEN;
use super::versions::{KEY_CONTENT_HASH, KEY_VERSION};

type ContentHash = [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN];

/// Which artifacts hold the bytes under each content hash: one row per pair a `blob.version`
/// claim named here. Key: bytes32 + id16 (artifact).
const VERSION_CLAIM: SideTable<(ContentHash, EntityId), (), Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_VERSION_CLAIM);

/// The same pairs keyed by artifact, so an artifact's delete reads its own bytes without a scan.
/// Key: id16 (artifact) + bytes32.
const CLAIMED_HASH: SideTable<(EntityId, ContentHash), (), Raw> =
    SideTable::new(&side_table::BLOB_ARTIFACT_CLAIMED_HASH);

/// The value of a fence a release planted. A fence an explicit delete planted is empty, and only
/// a release fence is ever lifted.
const RELEASE_FENCE: &[u8] = b"blob_artifact:release";

/// The value of a fence a hard erase planted on a carrier it scrubbed: a reference it took, or a
/// text derived from the bytes it took. It is never lifted. Like a release fence, the export door
/// drops its carrier with an ordinary delete (`super::erase`).
const ERASE_FENCE: &[u8] = b"blob_artifact:erase";

/// The artifact and content hash `body` names, when it is a `blob.version` claim.
pub(super) fn version_claim_reference(body: &ClaimBody) -> Option<(EntityId, ContentHash)> {
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

/// Records the pair one claim put names, at the claim put chokepoint for local and replicated
/// claims alike.
///
/// A claim naming an artifact this vault already deleted records nothing: the delete ran without
/// its hash, so the bytes are released now unless something live holds them. A claim naming a
/// live artifact lifts a fence an earlier release left on its bytes, so the export door keeps
/// their carrier and the next rematerialization takes them back.
///
/// A late reference (`super::erase::LateReference`) is refused: a claim a hard erase took, a claim
/// naming bytes a hard erase took here, and a claim naming an artifact whose hard erase was decided
/// here. Replicated ingest pierces such a claim before it reaches this put
/// (`Vault::refuse_erased_blob_arrival_in_txn`); every other door gets the refusal.
pub(crate) fn record_version_claim(
    store: &Store,
    txn: &mut RwTxn<'_>,
    claim: &EntityId,
    body: &ClaimBody,
) -> Result<()> {
    let Some((artifact, hash)) = version_claim_reference(body) else {
        return Ok(());
    };
    if super::erase::late_reference_in_txn(store, txn, claim, body)?.is_some() {
        return Err(Error::Artifact(
            if super::erase::reference_erased(store, txn, claim)? {
                ArtifactError::BlobVersionErased
            } else {
                ArtifactError::BlobContentErased
            },
        ));
    }
    let deleted_here = {
        let raw = store.entities.get(txn, artifact.as_bytes())?;
        crate::deletion::row_deletion_marked(store, txn, &artifact, raw.as_deref())?
    };
    if deleted_here {
        return super::lifecycle::release_bytes_of_deleted_artifact(store, txn, &artifact, &hash);
    }
    VERSION_CLAIM.put(store, txn, &(hash, artifact), &())?;
    CLAIMED_HASH.put(store, txn, &(artifact, hash), &())?;
    if artifact_is_live(store, txn, &artifact)? {
        lift_release_fence(
            store,
            txn,
            &super::versions::blob_artifact_asset_entity_id(&hash)?,
        )?;
    }
    Ok(())
}

/// The version number a `blob.version` claim body names.
pub(super) fn version_claim_version(body: &ClaimBody) -> Option<u64> {
    let Value::Map(entries) = &body.value else {
        return None;
    };
    entries
        .iter()
        .find_map(|(key, value)| match (key.as_str(), value) {
            (Some(KEY_VERSION), Value::Integer(version)) => version.as_u64(),
            _ => None,
        })
}

/// The content hashes the `blob.version` claims here named for `artifact`.
pub(super) fn claimed_hashes(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<Vec<ContentHash>> {
    let mut hashes = Vec::new();
    for row in CLAIMED_HASH.iter_from(store, txn, artifact.as_bytes())? {
        let ((_, hash), ()) = row?;
        hashes.push(hash);
    }
    Ok(hashes)
}

/// Drops every pair naming `artifact`, at its delete.
pub(super) fn forget_claimed_hashes(
    store: &Store,
    txn: &mut RwTxn<'_>,
    artifact: &EntityId,
) -> Result<()> {
    for hash in claimed_hashes(store, txn, artifact)? {
        CLAIMED_HASH.delete(store, txn, &(*artifact, hash))?;
        VERSION_CLAIM.delete(store, txn, &(hash, *artifact))?;
    }
    Ok(())
}

/// Whether a `blob.version` claim here named `artifact`: its delete has bytes to settle even
/// when its row never arrived.
pub(crate) fn claimed_hash_rows_exist(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
) -> Result<bool> {
    Ok(CLAIMED_HASH
        .iter_from(store, txn, artifact.as_bytes())?
        .next()
        .transpose()?
        .is_some())
}

/// Every artifact a hold row names for the bytes under `hash`, live or not: its `asset_ref` rows
/// and the pairs its version claims recorded. Never an id in `except`.
pub(super) fn holders(
    store: &Store,
    txn: &RoTxn<'_>,
    hash: &ContentHash,
    except: &[EntityId],
) -> Result<Vec<EntityId>> {
    let mut found = Vec::new();
    for row in super::store_keys::ASSET_REF.iter_from(store, txn, hash)? {
        let ((_, holder), ()) = row?;
        found.push(holder);
    }
    for row in VERSION_CLAIM.iter_from(store, txn, hash)? {
        let ((_, holder), ()) = row?;
        found.push(holder);
    }
    found.retain(|holder| !except.contains(holder));
    found.sort_unstable();
    found.dedup();
    Ok(found)
}

/// The artifacts whose hold keeps the bytes under `hash` past a plain delete: an `asset_ref` row,
/// or a live artifact's version claim. Never an id in `except`.
pub(super) fn live_holders(
    store: &Store,
    txn: &RoTxn<'_>,
    hash: &ContentHash,
    except: &[EntityId],
) -> Result<Vec<EntityId>> {
    let mut found = Vec::new();
    for row in super::store_keys::ASSET_REF.iter_from(store, txn, hash)? {
        let ((_, holder), ()) = row?;
        found.push(holder);
    }
    for row in VERSION_CLAIM.iter_from(store, txn, hash)? {
        let ((_, holder), ()) = row?;
        if artifact_is_live(store, txn, &holder)? {
            found.push(holder);
        }
    }
    found.retain(|holder| !except.contains(holder));
    found.sort_unstable();
    found.dedup();
    Ok(found)
}

/// Drops the pair a version claim recorded for `artifact` and `hash`.
pub(super) fn forget_hold(
    store: &Store,
    txn: &mut RwTxn<'_>,
    hash: &ContentHash,
    artifact: &EntityId,
) -> Result<()> {
    VERSION_CLAIM.delete(store, txn, &(*hash, *artifact))?;
    CLAIMED_HASH.delete(store, txn, &(*artifact, *hash))?;
    Ok(())
}

/// Whether an artifact live here, other than `except`, holds the bytes under `hash`.
pub(super) fn held_by_live_artifact(
    store: &Store,
    txn: &RoTxn<'_>,
    hash: &ContentHash,
    except: Option<&EntityId>,
) -> Result<bool> {
    for row in VERSION_CLAIM.iter_from(store, txn, hash)? {
        let ((_, artifact), ()) = row?;
        if Some(&artifact) != except && artifact_is_live(store, txn, &artifact)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A stored artifact row with its body, under no delete this vault holds.
pub(super) fn artifact_is_live(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
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
        Some(raw.as_ref()),
    )?)
}

/// Fences an ASSET whose last artifact went: replicated ingest refuses its carrier, and the
/// export door deletes that carrier from the live window without pinning it history-free. A
/// fence already there stays as it is: an explicit delete's fence never becomes liftable.
pub(super) fn fence_released_asset(
    store: &Store,
    txn: &mut RwTxn<'_>,
    asset: &EntityId,
) -> Result<()> {
    let key = HexId(*asset);
    if crate::deletion::ROW_DELETION_FENCE.contains(store, txn, &key)? {
        return Ok(());
    }
    crate::deletion::ROW_DELETION_FENCE.put(store, txn, &key, &RELEASE_FENCE.to_vec())
}

/// Lifts the release fence on a replicated artifact ASSET as its carrier comes in, when an
/// artifact live here holds its bytes again: the same bytes uploaded anew. The caller has
/// checked that no tombstone names the ASSET.
#[cfg(feature = "sync")]
pub(crate) fn readmit_held_asset_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    asset: &EntityId,
    body: &[u8],
) -> Result<()> {
    if !crate::deletion::ROW_DELETION_FENCE.contains(store, txn, &HexId(*asset))? {
        return Ok(());
    }
    let hash: ContentHash = *blake3::hash(body).as_bytes();
    if super::versions::blob_artifact_asset_entity_id(&hash)? != *asset
        || super::erase::content_erased(store, txn, &hash)?.is_some()
        || !held_by_live_artifact(store, txn, &hash, None)?
    {
        return Ok(());
    }
    lift_release_fence(store, txn, asset)
}

/// Whether only a release fences `asset`: its fence holds the release value and no hard-delete
/// marker stands beside it.
fn release_fenced_only(store: &Store, txn: &RoTxn<'_>, asset: &EntityId) -> Result<bool> {
    let key = HexId(*asset);
    Ok(crate::deletion::ROW_DELETION_FENCE
        .get(store, txn, &key)?
        .is_some_and(|value| value == RELEASE_FENCE)
        && !crate::deletion::HARD_DELETE_MARKER.contains(store, txn, &key)?)
}

/// Marks a carrier a hard erase just scrubbed (`super::erase`) with the erase's fence, when the
/// scrub planted the fence it holds. A fence it held before the erase stays as it was.
pub(crate) fn fence_erased_carrier(
    store: &Store,
    txn: &mut RwTxn<'_>,
    carrier: &EntityId,
    fenced_before: bool,
) -> Result<()> {
    if fenced_before {
        return Ok(());
    }
    crate::deletion::ROW_DELETION_FENCE.put(store, txn, &HexId(*carrier), &ERASE_FENCE.to_vec())
}

/// Whether a hard erase fenced `id`: a carrier it scrubbed, or one it refused at arrival. A local
/// put there is no sanctioned recreation; it would write erased content back.
pub(crate) fn erase_fenced(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    Ok(crate::deletion::ROW_DELETION_FENCE
        .get(store, txn, &HexId(*id))?
        .is_some_and(|value| value == ERASE_FENCE))
}

/// Whether the export door drops `id`'s carrier with an ordinary delete, without pinning its
/// window history-free: a release or a hard erase fenced it, and no hard-delete marker stands
/// beside the fence. Nobody withdrew a delete there; the old set operation stays in Loro history
/// until the sweep's shallow compaction, as for any deleted row.
#[cfg(feature = "sync")]
pub(crate) fn fenced_without_pin(store: &Store, txn: &RoTxn<'_>, id: &EntityId) -> Result<bool> {
    let key = HexId(*id);
    Ok(crate::deletion::ROW_DELETION_FENCE
        .get(store, txn, &key)?
        .is_some_and(|value| value == RELEASE_FENCE || value == ERASE_FENCE)
        && !crate::deletion::HARD_DELETE_MARKER.contains(store, txn, &key)?)
}

/// Drops the fence a release left on `asset`. A fence an explicit delete left, and a hard-delete
/// marker, stay.
fn lift_release_fence(store: &Store, txn: &mut RwTxn<'_>, asset: &EntityId) -> Result<()> {
    if release_fenced_only(store, txn, asset)? {
        crate::deletion::ROW_DELETION_FENCE.delete(store, txn, &HexId(*asset))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
