//! Blob artifact delete path: version-chain, head, and asset-ref cleanup,
//! and the release of one response version its last step claim let go of
//! (FIX 6225).

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::{ENTITY_TYPE_ASSET, ENTITY_TYPE_CLAIM};
use crate::store::Store;
use crate::store::ppr_cache_invalidation as ppr;

use super::holders::artifact_hashes;
use super::references::{
    claimed_hash_rows_exist, fence_released_asset, forget_claimed_hashes,
    forget_claimed_hashes_except_in_txn, forget_released_pair_in_txn, held_by_live_artifact,
    live_version_claim_reference, retained_claim_names,
};
use super::store_keys::{ASSET_REF, BLOB_ARTIFACT_CONTENT_HASH_LEN};
use super::versions::{HEAD, VERSIONS, blob_artifact_asset_entity_id};

/// Outcome of blob-artifact lifecycle cleanup: index flags and graph
/// neighbors from any orphaned ASSET entities deleted with the chain, for
/// the caller to fold into its own deletion accounting.
#[derive(Debug, Default)]
pub(crate) struct BlobArtifactLifecycleCleanup {
    pub(crate) had_vector: bool,
    pub(crate) had_graph_mutation: bool,
    pub(crate) neighbors: Vec<EntityId>,
}

/// Removes an artifact's version chain, head record, born-from index rows and
/// asset-reference rows, hard-deleting every ASSET entity this artifact was the LAST
/// reference to — version bytes never outlive the last artifact that holds
/// them, on the vault that wrote them or on any replica (H125).
///
/// The artifact's bytes are its chain's hashes plus every hash its
/// replicated `blob.version` claims name: a replica has no chain of its own.
/// Those claims count only for an artifact row, or for an id with no row
/// here (an artifact whose delete arrived first), never for another kind of
/// row a claim names. Bytes stay while an `asset_ref` row (one per
/// content-hash × local artifact pair) or a live artifact's version claim
/// still holds them. Runs inside every entity delete path (batch delete,
/// purge, soft erase, remote tombstone replay).
///
/// A released ASSET gets a deletion fence, never a tombstone: its id is the
/// hash of its bytes, and a tombstone would refuse the same bytes uploaded
/// again on every peer for good. The fence refuses a stale carrier at
/// replicated ingest, and the export door deletes that carrier from the live
/// window as an ordinary delete. A new artifact holding the same bytes lifts it.
pub(crate) fn delete_blob_artifact_lifecycle_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    deindex: &dyn Fn(
        &mut heed::RwTxn<'_>,
        &EntityId,
    ) -> crate::error::Result<(bool, bool, bool, Vec<EntityId>)>,
) -> Result<BlobArtifactLifecycleCleanup> {
    crate::store::blob_fingerprint::invalidate_blob_fingerprint(store, wtxn, id)?;
    crate::artifact_hosting::remove_blob_pointers_in_txn(store, wtxn, id)?;
    crate::edit_settle::purge_artifact_retention_in_txn(store, wtxn, id)?;
    let mut cleanup = BlobArtifactLifecycleCleanup::default();
    let hashes = artifact_hashes(store, wtxn, id)?;
    let keys = VERSIONS.scan_keys(store, wtxn, id.as_bytes())?;
    let mut kept_versions = BTreeSet::new();
    let mut kept_hashes = BTreeSet::new();
    for key in &keys {
        if let Some(version) = VERSIONS.get_lenient(store, wtxn, key)?
            && crate::channel_identity_provider::line_chat_archive_keeps_version_in_txn(
                store,
                wtxn,
                id,
                version.version,
                &version.content_hash,
                &version.claim_id,
            )?
        {
            kept_versions.insert(*key);
            kept_hashes.insert(version.content_hash);
        }
    }
    if kept_versions.is_empty() {
        forget_claimed_hashes(store, wtxn, id)?;
        HEAD.delete(store, wtxn, id)?;
    } else {
        forget_claimed_hashes_except_in_txn(store, wtxn, id, &kept_hashes)?;
    }
    for key in keys {
        if kept_versions.contains(&key) {
            continue;
        }
        if let Some(version) = VERSIONS.get_lenient(store, wtxn, &key)? {
            super::born_from::unindex_version_in_txn(store, wtxn, id, &version)?;
        }
        VERSIONS.delete(store, wtxn, &key)?;
    }
    if !kept_versions.is_empty() {
        let survivor = VERSIONS
            .iter_rev_from(store, wtxn, id.as_bytes())?
            .next()
            .transpose()?;
        if let Some((_, head)) = survivor {
            HEAD.put(store, wtxn, id, &head)?;
        }
    }
    for content_hash in hashes {
        if kept_hashes.contains(&content_hash) {
            continue;
        }
        ASSET_REF.delete(store, wtxn, &(content_hash, *id))?;
        release_unheld_bytes(store, wtxn, &content_hash, id, &mut cleanup, deindex)?;
    }
    cleanup.neighbors.sort_unstable();
    cleanup.neighbors.dedup();
    Ok(cleanup)
}

/// The owner's discard of a world copy (FIX 14534, Engine 11-06 08:34 call
/// 4 = A): `id`'s version chain and head, which carry its export names,
/// media types and provenance, its claimed-hash pairs and its `asset_ref`
/// holds on their bytes go. Local only: no deletion fence, no deindex of a
/// byte carrier, no pointer, publication or serving change. A carrier ASSET
/// is a member of its own: the tear takes it with its world's rows, and one
/// another holder needs keeps its row. Its version numbering (`highwater`)
/// and born-from rows stay as identifier-only history; a born-from listing
/// joins live versions only.
pub(crate) fn discard_local_copy_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    crate::store::blob_fingerprint::invalidate_blob_fingerprint(store, wtxn, id)?;
    let hashes = artifact_hashes(store, wtxn, id)?;
    forget_claimed_hashes(store, wtxn, id)?;
    HEAD.delete(store, wtxn, id)?;
    for key in VERSIONS.scan_keys(store, wtxn, id.as_bytes())? {
        VERSIONS.delete(store, wtxn, &key)?;
    }
    for content_hash in hashes {
        ASSET_REF.delete(store, wtxn, &(content_hash, *id))?;
    }
    Ok(())
}

/// The owner's discard of a world copy takes the hold the reference ASSET
/// `reference` has on the bytes under `content_hash` (FIX 14534): its
/// `asset_ref` row goes, and nothing else. The bytes' carrier is a member of
/// its own.
pub(crate) fn discard_asset_reference_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    reference: &EntityId,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<()> {
    ASSET_REF.delete(store, wtxn, &(*content_hash, *reference))?;
    Ok(())
}

/// Releases the bytes under `content_hash` once `artifact` lets go of them, unless an
/// `asset_ref` row or another live artifact's version claim still holds them: their ASSET is
/// fenced, and deindexed when its row is stored here. Never the id being deleted, and never a
/// row of another kind stored at the content-addressed id.
fn release_unheld_bytes(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    artifact: &EntityId,
    cleanup: &mut BlobArtifactLifecycleCleanup,
    deindex: &dyn Fn(
        &mut heed::RwTxn<'_>,
        &EntityId,
    ) -> crate::error::Result<(bool, bool, bool, Vec<EntityId>)>,
) -> Result<()> {
    let still_referenced = ASSET_REF
        .iter_from(store, wtxn, content_hash)?
        .next()
        .transpose()?
        .is_some()
        || held_by_live_artifact(store, wtxn, content_hash, Some(artifact))?;
    if still_referenced {
        return Ok(());
    }
    let asset_id = blob_artifact_asset_entity_id(content_hash)?;
    if asset_id == *artifact {
        return Ok(());
    }
    let stored_type = crate::ports::EntityStoreRead::port_entity_raw(store, wtxn, &asset_id)?
        .map(|raw| raw.first().copied());
    match stored_type {
        None => fence_released_asset(store, wtxn, &asset_id),
        Some(Some(ENTITY_TYPE_ASSET)) => {
            fence_released_asset(store, wtxn, &asset_id)?;
            let (_existed, had_vector, had_graph_mutation, neighbors) = deindex(wtxn, &asset_id)?;
            ppr::invalidate_ppr_for_delete(store, wtxn, &asset_id, &neighbors)?;
            cleanup.had_vector |= had_vector;
            cleanup.had_graph_mutation |= had_graph_mutation;
            cleanup.neighbors.extend(neighbors);
            Ok(())
        }
        Some(_) => Ok(()),
    }
}

/// Settles the bytes a `blob.version` claim names when its artifact was deleted here before the
/// claim arrived: the delete already ran without this hash, so they go now unless something live
/// holds them.
pub(super) fn release_bytes_of_deleted_artifact(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    deindex: &dyn Fn(
        &mut heed::RwTxn<'_>,
        &EntityId,
    ) -> crate::error::Result<(bool, bool, bool, Vec<EntityId>)>,
) -> Result<()> {
    let mut cleanup = BlobArtifactLifecycleCleanup::default();
    release_unheld_bytes(store, wtxn, content_hash, artifact, &mut cleanup, deindex)?;
    if cleanup.had_graph_mutation {
        crate::store::graph_version::increment_graph_version(store, wtxn)?;
    }
    if cleanup.had_vector {
        crate::store::vector_index::increment_vector_version(store, wtxn)?;
    }
    Ok(())
}

/// Releases the reference ASSET `reference` holds on the bytes under
/// `content_hash` (FIX 9949): its `asset_ref` row goes, and the bytes then go
/// by the delete rule above, unless another holder keeps them. Runs in the
/// ASSET's delete or erase transaction. A reference that is not there
/// releases nothing.
pub(crate) fn release_asset_reference_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    reference: &EntityId,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    deindex: &dyn Fn(
        &mut heed::RwTxn<'_>,
        &EntityId,
    ) -> crate::error::Result<(bool, bool, bool, Vec<EntityId>)>,
) -> Result<()> {
    if !ASSET_REF.delete(store, wtxn, &(*content_hash, *reference))? {
        return Ok(());
    }
    release_bytes_of_deleted_artifact(store, wtxn, reference, content_hash, deindex)
}

/// Holds the bytes under `content_hash` again for the ASSET that just landed
/// them (FIX 9949): a fence an earlier release left on their ASSET is lifted,
/// as a new artifact holding the same bytes lifts it. A hard delete's marker
/// and an explicit delete's fence stay.
pub(crate) fn hold_asset_reference_in_txn(
    store: &Store,
    wtxn: &mut RwTxn<'_>,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<()> {
    super::references::lift_release_fence(
        store,
        wtxn,
        &blob_artifact_asset_entity_id(content_hash)?,
    )
}

/// Releases exactly version `version` of `artifact`, holding `content_hash`,
/// once the last step claim pinning it as its response let go of it (FIX
/// 6225). Only that version goes: its record, its born-from rows and its
/// generated `blob.version` claim, a ledger event and no holder of the bytes
/// it records; the claim and an emptied artifact are erased as replicated
/// rows are (FIX 8501), and what this vault serves of the version goes with
/// it (FIX 8504). HEAD falls back to the greatest version that stays; HIGHWATER
/// stays, so its number is never issued again. Its hash's reference rows go
/// when no version that stays and no retained claim of the artifact names
/// it, and its bytes then by the delete rule above; an artifact left with no
/// version, claimed hash or retained claim goes whole. Every other version
/// and holder stays as it is. A version not recorded under that hash is a
/// no-op, never another version in its place; one whose artifact, claim or
/// ASSET a legal hold covers stays, so the release is never a refusal.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn release_response_version_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    version: u64,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<()> {
    release_version_in_txn(
        write,
        wtxn,
        artifact,
        version,
        content_hash,
        true,
        VersionClaimRow::Tear,
    )
}

/// Releases a native provider archive's privately captured version. The
/// ledger claim must still be the exact captured claim. Unlike a fresh
/// response artifact, a provider archive has a deterministic id: its empty
/// metadata row stays, so a later native append can use the high-water
/// number without colliding with a permanent artifact tombstone.
pub(crate) fn release_archive_version_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    version: u64,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    version_claim: &EntityId,
) -> Result<()> {
    if !archive_version_stands_in_txn(
        write.store,
        wtxn,
        artifact,
        version,
        content_hash,
        version_claim,
    )? {
        return Ok(());
    }
    release_version_in_txn(
        write,
        wtxn,
        artifact,
        version,
        content_hash,
        false,
        VersionClaimRow::Tear,
    )
}

/// Whether the immutable local archive version still names the exact
/// ledger claim captured by its native producer. HEAD is irrelevant.
pub(crate) fn archive_version_stands_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    version: u64,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    version_claim: &EntityId,
) -> Result<bool> {
    Ok(VERSIONS
        .get(store, txn, &(*artifact, version))?
        .is_some_and(|record| {
            record.version == version
                && record.content_hash == *content_hash
                && record.claim_id == *version_claim
        }))
}

/// The owner's delete of a live artifact's lone `blob.version` claim, run as the release of the
/// version it records (ASTRA-R2-002; Engine ruling 13 Nov 17:56). The claim goes with its version
/// and, unless another holder keeps them, with its bytes, so no replica that syncs later keeps
/// them. Where this vault holds the artifact's chain, the chain's version whose ledger claim this
/// is goes as a response release does, and the artifact stays even when emptied. A vault without
/// that version (a replica) tears the claim and settles its pair and bytes the same way.
///
/// `false` when a legal hold on the artifact, the claim or its ASSET keeps the version: nothing
/// went.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn release_claimed_version_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    claim: &EntityId,
    artifact: &EntityId,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<bool> {
    let store = write.store;
    if let Some((version, chained_hash)) = chained_version_of(store, wtxn, artifact, claim)? {
        release_version_in_txn(
            write,
            wtxn,
            artifact,
            version,
            &chained_hash,
            false,
            VersionClaimRow::Tear,
        )?;
        return Ok(VERSIONS.get(store, wtxn, &(*artifact, version))?.is_none());
    }
    let asset = blob_artifact_asset_entity_id(content_hash)?;
    for id in [artifact, claim, &asset] {
        if crate::store::legal_hold::held_in_txn(store, wtxn, id.as_bytes())? {
            return Ok(false);
        }
    }
    let mut cleanup = BlobArtifactLifecycleCleanup::default();
    tear_in_txn(write, wtxn, claim, &mut cleanup)?;
    if forget_released_pair_in_txn(store, wtxn, artifact, content_hash)? {
        release_unheld_bytes(
            store,
            wtxn,
            content_hash,
            artifact,
            &mut cleanup,
            &|txn, id| crate::batch::deindex_entity(write, txn, id),
        )?;
    }
    if cleanup.had_graph_mutation {
        crate::store::graph_version::increment_graph_version(store, wtxn)?;
    }
    if cleanup.had_vector {
        crate::store::vector_index::increment_vector_version(store, wtxn)?;
    }
    Ok(true)
}

/// The version of this vault's chain of `artifact` whose ledger claim is `claim`, with its hash.
fn chained_version_of(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    claim: &EntityId,
) -> Result<Option<(u64, [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN])>> {
    for row in VERSIONS.iter_from(store, txn, artifact.as_bytes())? {
        let (_, record) = row?;
        if record.claim_id == *claim {
            return Ok(Some((record.version, record.content_hash)));
        }
    }
    Ok(None)
}

/// A version of a live artifact's chain here whose `blob.version` claim a peer's tombstone is
/// about to purge: read before the purge, released after it
/// ([`release_replayed_claim_version_in_txn`]).
pub(crate) struct ReplayedClaimVersion {
    artifact: EntityId,
    version: u64,
    content_hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
}

/// The chain version a replayed tombstone of `claim` takes with it: `Some` when `claim` is a
/// `blob.version` claim of a live artifact here and this vault's chain of that artifact keeps a
/// version under it. `None` for any other record. Read before the replay's purge takes the
/// claim's body.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn replayed_claim_version_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    claim: &EntityId,
) -> Result<Option<ReplayedClaimVersion>> {
    let Some((artifact, _)) = live_version_claim_reference(store, txn, claim)? else {
        return Ok(None);
    };
    Ok(
        chained_version_of(store, txn, &artifact, claim)?.map(|(version, content_hash)| {
            ReplayedClaimVersion {
                artifact,
                version,
                content_hash,
            }
        }),
    )
}

/// A peer's purge of a version's `blob.version` claim releases that version of this vault's chain
/// (Engine ruling 13 Nov 17:56: the owner's release takes the claim and the bytes on every
/// replica). The origin may hold no chain and send only the claim's tombstone; without this the
/// uploader's chain would keep a version whose claim is gone, and reading it would answer
/// `CorruptedIndex`. The version goes as the owner's release takes it, after the replay purged the
/// claim; the artifact stays even when emptied, and a legal hold on the artifact or its ASSET
/// keeps the version.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn release_replayed_claim_version_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    replayed: &ReplayedClaimVersion,
) -> Result<()> {
    release_version_in_txn(
        write,
        wtxn,
        &replayed.artifact,
        replayed.version,
        &replayed.content_hash,
        false,
        VersionClaimRow::PurgedByReplay,
    )
}

/// What a version's release does with the version's ledger claim.
#[derive(Clone, Copy, PartialEq, Eq)]
enum VersionClaimRow {
    /// The release tears it and stages its tombstone.
    Tear,
    /// A replayed tombstone purged it in this transaction.
    PurgedByReplay,
}

fn release_version_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    artifact: &EntityId,
    version: u64,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
    remove_empty_artifact: bool,
    claim_row: VersionClaimRow,
) -> Result<()> {
    let store = write.store;
    let Some(record) = VERSIONS.get(store, wtxn, &(*artifact, version))? else {
        return Ok(());
    };
    if record.version != version || record.content_hash != *content_hash {
        return Ok(());
    }
    let asset = blob_artifact_asset_entity_id(content_hash)?;
    for id in [artifact, &record.claim_id, &asset] {
        if crate::store::legal_hold::held_in_txn(store, wtxn, id.as_bytes())? {
            return Ok(());
        }
    }
    let mut cleanup = BlobArtifactLifecycleCleanup::default();
    super::born_from::unindex_version_in_txn(store, wtxn, artifact, &record)?;
    VERSIONS.delete(store, wtxn, &(*artifact, version))?;
    if HEAD
        .get(store, wtxn, artifact)?
        .is_some_and(|head| head.version == version)
    {
        crate::store::blob_fingerprint::invalidate_blob_fingerprint(store, wtxn, artifact)?;
        let survivor = VERSIONS
            .iter_rev_from(store, wtxn, artifact.as_bytes())?
            .next()
            .transpose()?;
        match survivor {
            Some((_, head)) => HEAD.put(store, wtxn, artifact, &head)?,
            None => {
                HEAD.delete(store, wtxn, artifact)?;
            }
        }
    }
    if claim_row == VersionClaimRow::Tear {
        tear_in_txn(write, wtxn, &record.claim_id, &mut cleanup)?;
    }
    crate::artifact_hosting::retire_released_version_in_txn(store, wtxn, artifact, version)?;
    if !chain_holds(store, wtxn, artifact, content_hash)? {
        ASSET_REF.delete(store, wtxn, &(*content_hash, *artifact))?;
        if forget_released_pair_in_txn(store, wtxn, artifact, content_hash)? {
            release_unheld_bytes(
                store,
                wtxn,
                content_hash,
                artifact,
                &mut cleanup,
                &|txn, id| crate::batch::deindex_entity(write, txn, id),
            )?;
        }
    }
    let emptied = VERSIONS
        .iter_from(store, wtxn, artifact.as_bytes())?
        .next()
        .transpose()?
        .is_none()
        && !claimed_hash_rows_exist(store, wtxn, artifact)?
        && !retained_claim_names(store, wtxn, artifact, None)?;
    if remove_empty_artifact && emptied {
        tear_in_txn(write, wtxn, artifact, &mut cleanup)?;
    }
    if cleanup.had_graph_mutation {
        crate::store::graph_version::increment_graph_version(store, wtxn)?;
    }
    if cleanup.had_vector {
        crate::store::vector_index::increment_vector_version(store, wtxn)?;
    }
    Ok(())
}

/// Whether version `version` of `artifact` is recorded here holding
/// `content_hash`: the exact version a step claim's response pin names
/// stands (FIX 6225).
///
/// # Errors
///
/// Storage errors.
pub(crate) fn response_version_stands_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    version: u64,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<bool> {
    Ok(VERSIONS
        .get(store, txn, &(*artifact, version))?
        .is_some_and(|record| record.version == version && record.content_hash == *content_hash))
}

/// Whether a version of `artifact`'s chain still holds `content_hash`.
fn chain_holds(
    store: &Store,
    txn: &RoTxn<'_>,
    artifact: &EntityId,
    content_hash: &[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
) -> Result<bool> {
    for row in VERSIONS.iter_from(store, txn, artifact.as_bytes())? {
        if row?.1.content_hash == *content_hash {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Tears `id`, a released version's ledger claim or an emptied artifact,
/// with its machine history, as a local delete does, folding its graph and
/// vector accounting into `cleanup`. A row that was here is erased as a
/// replicated row is (FIX 8501): its permanent `dt:` marker refuses a
/// peer's copy sent again, and its tombstone, staged in the window the row
/// rode, takes the copies peers hold. Neither id is minted again: a
/// response artifact's is fresh, and HIGHWATER keeps a version's number.
fn tear_in_txn(
    write: &crate::secret_custody::CustodyWrite<'_>,
    wtxn: &mut RwTxn<'_>,
    id: &EntityId,
    cleanup: &mut BlobArtifactLifecycleCleanup,
) -> Result<()> {
    let store = write.store;
    let raw = crate::ports::EntityStoreRead::port_entity_raw(store, &*wtxn, id)?;
    let (_existed, had_vector, had_graph_mutation, neighbors) =
        crate::batch::deindex_entity_with_machine_history(write, wtxn, id)?;
    ppr::invalidate_ppr_for_delete(store, wtxn, id, &neighbors)?;
    cleanup.had_vector |= had_vector;
    cleanup.had_graph_mutation |= had_graph_mutation;
    cleanup.neighbors.extend(neighbors);
    match raw.as_deref().and_then(EntityMetadataHeader::parse) {
        Some(header) => {
            let window = torn_row_window(&header, raw.as_deref().unwrap_or_default());
            let value = crate::deletion::TombstoneValueV2 {
                reason: crate::deletion::TombstoneReason::UserHardDelete,
                deleted_at: crate::ports::recorded_at_in_txn(store, wtxn)?,
                request_id: *id.as_bytes(),
            };
            crate::deletion::stage_engine_row_hard_erasure_at_in_txn(
                store, wtxn, id, window, &value,
            )
        }
        None => Ok(()),
    }
}

/// The window a torn row rode: a CLAIM's world's month when its body names a
/// world, else the base month of its learned-at, as sync placed it.
fn torn_row_window(header: &EntityMetadataHeader, raw: &[u8]) -> String {
    let mut window = crate::deletion::window_label_from_timestamp(header.learned_at);
    if header.entity_type == ENTITY_TYPE_CLAIM
        && let Some(world) = raw
            .get(ENTITY_METADATA_HEADER_LEN..)
            .and_then(|body| crate::write_envelope::claim_body::decode_claim_body(body, true).ok())
            .and_then(|body| body.world)
    {
        window.push('@');
        window.push_str(&world.to_hex());
    }
    window
}
