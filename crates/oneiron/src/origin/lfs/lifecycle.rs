//! Last-reference byte reclamation and permanent object deletion markers.

use super::{LfsOid, chunks};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Vault};
use heed::RwTxn;

/// Permanent tombstone (empty marker) for one deleted LFS object id, blocking resurrection. Key:
/// oid.
pub(super) const DELETED: SideTable<LfsOid, (), Raw> =
    SideTable::new(&side_table::ORIGIN_LFS_DELETED);

/// Reverse pointer from an LFS manifest ASSET back to its object id. Key: asset id.
pub(super) const REVERSE: SideTable<EntityId, LfsOid, Raw> =
    SideTable::new(&side_table::ORIGIN_LFS_MANIFEST_REVERSE);

/// Crash-recoverable heartbeat journal (oid32+timestamp8) for one in-progress streamed LFS
/// upload. Key: owner id.
pub(super) const JOURNAL: SideTable<EntityId, [u8; 40], Raw> =
    SideTable::new(&side_table::ORIGIN_LFS_UPLOAD_JOURNAL);

/// Queue (empty marker) of upload owners whose chunk references are pending garbage collection.
/// Key: owner id.
pub(super) const GC: SideTable<EntityId, (), Raw> =
    SideTable::new(&side_table::ORIGIN_LFS_GC_QUEUE);

/// Runs at the shared deindex door. Only metadata changes here. Byte reclamation
/// runs in bounded follow-up transactions, so a multi-GiB delete cannot create
/// a multi-GiB LMDB writer. The object stops resolving in this transaction.
pub(crate) fn delete_lfs_lifecycle_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let Some(oid) = REVERSE.get(store, txn, id)? else {
        return Ok(());
    };
    if let Some(record) = super::store::OBJECTS.get(store, txn, &oid)? {
        GC.put(store, txn, &record.ref_owner, &())?;
    }
    DELETED.put(store, txn, &oid, &())?;
    super::store::OBJECTS.delete(store, txn, &oid)?;
    REVERSE.delete(store, txn, id)?;
    // Ref attachments are reachability metadata, never authority to recreate.
    // They are omitted from reads once their OID is permanently deleted.
    Ok(())
}

/// Internal chunk bytes never enter Loro windows or generic sync exports.
#[cfg(feature = "sync")]
pub(crate) fn is_lfs_chunk_asset_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    chunks::CHUNK_MARKS.contains(store, txn, id)
}

impl Vault {
    /// Owner-facing deletion. The standing tombstone-first door prevents replay
    /// resurrection; the OID marker also blocks new manifests with new chunking.
    pub fn delete_lfs_object(&self, oid: LfsOid) -> Result<bool> {
        let Some(object) = self.lfs_object(oid)? else {
            self.with_write_txn(|txn| {
                DELETED.put(&self.store, txn, &oid, &())?;
                Ok(())
            })?;
            return Ok(false);
        };
        let deleted = self.delete_entity(&object.asset_id)?;
        while self.collect_lfs_garbage(32)? != 0 {}
        Ok(deleted)
    }

    /// Reclaims at most `budget` chunk references, in one bounded transaction.
    /// This is completion of an explicit deletion/aborted upload, not an age-
    /// based destruction policy. Shared chunks survive until their last owner.
    pub fn collect_lfs_garbage(&self, budget: usize) -> Result<usize> {
        let budget = budget.min(128);
        if budget == 0 {
            return Ok(0);
        }
        self.with_write_txn(|txn| {
            let pending = GC.iter_from(&self.store, txn, &[])?.next().transpose()?;
            let Some((owner, ())) = pending else {
                return Ok(0);
            };
            let rows: Vec<(EntityId, [u8; 32])> = chunks::OWNER_REFS
                .iter_from(&self.store, txn, owner.as_bytes())?
                .take(budget)
                .map(|row| row.map(|(key, ())| key))
                .collect::<Result<Vec<_>>>()?;
            let mut graph = false;
            let mut vector = false;
            for (_, hash) in &rows {
                chunks::OWNER_REFS.delete(&self.store, txn, &(owner, *hash))?;
                chunks::CHUNK_REFS.delete(&self.store, txn, &(*hash, owner))?;
                let referenced = chunks::CHUNK_REFS
                    .iter_from(&self.store, txn, hash.as_slice())?
                    .next()
                    .transpose()?
                    .is_some();
                if !referenced {
                    let id = chunks::chunk_id(hash)?;
                    let (_, had_vector, had_graph, neighbors) =
                        crate::batch::deindex_entity(&self.store, txn, &id)?;
                    graph |= had_graph;
                    vector |= had_vector;
                    crate::ppr::invalidate_ppr_for_delete(&self.store, txn, &id, &neighbors)?;
                    // Keep the small internal-byte marker: stale sync imports must
                    // not promote a retired chunk into the generic metadata plane.
                }
            }
            if graph {
                crate::ppr::increment_graph_version(&self.store, txn)?;
            }
            if vector {
                crate::hnsw::increment_vector_version(&self.store, txn)?;
            }
            if rows.len() < budget {
                GC.delete(&self.store, txn, &owner)?;
            }
            // Empty queue rows still count as progress, so a drain visits the next.
            Ok(rows.len().max(1))
        })
    }

    /// Cancels abandoned uploads older than a caller-chosen recovery cutoff.
    /// Cancellation is transactional. A still-running uploader observes its
    /// missing journal before its next chunk or publication and fails closed.
    pub fn recover_lfs_uploads_before(&self, cutoff: u64) -> Result<usize> {
        self.with_write_txn(|txn| {
            let mut rows = Vec::new();
            for row in JOURNAL.iter_from(&self.store, txn, &[])? {
                let (owner, value) = row?;
                let stamp = u64::from_le_bytes(value[32..].try_into().expect("length checked"));
                if stamp < cutoff {
                    rows.push(owner);
                }
                if rows.len() == 128 {
                    break;
                }
            }
            for owner in &rows {
                GC.put(&self.store, txn, owner, &())?;
                JOURNAL.delete(&self.store, txn, owner)?;
            }
            Ok(rows.len())
        })
    }

    /// Removes at most 128 obsolete Git ref rows after explicit object deletion.
    pub fn collect_deleted_lfs_ref_rows(&self) -> Result<usize> {
        self.with_write_txn(|txn| {
            let mut rows = Vec::new();
            for row in super::store::REFS.iter_from(&self.store, txn, &[])? {
                let (key, _) = row?;
                if DELETED.contains(&self.store, txn, &key.oid)? {
                    rows.push(key);
                }
                if rows.len() == 128 {
                    break;
                }
            }
            for key in &rows {
                super::store::REFS.delete(&self.store, txn, key)?;
            }
            Ok(rows.len())
        })
    }
}

/// The content-id domain also identifies a chunk arriving before its local
/// marker. This blocks a fresh receiver from importing byte chunks via Loro.
#[cfg(feature = "sync")]
pub(crate) fn is_lfs_chunk_blob(id: &EntityId, blob: &[u8]) -> bool {
    let Some(header) = crate::batch::EntityMetadataHeader::parse(blob) else {
        return false;
    };
    if header.entity_type != crate::registry::ENTITY_TYPE_ASSET {
        return false;
    }
    let body = &blob[crate::batch::ENTITY_METADATA_HEADER_LEN..];
    body.len() <= super::LFS_CHUNK_MAX
        && chunks::chunk_id(blake3::hash(body).as_bytes())
            .ok()
            .as_ref()
            == Some(id)
}

/// Derived bytes have no independent owner-facing deletion semantics. Delete
/// their manifest instead; GC can then decide whether a chunk is still shared.
pub(crate) fn reject_direct_lfs_chunk_delete(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if chunks::CHUNK_MARKS.contains(store, txn, id)? {
        return Err(chunks::invalid("delete the lfs object, not a shared chunk"));
    }
    Ok(())
}

/// Published manifests and shared chunks are immutable at their content ids.
/// All generic puts and document migration use this same guard.
pub(crate) fn guard_lfs_asset_put(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    data: &[u8],
) -> Result<()> {
    let chunk_hash = chunks::CHUNK_MARKS.get(store, txn, id)?;
    let manifest = REVERSE.contains(store, txn, id)?;
    if chunk_hash.is_none() && !manifest {
        return Ok(());
    }
    if entity_type != crate::registry::ENTITY_TYPE_ASSET {
        return Err(chunks::invalid(
            "content-addressed lfs assets cannot change kind",
        ));
    }
    let Some(old) = store.entities.get(txn, id.as_bytes())? else {
        // GC retires bytes, not the chunk-id reservation. Only authenticated
        // bytes can restore that chunk; a missing published manifest is corrupt.
        let Some(hash) = chunk_hash.filter(|_| !manifest) else {
            return Err(Error::CorruptedIndex("lfs protected asset missing"));
        };
        if chunks::chunk_id(&hash)? != *id {
            return Err(Error::CorruptedIndex("lfs chunk marker id"));
        }
        if data.len() > super::LFS_CHUNK_MAX || blake3::hash(data).as_bytes() != &hash {
            return Err(chunks::invalid(
                "restored lfs chunk must match its content id",
            ));
        }
        return Ok(());
    };
    if old.get(crate::batch::ENTITY_METADATA_HEADER_LEN..) != Some(data) {
        return Err(chunks::invalid(
            "content-addressed lfs assets are immutable",
        ));
    }
    Ok(())
}
