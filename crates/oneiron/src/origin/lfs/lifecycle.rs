//! Last-reference byte reclamation and permanent object deletion markers.

use super::store::{VAULT_LFS_REF_KEY_PREFIX, decode_lfs_object_record, lfs_object_key};
use super::{LfsOid, chunks};
use crate::error::{Error, Result};
use crate::store::Store;
use crate::{EntityId, Vault};
use heed::RwTxn;

pub(super) const DELETED: &[u8] = b"origin:lfs:deleted:v1:";
pub(super) const REVERSE: &[u8] = b"origin:lfs:manifest:v1:";
pub(super) const JOURNAL: &[u8] = b"origin:lfs:upload:v1:";
pub(super) const GC: &[u8] = b"origin:lfs:gc:v1:";

/// Runs at the shared deindex door. Only metadata changes here. Byte reclamation
/// runs in bounded follow-up transactions, so a multi-GiB delete cannot create
/// a multi-GiB LMDB writer. The object stops resolving in this transaction.
pub(crate) fn delete_lfs_lifecycle_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let reverse = chunks::key(REVERSE, id.as_bytes());
    let Some(raw_oid) = store.vault_meta.get(txn, &reverse)? else {
        return Ok(());
    };
    let oid = LfsOid::from_bytes(
        raw_oid
            .as_ref()
            .try_into()
            .map_err(|_| Error::CorruptedIndex("lfs reverse oid"))?,
    );
    let object_key = lfs_object_key(&oid);
    if let Some(raw) = store.vault_meta.get(txn, &object_key)? {
        let object = decode_lfs_object_record(oid, &raw)?;
        store
            .vault_meta
            .put(txn, &chunks::key(GC, object.ref_owner.as_bytes()), &[])?;
    }
    store
        .vault_meta
        .put(txn, &chunks::key(DELETED, oid.as_bytes()), &[])?;
    store.vault_meta.delete(txn, &object_key)?;
    store.vault_meta.delete(txn, &reverse)?;
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
    Ok(store
        .vault_meta
        .get(txn, &chunks::key(chunks::CHUNK_MARK, id.as_bytes()))?
        .is_some())
}

impl Vault {
    /// Owner-facing deletion. The standing tombstone-first door prevents replay
    /// resurrection; the OID marker also blocks new manifests with new chunking.
    pub fn delete_lfs_object(&self, oid: LfsOid) -> Result<bool> {
        let Some(object) = self.lfs_object(oid)? else {
            self.with_write_txn(|txn| {
                self.store
                    .vault_meta
                    .put(txn, &chunks::key(DELETED, oid.as_bytes()), &[])?;
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
            let pending = self
                .store
                .vault_meta
                .prefix_iter(txn, GC)?
                .next()
                .transpose()?
                .map(|(key, _)| key.to_vec());
            let Some(gc_key) = pending else { return Ok(0) };
            let owner = EntityId::from_bytes(
                gc_key[GC.len()..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("lfs gc key"))?,
            )
            .map_err(|_| Error::CorruptedIndex("lfs gc owner"))?;
            let prefix = chunks::key(chunks::OWNER_REF, owner.as_bytes());
            let rows = self
                .store
                .vault_meta
                .prefix_iter(txn, &prefix)?
                .take(budget)
                .map(|row| row.map(|(key, _)| key.to_vec()))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let mut graph = false;
            let mut vector = false;
            for row in &rows {
                let hash: [u8; 32] = row[prefix.len()..]
                    .try_into()
                    .map_err(|_| Error::CorruptedIndex("lfs owner reference"))?;
                self.store.vault_meta.delete(txn, row)?;
                self.store
                    .vault_meta
                    .delete(txn, &chunks::ref_key(&hash, owner))?;
                let referenced = self
                    .store
                    .vault_meta
                    .prefix_iter(txn, &chunks::key(chunks::REF_PREFIX, &hash))?
                    .next()
                    .transpose()?
                    .is_some();
                if !referenced {
                    let id = chunks::chunk_id(&hash)?;
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
                self.store.vault_meta.delete(txn, &gc_key)?;
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
            for row in self.store.vault_meta.prefix_iter(txn, JOURNAL)? {
                let (key, value) = row?;
                if value.len() != 40 {
                    return Err(Error::CorruptedIndex("lfs upload journal"));
                }
                let stamp = u64::from_le_bytes(value[32..].try_into().expect("length checked"));
                if stamp < cutoff {
                    rows.push(key.to_vec());
                }
                if rows.len() == 128 {
                    break;
                }
            }
            for row in &rows {
                self.store
                    .vault_meta
                    .put(txn, &chunks::key(GC, &row[JOURNAL.len()..]), &[])?;
                self.store.vault_meta.delete(txn, row)?;
            }
            Ok(rows.len())
        })
    }

    /// Removes at most 128 obsolete Git ref rows after explicit object deletion.
    pub fn collect_deleted_lfs_ref_rows(&self) -> Result<usize> {
        self.with_write_txn(|txn| {
            let mut rows = Vec::new();
            for row in self
                .store
                .vault_meta
                .prefix_iter(txn, VAULT_LFS_REF_KEY_PREFIX)?
            {
                let (key, _) = row?;
                if key.len() < 32 {
                    return Err(Error::CorruptedIndex("lfs ref key"));
                }
                if self
                    .store
                    .vault_meta
                    .get(txn, &chunks::key(DELETED, &key[key.len() - 32..]))?
                    .is_some()
                {
                    rows.push(key.to_vec());
                }
                if rows.len() == 128 {
                    break;
                }
            }
            for row in &rows {
                self.store.vault_meta.delete(txn, row)?;
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
    if store
        .vault_meta
        .get(txn, &chunks::key(chunks::CHUNK_MARK, id.as_bytes()))?
        .is_some()
    {
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
    let chunk_hash = store
        .vault_meta
        .get(txn, &chunks::key(chunks::CHUNK_MARK, id.as_bytes()))?;
    let manifest = store
        .vault_meta
        .get(txn, &chunks::key(REVERSE, id.as_bytes()))?
        .is_some();
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
        let hash: [u8; 32] = hash
            .as_ref()
            .try_into()
            .map_err(|_| Error::CorruptedIndex("lfs chunk marker"))?;
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
