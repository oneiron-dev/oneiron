//! Bounded streaming ingress: validate before publishing, then commit small chunk transactions.

use super::chunks::{self, LFS_CHUNK_AVG, LFS_CHUNK_MAX, LFS_CHUNK_MIN, LfsChunkRef, LfsManifest};
use super::lifecycle::{DELETED, GC, JOURNAL, REVERSE};
use super::store::{LfsObjectRecord, OBJECTS};
use super::{LfsOid, LfsPutOutcome, VaultLfsObject};
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_ASSET;
use crate::side_table::HexId;
use crate::{EntityId, TimeRange, Vault};
use fastcdc::v2020::{Normalization, StreamCDC};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};

/// Local hard-delete marker (`deletion::tombstone` owns the writer side; this is a read-only
/// existence check bound to the SAME declaration, never decoding the value — presence-only,
/// exactly as every other reader of this row treats it). Key: hex32.
const HARD_DELETE_MARKERS: crate::side_table::SideTable<HexId, Vec<u8>, crate::side_table::Raw> =
    crate::side_table::SideTable::new(&crate::side_table::DELETION_HARD_DELETE_MARKER);

impl Vault {
    /// Uploads any-sized object with bounded resident bytes and bounded writers.
    ///
    /// The anonymous staging file is removed on success, refusal and disconnect.
    /// SHA-256 and the cross-boundary credential scanner finish before any ASSET
    /// write. Each subsequent writer holds at most one 128 KiB chunk. The final
    /// transaction publishes only the manifest and lookup row, never the body.
    pub fn put_lfs_object_stream<R: Read>(
        &self,
        expected_oid: LfsOid,
        expected_size: Option<u64>,
        mut reader: R,
        occurred: TimeRange,
        learned_at: u64,
    ) -> Result<LfsPutOutcome> {
        let params = self.lfs_chunk_parameters()?;
        let mut spool = tempfile::tempfile()?;
        let mut sha = Sha256::new();
        let mut scanner = super::scanner::CredentialStream::default();
        let mut buffer = vec![0u8; LFS_CHUNK_MAX];
        let mut size = 0u64;
        loop {
            let count = match reader.read(&mut buffer) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                other => other?,
            };
            if count == 0 {
                break;
            }
            size = size
                .checked_add(count as u64)
                .ok_or_else(|| chunks::invalid("lfs size overflow"))?;
            if expected_size.is_some_and(|limit| size > limit) {
                return Err(chunks::invalid("lfs size exceeds declaration"));
            }
            scanner.feed(&buffer[..count])?;
            sha.update(&buffer[..count]);
            spool.write_all(&buffer[..count])?;
        }
        let actual: [u8; 32] = sha.finalize().into();
        super::store::check_lfs_digest(
            expected_oid,
            expected_size,
            LfsOid::from_bytes(actual),
            size,
        )?;
        // Validation still runs for a duplicate: an OID does not authenticate a body.
        if let Some(object) = self.lfs_object(expected_oid)? {
            return Ok(LfsPutOutcome {
                object,
                deduplicated: true,
            });
        }
        spool.seek(SeekFrom::Start(0))?;
        let mut manifest = LfsManifest {
            size_bytes: size,
            chunks: Vec::new(),
        };
        for chunk in StreamCDC::with_level_and_seed(
            &mut spool,
            LFS_CHUNK_MIN as u32,
            LFS_CHUNK_AVG as u32,
            LFS_CHUNK_MAX as u32,
            Normalization::Level1,
            params.seed,
        ) {
            let chunk = chunk.map_err(|e| std::io::Error::other(e.to_string()))?;
            manifest.chunks.push(LfsChunkRef {
                hash: *blake3::hash(&chunk.data).as_bytes(),
                size: chunk.length as u32,
            });
        }
        spool.seek(SeekFrom::Start(0))?;
        self.install_lfs_manifest(expected_oid, &manifest, occurred, learned_at, |chunk| {
            let mut bytes = vec![0u8; chunk.size as usize];
            spool.read_exact(&mut bytes)?;
            Ok(bytes)
        })
    }

    /// Installs a verified ordered manifest with one chunk transaction at a time.
    /// The supplier must return every ordered chunk (including repeats), so it
    /// can be a sequential file reader. Sync ingress uses the same admission.
    pub(crate) fn install_lfs_manifest<F>(
        &self,
        oid: LfsOid,
        manifest: &LfsManifest,
        occurred: TimeRange,
        learned_at: u64,
        mut supply: F,
    ) -> Result<LfsPutOutcome>
    where
        F: FnMut(&LfsChunkRef) -> Result<Vec<u8>>,
    {
        let encoded = manifest.encode()?;
        let asset_id = manifest.asset_id()?;
        let owner = EntityId::now();
        self.with_write_txn(|txn| {
            if DELETED.contains(&self.store, txn, &oid)?
                || HARD_DELETE_MARKERS.contains(&self.store, txn, &HexId(asset_id))?
            {
                return Err(chunks::invalid("lfs object was permanently deleted"));
            }
            JOURNAL.put(&self.store, txn, &owner, &journal_heartbeat(oid))?;
            Ok(())
        })?;
        let outcome = (|| {
            let mut seen = BTreeSet::new();
            let mut sha = Sha256::new();
            let mut scanner = super::scanner::CredentialStream::default();
            for chunk in &manifest.chunks {
                let bytes = supply(chunk)?;
                if bytes.len() != chunk.size as usize
                    || blake3::hash(&bytes).as_bytes() != &chunk.hash
                {
                    return Err(chunks::invalid("lfs chunk does not match manifest"));
                }
                scanner.feed(&bytes)?;
                sha.update(&bytes);
                if !seen.insert(chunk.hash) {
                    continue;
                }
                let id = chunks::chunk_id(&chunk.hash)?;
                self.with_write_txn(|txn| {
                    if !JOURNAL.contains(&self.store, txn, &owner)?
                        || DELETED.contains(&self.store, txn, &oid)?
                    {
                        return Err(chunks::invalid("lfs upload was cancelled"));
                    }
                    if let Some(raw) = self.store.entities.get(txn, id.as_bytes())? {
                        let body = raw
                            .get(crate::batch::ENTITY_METADATA_HEADER_LEN..)
                            .ok_or(Error::CorruptedIndex("lfs chunk header"))?;
                        if body != bytes {
                            return Err(Error::CorruptedIndex("lfs chunk collision"));
                        }
                    } else {
                        self.batch_in()
                            .put(&id, ENTITY_TYPE_ASSET, occurred, learned_at, &bytes)
                            .apply(txn)?;
                    }
                    chunks::CHUNK_MARKS.put(&self.store, txn, &id, &chunk.hash)?;
                    chunks::CHUNK_REFS.put(&self.store, txn, &(chunk.hash, owner), &())?;
                    chunks::OWNER_REFS.put(&self.store, txn, &(owner, chunk.hash), &())?;
                    JOURNAL.put(&self.store, txn, &owner, &journal_heartbeat(oid))?;
                    Ok(())
                })?;
            }
            let actual: [u8; 32] = sha.finalize().into();
            if actual != *oid.as_bytes() {
                return Err(chunks::invalid("lfs manifest pointer mismatch"));
            }
            self.with_write_txn(|txn| {
                if !JOURNAL.contains(&self.store, txn, &owner)?
                    || DELETED.contains(&self.store, txn, &oid)?
                {
                    return Err(chunks::invalid("lfs upload was cancelled"));
                }
                if let Some(record) = OBJECTS.get(&self.store, txn, &oid)? {
                    return Ok(LfsPutOutcome {
                        object: record.with_oid(oid),
                        deduplicated: true,
                    });
                }
                self.batch_in()
                    .put(&asset_id, ENTITY_TYPE_ASSET, occurred, learned_at, &encoded)
                    .apply(txn)?;
                let object = VaultLfsObject {
                    oid,
                    asset_id,
                    size_bytes: manifest.size_bytes,
                    created_at: learned_at,
                    ref_owner: owner,
                };
                OBJECTS.put(
                    &self.store,
                    txn,
                    &oid,
                    &LfsObjectRecord::from_object(&object),
                )?;
                REVERSE.put(&self.store, txn, &asset_id, &oid)?;
                JOURNAL.delete(&self.store, txn, &owner)?;
                Ok(LfsPutOutcome {
                    object,
                    deduplicated: false,
                })
            })
        })();
        // Failed/in-race duplicate imports cannot leave unreferenced byte assets.
        if !matches!(&outcome, Ok(result) if !result.deduplicated) {
            self.with_write_txn(|txn| {
                JOURNAL.delete(&self.store, txn, &owner)?;
                GC.put(&self.store, txn, &owner, &())?;
                Ok(())
            })?;
            while self.collect_lfs_garbage(32)? != 0 {}
        }
        outcome
    }
}

/// `oid(32) ++ now u64 LE(8)`, unchanged — a fresh heartbeat stamp every time it is written.
fn journal_heartbeat(oid: LfsOid) -> [u8; 40] {
    let mut journal = [0_u8; 40];
    journal[..32].copy_from_slice(oid.as_bytes());
    journal[32..].copy_from_slice(&crate::unix_seconds_now().to_le_bytes());
    journal
}
