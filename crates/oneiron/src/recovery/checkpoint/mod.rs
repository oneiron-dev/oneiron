//! Tier-C physical-row checkpoints and one restore/wake/migrate path.
//!
//! Images encode raw database keys/values from ONE LMDB read transaction. They
//! never copy free pages, locks, index pages, telemetry or process leases. This
//! is distinct from the logical export's entity/claim transformation format.
mod rebuild;
mod tiers;
use crate::{Error, Result, Vault, VaultConfig, store::DB_MANIFEST};
use heed::types::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    path::Path,
};
pub use tiers::{StorageTier, storage_tier};
type CanonicalRows = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointImage {
    version: u16,
    created_at: u64,
    databases: BTreeMap<String, CanonicalRows>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestoreReason {
    Restore,
    Wake,
    Migrate,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreEpoch {
    pub checkpoint_id: String,
    pub restored_at: u64,
    pub reason: RestoreReason,
}
/// Source checkpoint identity and newly rebuilt engine indexes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RestoreReport {
    pub epoch: RestoreEpoch,
    pub rebuilt_entities: usize,
    pub rebuilt_text_documents: usize,
    pub pending_embeddings: usize,
}
fn codec_error() -> Error {
    Error::CorruptedIndex("canonical checkpoint image")
}
impl Vault {
    /// Create-new output only. Checkpoint id hashes the entire canonical image.
    pub fn snapshot_checkpoint(&self, path: &Path, created_at: u64) -> Result<String> {
        let txn = self.store.env.read_txn()?;
        // Only claim/summary bodies have a canonical re-embedding path today.
        // Diagnostics are deliberately runtime-only. Other explicit vectors must
        // not silently disappear.
        for row in self.store.vectors.iter(&txn)? {
            let (id, _) = row?;
            let entity_type = self
                .store
                .entities
                .get(&txn, &id)?
                .and_then(|raw| crate::batch::EntityMetadataHeader::parse(&raw))
                .map(|header| header.entity_type);
            if !matches!(
                entity_type,
                Some(
                    crate::registry::ENTITY_TYPE_CLAIM
                        | crate::registry::ENTITY_TYPE_SUMMARY
                        | crate::registry::ENTITY_TYPE_DIAGNOSTIC
                )
            ) {
                return Err(Error::InvalidConfig(
                    "checkpoint vector lacks a canonical re-embedding source".into(),
                ));
            }
        }
        // A pre-witness index is not silently restored as an empty search surface.
        for row in self.store.text_forward.iter(&txn)? {
            let (id, _) = row?;
            let mut key = b"index_source:text:v1:".to_vec();
            key.extend_from_slice(&id);
            if self.store.vault_meta.get(&txn, &key)?.is_none() {
                return Err(Error::InvalidConfig(
                    "text index lacks canonical rebuild input".into(),
                ));
            }
        }
        for row in self.store.phonetic_forward.iter(&txn)? {
            let (id, _) = row?;
            let mut key = b"index_source:phonetic:v1:".to_vec();
            key.extend_from_slice(&id);
            if self.store.vault_meta.get(&txn, &key)?.is_none() {
                return Err(Error::InvalidConfig(
                    "phonetic index lacks canonical rebuild input".into(),
                ));
            }
        }
        let mut excluded = std::collections::BTreeSet::<Vec<u8>>::new();
        for row in self.store.entities.iter(&txn)? {
            let (key, value) = row?;
            if crate::batch::EntityMetadataHeader::parse(&value)
                .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC)
            {
                excluded.insert(key.to_vec());
            }
        }
        let mut databases = BTreeMap::new();
        for entry in DB_MANIFEST {
            let db = self
                .store
                .env
                .open_database::<Bytes, Bytes>(&txn, Some(entry.name))?
                .ok_or(codec_error())?;
            let mut rows = Vec::new();
            for row in db.iter(&txn)? {
                let (key, value) = row?;
                if storage_tier(entry.name, key) != StorageTier::Canonical {
                    continue;
                }
                let excluded_row = match entry.name {
                    "entities" | "short_ids_reverse" => excluded.contains(key),
                    "short_ids" => excluded.contains(value),
                    "edges_out" | "edges_in" => {
                        key.len() == 33
                            && (excluded.contains(&key[..16]) || excluded.contains(&key[17..]))
                    }
                    "vault_meta" => [
                        b"index_source:text:v1:".as_slice(),
                        b"index_source:phonetic:v1:",
                    ]
                    .iter()
                    .any(|p| key.strip_prefix(*p).is_some_and(|id| excluded.contains(id))),
                    _ => false,
                };
                if excluded_row {
                    continue;
                }
                let value = if entry.name == "job_records" {
                    rebuild::unlease_attempt(key, value)?
                } else {
                    value.to_vec()
                };
                rows.push((key.to_vec(), value));
            }
            databases.insert(entry.name.into(), rows);
        }
        drop(txn);
        let image = CheckpointImage {
            version: 1,
            created_at,
            databases,
        };
        let bytes = rmp_serde::to_vec_named(&image).map_err(|_| codec_error())?;
        let digest = blake3::hash(&bytes);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        // A checkpoint contains canonical private data and device key material.
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(b"ONEIRONC1")?;
        file.write_all(digest.as_bytes())?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(digest.to_hex().to_string())
    }
    /// Restore, wake and migrate use the same fail-closed path, with no tail replay.
    /// Model-dependent vectors enter the normal pending-embedding queue; no vector
    /// from another owner or old model can be served while that queue is rebuilt.
    pub fn restore_checkpoint(
        path: &Path,
        destination: &Path,
        config: VaultConfig,
        reason: RestoreReason,
        restored_at: u64,
    ) -> Result<(Self, RestoreReport)> {
        let mut file = std::fs::File::open(path)?;
        let mut header = [0; 41];
        file.read_exact(&mut header)?;
        if &header[..9] != b"ONEIRONC1" {
            return Err(codec_error());
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        if blake3::hash(&bytes).as_bytes() != &header[9..] {
            return Err(codec_error());
        }
        let image: CheckpointImage = rmp_serde::from_slice(&bytes).map_err(|_| codec_error())?;
        if image.version != 1
            || image.databases.len() != DB_MANIFEST.len()
            || DB_MANIFEST
                .iter()
                .any(|e| !image.databases.contains_key(e.name))
        {
            return Err(codec_error());
        }
        for (name, rows) in &image.databases {
            if rows.windows(2).any(|w| w[0].0 >= w[1].0)
                || rows
                    .iter()
                    .any(|(k, _)| storage_tier(name, k) != StorageTier::Canonical)
            {
                return Err(codec_error());
            }
        }
        if image.databases["entities"].iter().any(|(_, value)| {
            crate::batch::EntityMetadataHeader::parse(value)
                .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC)
        }) {
            return Err(codec_error());
        }
        // Existing content is never replaced or partially restored over.
        std::fs::create_dir(destination)?;
        let vault = Self::open_owned(destination, config.clone())?;
        vault.with_write_txn(|txn| {
            for entry in DB_MANIFEST {
                let db = vault
                    .store
                    .env
                    .open_database::<Bytes, Bytes>(txn, Some(entry.name))?
                    .ok_or(codec_error())?;
                db.clear(txn)?;
                for (key, value) in &image.databases[entry.name] {
                    db.put(txn, key, value)?;
                }
            }
            // Open-time seed/backfill gates consult type indexes. Reconstruct this
            // mechanical projection before reopening; tokenizer/model work waits
            // until those compatibility gates have passed.
            for (key, raw) in &image.databases["entities"] {
                let id = crate::EntityId::from_bytes(
                    key.as_slice().try_into().map_err(|_| codec_error())?,
                )?;
                let h = crate::batch::EntityMetadataHeader::parse(raw).ok_or_else(codec_error)?;
                crate::batch::stage_entity_index_rows(
                    &vault.store,
                    txn,
                    &id,
                    h.entity_type,
                    crate::temporal::TimeRange {
                        start: h.occurred_start,
                        end: h.occurred_end,
                    },
                    h.learned_at,
                )?;
            }
            Ok(())
        })?;
        drop(vault);
        // Re-open through all ABI, model, analyzer and manifest gates before rebuilding.
        let vault = Self::open_owned(destination, config)?;
        let (rebuilt_entities, rebuilt_text_documents, pending_embeddings) =
            rebuild::rebuild(&vault)?;
        rebuild::rebuild_auxiliary(&vault, image.created_at)?;
        let epoch = RestoreEpoch {
            checkpoint_id: blake3::hash(&bytes).to_hex().to_string(),
            restored_at,
            reason,
        };
        vault.with_write_txn(|txn| {
            let prefix = b"restore:epoch:v1:";
            let sequence = match vault
                .store
                .vault_meta
                .prefix_iter(txn, prefix)?
                .last()
                .transpose()?
            {
                None => 0,
                Some((key, _)) => {
                    u64::from_be_bytes(key[prefix.len()..].try_into().map_err(|_| codec_error())?)
                        .checked_add(1)
                        .ok_or(codec_error())?
                }
            };
            let mut key = prefix.to_vec();
            key.extend_from_slice(&sequence.to_be_bytes());
            let body = rmp_serde::to_vec_named(&epoch).map_err(|_| codec_error())?;
            vault.store.vault_meta.put(txn, &key, &body)?;
            Ok(())
        })?;
        let report = RestoreReport {
            epoch,
            rebuilt_entities,
            rebuilt_text_documents,
            pending_embeddings,
        };
        Ok((vault, report))
    }
    pub fn restore_epochs(&self) -> Result<Vec<RestoreEpoch>> {
        let txn = self.store.env.read_txn()?;
        let mut epochs = Vec::new();
        for row in self
            .store
            .vault_meta
            .prefix_iter(&txn, b"restore:epoch:v1:")?
        {
            let (_, body) = row?;
            epochs.push(rmp_serde::from_slice(&body).map_err(|_| codec_error())?);
        }
        Ok(epochs)
    }
}
#[cfg(test)]
mod tests;
