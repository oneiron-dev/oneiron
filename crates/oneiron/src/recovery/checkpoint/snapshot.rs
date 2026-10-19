//! Taking one sealed checkpoint image: the snapshot behind
//! [`Vault::snapshot_checkpoint`] and [`Vault::snapshot_backup`] (moved out
//! of the checkpoint module whole).

use std::collections::BTreeMap;
use std::path::Path;

use heed::types::Bytes;

use super::{
    ArtifactKind, CheckpointImage, INDEX_SOURCE_PHONETIC, INDEX_SOURCE_TEXT, RecoveryWriteBudget,
    StorageTier, artifact, carried_bodies, codec_error, commitment, rebuild, storage_tier,
};
use crate::ports::{IndexRows, RetrievalIndexInventory};
use crate::store::DB_MANIFEST;
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    pub(super) fn snapshot_checkpoint_checked(
        &self,
        path: &Path,
        created_at: u64,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        kind: ArtifactKind,
        budget: &dyn RecoveryWriteBudget,
    ) -> Result<String> {
        self.unlock_vault_key()?;
        let keys = self.checkpoint_signing_keys()?;
        let _custody = self.store.gate_custody_read_guard()?;
        let _bodies = self.pin_all_result_bodies();
        let txn = self.store.env.read_txn()?;
        if let Some(owner) = owner {
            owner.revalidate_in_txn(self, &txn)?;
        }
        // The vault key's wraps the artifact carries are the rows' own, and
        // so is the chain it extends.
        let (carried, key) = self.checkpoint_seal_in_txn(&txn)?;
        let link = commitment::Link {
            keys,
            head: self.checkpoint_chain_in_txn(&txn)?,
        };
        // Refuse a checkpoint that cannot read CURRENT exterior custody; it
        // cannot package key bytes to paper over a missing/shredded key.
        self.store.for_each_gate_decision_in_txn(&txn, |_| Ok(()))?;
        // Only claim/summary bodies have a canonical re-embedding path today.
        // Diagnostics are deliberately runtime-only. Other explicit vectors must
        // not silently disappear.
        for row in self.store.port_vector_rows(&txn, |id, _| {
            crate::EntityId::from_bytes(id.try_into().map_err(|_| codec_error())?)
        })? {
            let id = row??;
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, &txn, &id)?;
            let reconstructable = match raw.as_deref() {
                Some(raw) => {
                    rebuild::has_embedding_source(raw)?
                        || crate::batch::EntityMetadataHeader::parse(raw).is_some_and(|header| {
                            header.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC
                        })
                }
                None => false,
            };
            if !reconstructable {
                return Err(Error::InvalidConfig(
                    "checkpoint vector lacks a canonical re-embedding source".into(),
                ));
            }
        }
        // A pre-witness index is not silently restored as an empty search surface.
        for row in self
            .store
            .port_index_rows(&txn, IndexRows::TextForward, |id, _| {
                EntityId::from_bytes(id.try_into().map_err(|_| codec_error())?)
            })?
        {
            let id = row??;
            if !INDEX_SOURCE_TEXT.contains(&self.store, &txn, &id)? {
                return Err(Error::InvalidConfig(
                    "text index lacks canonical rebuild input".into(),
                ));
            }
        }
        for row in self
            .store
            .port_index_rows(&txn, IndexRows::PhoneticForward, |id, _| {
                EntityId::from_bytes(id.try_into().map_err(|_| codec_error())?)
            })?
        {
            let id = row??;
            if !INDEX_SOURCE_PHONETIC.contains(&self.store, &txn, &id)? {
                return Err(Error::InvalidConfig(
                    "phonetic index lacks canonical rebuild input".into(),
                ));
            }
        }
        let mut excluded = std::collections::BTreeSet::<Vec<u8>>::new();
        for row in crate::ports::EntityStoreRead::port_entity_raw_records(&self.store, &txn)? {
            let (key, value) = row?;
            if crate::batch::EntityMetadataHeader::parse(&value)
                .is_some_and(|h| h.entity_type == crate::registry::ENTITY_TYPE_DIAGNOSTIC)
            {
                excluded.insert(key.as_bytes().to_vec());
            }
        }
        let mut databases = BTreeMap::new();
        let mut census = carried_bodies::BodyCensus::default();
        for entry in DB_MANIFEST {
            let mut image_row = |key: &[u8], value: &[u8]| -> Result<Option<(Vec<u8>, Vec<u8>)>> {
                if storage_tier(entry.name, key) != StorageTier::Canonical {
                    return Ok(None);
                }
                let excluded_row = match entry.name {
                    "entities" | "short_ids_reverse" => excluded.contains(key),
                    "short_ids" => excluded.contains(value),
                    "edges_out" | "edges_in" => {
                        key.len() == 33
                            && (excluded.contains(&key[..16]) || excluded.contains(&key[17..]))
                    }
                    "vault_meta" => [
                        INDEX_SOURCE_TEXT.decl().prefix,
                        INDEX_SOURCE_PHONETIC.decl().prefix,
                    ]
                    .iter()
                    .any(|p| key.strip_prefix(*p).is_some_and(|id| excluded.contains(id))),
                    _ => false,
                };
                if excluded_row {
                    return Ok(None);
                }
                // Every body file a row names goes with it: a result body's,
                // a file-plane ASSET's (FIX 3677), each descriptor's, and a
                // sealed file's key row (FIX 5348).
                census.note(&self.store, &txn, entry.name, key, value)?;
                let value = if entry.name == "job_records" {
                    rebuild::unlease_attempt(key, value)?
                } else {
                    value.to_vec()
                };
                Ok(Some((key.to_vec(), value)))
            };
            let mut rows = Vec::new();
            // A retrieval-index table is read through the inventory port, whose tables the open
            // gate proved present; any other table opens by name, and a missing one is a corrupt
            // image.
            if let Some(index) = IndexRows::of_manifest_db(entry.name) {
                for row in self.store.port_index_rows(&txn, index, &mut image_row)? {
                    rows.extend(row??);
                }
            } else {
                let db = self
                    .store
                    .env
                    .open_database::<Bytes, Bytes>(&txn, Some(entry.name))?
                    .ok_or(codec_error())?;
                for row in db.iter(&txn)? {
                    let (key, value) = row?;
                    rows.extend(image_row(key, value)?);
                }
            }
            databases.insert(entry.name.into(), rows);
        }
        drop(txn);
        // Two rows may name one file: it is carried once. Body files are
        // immutable once named, so the ones the snapshot's rows name read the
        // same after its transaction. Each is sealed into the artifact after
        // the image, and never lands anywhere in the clear.
        let files = census.finish(&self.store)?;
        let (bodies, sealed_bodies) = files.image_bodies();
        let image = CheckpointImage {
            version: 2,
            created_at,
            databases,
            bodies,
            sealed_bodies,
        };
        let bytes = rmp_serde::to_vec_named(&image).map_err(|_| codec_error())?;
        let (id, head) = artifact::write_artifact(
            path,
            &key,
            kind,
            &carried,
            &link,
            created_at,
            &bytes,
            &files.streams(),
            |index| files.open(index),
            budget,
        )?;
        // A checkpoint the chain does not take is no checkpoint.
        if let Err(error) = self.advance_checkpoint_chain(link.head, head) {
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        Ok(blake3::Hash::from(id).to_hex().to_string())
    }
}
