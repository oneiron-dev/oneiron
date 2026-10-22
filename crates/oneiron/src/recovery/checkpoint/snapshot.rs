//! Taking one sealed checkpoint image: the snapshot behind
//! [`Vault::snapshot_checkpoint`] and [`Vault::snapshot_backup`] (moved out
//! of the checkpoint module whole).

use std::collections::BTreeMap;
use std::path::Path;

use heed::types::Bytes;
use oneiron_crypto::backup::{BackupEvidence, CheckpointFact, SignedCheckpointFact};

use super::watermark::SnapshotMark;
use super::{
    ArtifactKind, BackupSnapshotReceipt, CheckpointImage, INDEX_SOURCE_PHONETIC, INDEX_SOURCE_TEXT,
    RecoveryWriteBudget, StorageTier, artifact, carried_bodies, codec_error, commitment, rebuild,
    storage_tier,
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
        registry: Option<&str>,
        budget: &dyn RecoveryWriteBudget,
    ) -> Result<BackupSnapshotReceipt> {
        // Each stage logs its start with counts and elapsed time only, never
        // a row, a key, a path or a value (FIX 6778).
        let started = std::time::Instant::now();
        tracing::info!(
            stage = "setup",
            kind = kind.code(),
            "checkpoint snapshot: unlocking the vault key, minting the backup incarnation and \
             preparing pads"
        );
        self.unlock_vault_key()?;
        // The store's backup incarnation is minted before its first
        // snapshot reads it (the backup watermark).
        self.mint_backup_incarnation()?;
        // Every pad a row holds goes into current custody first, outside
        // the custody guard, so the image names it by reference (KS-5, FIX
        // 5686 part 2). One that does not go rides as its carrier.
        if let Err(error) = self.prepare_image_pads() {
            tracing::warn!(
                kind = ?error.kind(),
                "world key pads were not prepared for this image; any custody lacks rides as \
                 its carrier"
            );
        }
        let mut pass = 0_u32;
        loop {
            pass = pass.saturating_add(1);
            tracing::info!(
                stage = "binding",
                pass,
                elapsed_ms = elapsed_ms(started),
                "checkpoint snapshot: binding the bodies the image carries"
            );
            // Every body the image carries has its instance minted and bound
            // first, before the snapshot and its custody guard, the mints
            // outside any writer (KS-2A). A body written since is bound by
            // the next pass, and the snapshot taken again.
            self.bind_carried_bodies()?;
            if let Some(id) = self.snapshot_once(path, created_at, owner, kind, registry, budget)? {
                tracing::info!(
                    stage = "done",
                    pass,
                    elapsed_ms = elapsed_ms(started),
                    "checkpoint snapshot: done"
                );
                return Ok(id);
            }
            tracing::info!(
                stage = "retry",
                pass,
                elapsed_ms = elapsed_ms(started),
                "checkpoint snapshot: a body its rows name has no instance bound yet; taking it \
                 again"
            );
        }
    }

    /// One snapshot: `None` when a body its rows name has no instance bound
    /// yet. Its receipt covers what its read transaction and the custody
    /// position under its guard saw, its own chain advance excluded.
    fn snapshot_once(
        &self,
        path: &Path,
        created_at: u64,
        owner: Option<&crate::consent::AuthenticatedOwner>,
        kind: ArtifactKind,
        registry: Option<&str>,
        budget: &dyn RecoveryWriteBudget,
    ) -> Result<Option<BackupSnapshotReceipt>> {
        let started = std::time::Instant::now();
        let keys = self.checkpoint_signing_keys()?;
        tracing::info!(
            stage = "lock",
            "checkpoint snapshot: taking the custody read guard and the result-body pins"
        );
        let _custody = self.store.gate_custody_read_guard()?;
        let _bodies = self.pin_all_result_bodies();
        let txn = self.store.env.read_txn()?;
        tracing::info!(
            stage = "pins",
            elapsed_ms = elapsed_ms(started),
            "checkpoint snapshot: custody guard and pins held; reading the rows"
        );
        // Where the vault stands for the backup watermark: this read
        // transaction's id and the custody position under the same guard,
        // after the keys, signer and bodies were prepared.
        let mark = SnapshotMark::read(self, &txn)?;
        // What the image needs of its custody, read under the same guard
        // once its snapshot is open, so every key a row of it names was
        // journaled first: its position and every live id, never a key
        // (KS-4).
        let required = self.store.custody_requirement()?;
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
        // Claim and summary bodies and a TURN's message text (FIX 8826) have a
        // canonical re-embedding path. Diagnostics are deliberately
        // runtime-only. Other explicit vectors must not silently disappear.
        self.validate_checkpoint_rebuild_sources(&txn)?;
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
        // Window snapshots kept as they rest, warned by count (FIX 7107).
        let mut kept_windows = 0;
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
                // Every body a row names goes with it, sealed under its
                // instance: a result body's file, a file-plane ASSET's (FIX
                // 3677), each descriptor's, and an inline body, whose row
                // goes without it (KS-2A).
                let stripped = census.note(&self.store, &txn, entry.name, key, value)?;
                // A credential row rides as it rests, its value sealed under
                // its generation's custody key, never opened (KS-6 part 2,
                // CALLS `KS-6 image value form`).
                let value = if let Some(stripped) = stripped {
                    stripped
                } else if entry.name == "entities"
                    && let Some(reference) =
                        crate::world_keys::image_pad_projection(&self.store, value)
                {
                    // A pad row goes by its bare reference, its pad left in
                    // current custody, which a restore takes it from (KS-5,
                    // FIX 5686 part 2).
                    reference
                } else if let Some(projected) = super::window_pad_refs::image_window_pads(
                    self,
                    entry.name,
                    key,
                    value,
                    &mut kept_windows,
                ) {
                    // So does a window snapshot's, where custody here holds
                    // its pads (FIX 7107).
                    projected
                } else {
                    value.to_vec()
                };
                // Every queue row goes unleased: an agent dispatch's stub
                // too, whose instance seals the row as it stood (FIX 7115).
                // An opaque one's stub, the erased marker, and an opaque row
                // itself go as they are (FIX 9390).
                let value = if entry.name == "job_records"
                    && !crate::attempt_queue::attempt_row_opaque(key, &value)
                {
                    rebuild::unlease_attempt(key, &value)?
                } else {
                    value
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
        super::window_pad_refs::warn_kept_window_pads(kept_windows);
        tracing::info!(
            stage = "census",
            databases = databases.len(),
            rows = databases.values().map(Vec::len).sum::<usize>(),
            elapsed_ms = elapsed_ms(started),
            "checkpoint snapshot: rows read"
        );
        // A response binding whose row holds no response now names nothing
        // the image carries: it stays out (KS-2B1).
        let stale = census.stale();
        if let Some(rows) = databases.get_mut("vault_meta") {
            rows.retain(|(key, _)| !stale.contains(key));
        }
        // Two rows may name one file: it is carried once. Body files are
        // immutable once named, so the ones the snapshot's rows name read the
        // same after its transaction. Each is sealed into the artifact after
        // the image, and never lands anywhere in the clear.
        let Some(files) = census.finish(&self.store)? else {
            tracing::info!(
                stage = "unbound",
                elapsed_ms = elapsed_ms(started),
                "checkpoint snapshot: a body its rows name has no instance bound yet"
            );
            return Ok(None);
        };
        let (bodies, sealed_bodies, inline_bodies) = files.image_bodies();
        let image = CheckpointImage {
            version: super::image::IMAGE_VERSION,
            created_at,
            databases,
            bodies,
            sealed_bodies,
            inline_bodies,
            checkpoint_sequence: None,
        };
        let bytes = rmp_serde::to_vec_named(&image).map_err(|_| codec_error())?;
        tracing::info!(
            stage = "holder",
            image_bytes = bytes.len(),
            files = image.bodies.len(),
            inline = image.inline_bodies.len(),
            elapsed_ms = elapsed_ms(started),
            "checkpoint snapshot: holding the image's bodies"
        );
        // Every body instance the image carries is held for it, synced,
        // before it is written (FIX 6022): no retention retires one while a
        // copy of it is kept. A write that fails keeps the holder.
        let holder = self.store.hold_image_bodies(
            image
                .databases
                .get("vault_meta")
                .map_or(&[][..], Vec::as_slice),
        )?;
        tracing::info!(
            stage = "write",
            held = holder.is_some(),
            elapsed_ms = elapsed_ms(started),
            "checkpoint snapshot: writing the artifact"
        );
        let (id, head, evidence) = artifact::write_artifact(
            path,
            &key,
            kind,
            registry,
            &carried,
            &link,
            required.as_ref(),
            created_at,
            &bytes,
            &files.streams(),
            |index| files.open(index),
            None,
            budget,
        )?;
        tracing::info!(
            stage = "chain",
            size = evidence.size,
            frames = evidence.frames,
            elapsed_ms = elapsed_ms(started),
            "checkpoint snapshot: artifact written; advancing the chain"
        );
        // A checkpoint the chain does not take is no checkpoint.
        if let Err(error) = self.advance_checkpoint_chain(link.head, head) {
            let _ = std::fs::remove_file(path);
            return Err(error);
        }
        // Its holder is named by its checkpoint id, which its custodian
        // knows it by; one that is not named stays kept.
        if let Some(holder) = holder
            && let Err(error) = holder.name(&id)
        {
            tracing::warn!(
                kind = ?error.kind(),
                "a checkpoint's body holder was not named; its bodies stay kept"
            );
        }
        // A backup's identity is complete and the chain took it: its
        // checkpoint fact is signed with the keys that signed it (FIX 7326).
        // A checkpoint publishes none.
        let checkpoint_fact = (kind == ArtifactKind::Backup)
            .then(|| sign_fact(&link.keys, id, &evidence))
            .flatten();
        tracing::info!(
            stage = "receipt",
            fact = checkpoint_fact.is_some(),
            elapsed_ms = elapsed_ms(started),
            "checkpoint snapshot: receipt"
        );
        Ok(Some(BackupSnapshotReceipt {
            image_digest: blake3::Hash::from(id).to_hex().to_string(),
            covered: mark.covered(),
            evidence,
            checkpoint_fact,
        }))
    }

    /// Every explicit vector and text or phonetic index row has the canonical
    /// source a restore rebuilds it from.
    fn validate_checkpoint_rebuild_sources(&self, txn: &heed::RoTxn<'_>) -> Result<()> {
        for row in self.store.port_vector_rows(txn, |id, _| {
            crate::EntityId::from_bytes(id.try_into().map_err(|_| codec_error())?)
        })? {
            let id = row??;
            let raw = crate::ports::EntityStoreRead::port_entity_raw(&self.store, txn, &id)?;
            let reconstructable = match raw.as_deref() {
                Some(raw) => {
                    rebuild::has_checkpoint_embedding_source(self, txn, &id, raw)?
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
            .port_index_rows(txn, IndexRows::TextForward, |id, _| {
                EntityId::from_bytes(id.try_into().map_err(|_| codec_error())?)
            })?
        {
            let id = row??;
            if !INDEX_SOURCE_TEXT.contains(&self.store, txn, &id)? {
                return Err(Error::InvalidConfig(
                    "text index lacks canonical rebuild input".into(),
                ));
            }
        }
        for row in self
            .store
            .port_index_rows(txn, IndexRows::PhoneticForward, |id, _| {
                EntityId::from_bytes(id.try_into().map_err(|_| codec_error())?)
            })?
        {
            let id = row??;
            if !INDEX_SOURCE_PHONETIC.contains(&self.store, txn, &id)? {
                return Err(Error::InvalidConfig(
                    "phonetic index lacks canonical rebuild input".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Milliseconds since `started`, for a stage's log.
fn elapsed_ms(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// The checkpoint fact of the backup `evidence` describes, whose image is
/// `id`, signed with `keys`, the keys that signed its commitment. One that
/// fails is logged and left unavailable: the backup stands without it.
fn sign_fact(
    keys: &commitment::SigningKeys,
    id: [u8; 32],
    evidence: &BackupEvidence,
) -> Option<SignedCheckpointFact> {
    let fact = CheckpointFact {
        engine_vault_id: evidence.engine_vault_id,
        checkpoint_id: id,
        commitment_digest: evidence.commitment_digest,
        outer_blake3: evidence.outer_blake3,
        size: evidence.size,
    };
    match keys.sign_checkpoint_fact(&fact) {
        Ok(signed) => Some(signed),
        Err(error) => {
            tracing::warn!(
                reason = "backup_checkpoint_fact_unsigned",
                kind = ?error.kind(),
                "the backup landed with no checkpoint fact; its checkpoint id stays unsigned \
                 beside it"
            );
            None
        }
    }
}
