//! Three-tier repair driver with all-or-nothing bounded work admission.

use super::canonical::{CanonicalSnapshot, invalid, pack, rebuild_vault_window_from_canonical};
use super::{decode_recovery_artifact, encode_recovery_artifact};
use crate::error::{ArtifactError, Result};
use loro::LoroDoc;
use serde::{Deserialize, Serialize};
use std::io::Read;
#[cfg(feature = "sync")]
use std::io::Write;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub const RECOVERY_MANIFEST_ARTIFACT_TYPE: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryTier {
    Healthy,
    TargetedChunkRepair,
    FullRebuild,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryManifest {
    pub snapshot_blake3: [u8; 32],
    pub chunks: BTreeMap<String, [u8; 32]>,
}
impl RecoveryManifest {
    pub fn from_snapshot(snapshot: &CanonicalSnapshot) -> Result<Self> {
        snapshot.validate()?;
        let mut chunks = BTreeMap::new();
        let mut add = |key: &str, bytes: Vec<u8>| {
            chunks.insert(key.to_owned(), *blake3::hash(&bytes).as_bytes());
        };
        add("entities", pack(&snapshot.entity_blobs)?);
        add("edges", pack(&snapshot.base_edges)?);
        add("tombstones", pack(&snapshot.tombstones)?);
        add("document_heads", pack(&snapshot.document_heads)?);
        add("head_move_receipts", pack(&snapshot.head_move_receipts)?);
        add("note_forks", pack(&snapshot.note_forks)?);
        add("note_proposals", pack(&snapshot.note_proposals)?);
        add("schema", pack(&snapshot.schema_manifest)?);
        add("containers", pack(&snapshot.container_manifests)?);
        for document in &snapshot.doc_snapshots {
            add(&document.key(), pack(document)?);
        }
        Ok(Self {
            snapshot_blake3: snapshot.blake3()?,
            chunks,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        encode_recovery_artifact(RECOVERY_MANIFEST_ARTIFACT_TYPE, &pack(self)?)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let artifact = decode_recovery_artifact(bytes, RECOVERY_MANIFEST_ARTIFACT_TYPE)?;
        let value: Self =
            rmp_serde::from_slice(artifact.payload()).map_err(|_| invalid("manifest payload"))?;
        if value.chunks.is_empty()
            || value.chunks.len() > 65536
            || pack(&value)? != artifact.payload()
        {
            return Err(invalid("manifest shape"));
        }
        Ok(value)
    }
}

/// Invalid canonical state is an error, never an excuse to rebuild from bad bytes.
pub fn assess_recovery(
    manifest: Option<&RecoveryManifest>,
    snapshot: &CanonicalSnapshot,
) -> Result<RecoveryTier> {
    let expected = RecoveryManifest::from_snapshot(snapshot)?;
    Ok(classify(manifest, &expected))
}
fn classify(manifest: Option<&RecoveryManifest>, expected: &RecoveryManifest) -> RecoveryTier {
    let Some(manifest) = manifest else {
        return RecoveryTier::FullRebuild;
    };
    if manifest == expected {
        return RecoveryTier::Healthy;
    }
    if manifest.snapshot_blake3 != expected.snapshot_blake3
        || manifest.chunks.keys().ne(expected.chunks.keys())
        || manifest.chunks.get("schema") != expected.chunks.get("schema")
        || manifest.chunks.get("containers") != expected.chunks.get("containers")
    {
        return RecoveryTier::FullRebuild;
    }
    let broken = expected
        .chunks
        .iter()
        .filter(|(key, hash)| manifest.chunks.get(*key) != Some(*hash))
        .count();
    if broken == 1 {
        RecoveryTier::TargetedChunkRepair
    } else {
        RecoveryTier::FullRebuild
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RecoveryBudget {
    pub max_bytes: usize,
    pub max_obligations: usize,
}
impl Default for RecoveryBudget {
    fn default() -> Self {
        Self {
            max_bytes: super::CANONICAL_SNAPSHOT_MAX_BYTES,
            max_obligations: 4096,
        }
    }
}

/// Validated and admitted work. No pending obligation is truncated to fit a budget.
/// On an apply error the caller retains the canonical artifact and retries; the
/// quarantined manifest is never deleted or republished as healthy.
pub struct PreparedRecovery {
    pub tier: RecoveryTier,
    pub window: LoroDoc,
    pub quarantine_path: Option<PathBuf>,
    pub obligations: Vec<String>,
    manifest: RecoveryManifest,
}

/// Quarantine happens after complete payload/budget validation and before rebuild.
/// Run with window writers stopped, as for canonical capture.
pub fn prepare_recovery(
    manifest_path: impl AsRef<Path>,
    snapshot: &CanonicalSnapshot,
    budget: RecoveryBudget,
) -> Result<PreparedRecovery> {
    let encoded = snapshot.encode()?;
    limit(encoded.len(), budget.max_bytes)?;
    let expected = RecoveryManifest::from_snapshot(snapshot)?;
    let path = manifest_path.as_ref();
    let bytes = match fs::File::open(path) {
        Ok(file) => {
            limit(
                usize::try_from(file.metadata()?.len()).unwrap_or(usize::MAX),
                budget.max_bytes,
            )?;
            let mut bytes = Vec::new();
            file.take(budget.max_bytes.saturating_add(1) as u64)
                .read_to_end(&mut bytes)?;
            limit(bytes.len(), budget.max_bytes)?;
            Some(bytes)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let manifest = bytes
        .as_ref()
        .and_then(|bytes| RecoveryManifest::decode(bytes).ok());
    let tier = classify(manifest.as_ref(), &expected);
    let obligations: Vec<_> = expected
        .chunks
        .iter()
        .filter(|(key, hash)| {
            tier == RecoveryTier::FullRebuild
                || manifest
                    .as_ref()
                    .is_none_or(|m| m.chunks.get(*key) != Some(*hash))
        })
        .map(|(key, _)| key.clone())
        .collect();
    limit(obligations.len(), budget.max_obligations)?;
    let quarantine_path = if tier != RecoveryTier::Healthy {
        bytes
            .as_ref()
            .map(|bytes| super::quarantine::quarantine_invalid_artifact(path, bytes))
            .transpose()?
    } else {
        None
    };
    let window = rebuild_vault_window_from_canonical(snapshot)?;
    Ok(PreparedRecovery {
        tier,
        window,
        quarantine_path,
        obligations,
        manifest: expected,
    })
}
fn limit(required: usize, limit: usize) -> Result<()> {
    if required > limit {
        return Err(ArtifactError::OverlayLimit { required, limit }.into());
    }
    Ok(())
}

impl PreparedRecovery {
    /// Persist the repaired manifest only after the normal materializer completed.
    /// A normal atomic rename would overwrite a concurrent publisher; the
    /// exclusive rename instead keeps both bytes and reports a retryable race.
    #[cfg(feature = "sync")]
    fn publish(&self, path: &Path) -> Result<()> {
        let temporary = path.with_extension(format!("repair-{}", crate::EntityId::now().to_hex()));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        let outcome = (|| {
            file.write_all(&self.manifest.encode()?)?;
            file.sync_all()?;
            match super::quarantine::rename_no_replace(&temporary, path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    return Err(crate::Error::ConcurrentWrite(
                        "recovery manifest published concurrently",
                    ));
                }
                Err(error) => return Err(error.into()),
            }
            super::quarantine::sync_parent(path)?;
            Ok(())
        })();
        if outcome.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        outcome
    }
    /// The expected replacement manifest, also usable by featureless hosts.
    pub fn repaired_manifest(&self) -> &RecoveryManifest {
        &self.manifest
    }
}

/// Recovery replay uses the exact same forward validator/materializer as sync.
/// Targeted repair benefits from its byte-compare skips: unaffected LMDB rows
/// and entity documents are not replaced. A failed pass never publishes Healthy.
#[cfg(feature = "sync")]
pub fn recover_vault_window(
    vault: &crate::Vault,
    materializer: &crate::sync::bridge::Materializer,
    manifest_path: impl AsRef<Path>,
    snapshot: &CanonicalSnapshot,
    budget: RecoveryBudget,
) -> Result<PreparedRecovery> {
    let path = manifest_path.as_ref();
    // Full domain validation precedes quarantine and every durable write.
    limit(snapshot.encode()?.len(), budget.max_bytes)?;
    let candidate = rebuild_vault_window_from_canonical(snapshot)?;
    crate::sync::bridge::preflight_canonical_recovery(vault, materializer, snapshot, &candidate)?;
    let prepared = prepare_recovery(path, snapshot, budget)?;
    let key = crate::sync::types::WindowKey::new(&snapshot.window);
    crate::sync::window::forward_recovery(vault, &prepared.window, materializer, &key, snapshot)?;
    // Forward replay may quarantine semantic/authority failures. Never mark a
    // partial replay complete merely because that door reported its row count.
    let actual = super::capture_canonical_window(vault, &snapshot.window, &prepared.window)?;
    if &actual != snapshot {
        return Err(invalid("recovery materialization is not equivalent"));
    }
    {
        let txn = vault.store.env.read_txn()?;
        for entity in &snapshot.entity_blobs {
            if vault.store.entities.get(&txn, &entity.id)?.as_deref()
                != Some(entity.blob.as_slice())
            {
                return Err(invalid("entity materialization incomplete"));
            }
        }
        for edge in &snapshot.base_edges {
            let key = [&edge.source[..], &[edge.kind], &edge.target[..]].concat();
            if vault.store.edges_out.get(&txn, &key)?.as_deref() != Some(edge.value.as_slice()) {
                return Err(invalid("edge materialization incomplete"));
            }
        }
    }
    if prepared.tier != RecoveryTier::Healthy {
        prepared.publish(path)?;
    }
    Ok(prepared)
}
