//! Three-tier repair driver: whole validation and publication, the work
//! between them paged on the vault's fair task-work line (FIX 8821).

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
        add("entity_documents", pack(&snapshot.entity_documents)?);
        add("document_heads", pack(&snapshot.document_heads)?);
        add("head_move_receipts", pack(&snapshot.head_move_receipts)?);
        add("note_forks", pack(&snapshot.note_forks)?);
        add("note_proposals", pack(&snapshot.note_proposals)?);
        add("row_births", pack(&snapshot.row_births)?);
        add("withdrawn_cutoffs", pack(&snapshot.withdrawn_cutoffs)?);
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
    /// The rows one page of a recovery's rebuild, replay or verification
    /// takes before it hands its turn on: a page size, never a total a
    /// recovery refuses past (Rule 5, FIX 8821). Zero reads as one.
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

/// Quarantine happens after complete payload/budget validation and the
/// rebuild, before any replay write. Run with window writers stopped, as for
/// canonical capture.
pub fn prepare_recovery(
    manifest_path: impl AsRef<Path>,
    snapshot: &CanonicalSnapshot,
    budget: RecoveryBudget,
) -> Result<PreparedRecovery> {
    let window = rebuild_vault_window_from_canonical(snapshot)?;
    prepare_rebuilt(manifest_path.as_ref(), snapshot, budget, window)
}

/// [`prepare_recovery`] with `window` already rebuilt from `snapshot`. Every
/// obligation is admitted: how many there are sizes the pages that repair
/// them, and never refuses the recovery (Rule 5, FIX 8821).
pub(super) fn prepare_rebuilt(
    path: &Path,
    snapshot: &CanonicalSnapshot,
    budget: RecoveryBudget,
    window: LoroDoc,
) -> Result<PreparedRecovery> {
    let encoded = snapshot.encode()?;
    limit(encoded.len(), budget.max_bytes)?;
    let expected = RecoveryManifest::from_snapshot(snapshot)?;
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
    let quarantine_path = if tier != RecoveryTier::Healthy {
        bytes
            .as_ref()
            .map(|bytes| super::quarantine::quarantine_invalid_artifact(path, bytes))
            .transpose()?
    } else {
        None
    };
    Ok(PreparedRecovery {
        tier,
        window,
        quarantine_path,
        obligations,
        manifest: expected,
    })
}
pub(super) fn limit(required: usize, limit: usize) -> Result<()> {
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
    pub(super) fn publish(&self, path: &Path) -> Result<()> {
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
/// The work runs a page at a time on the vault's task-work line, as host
/// work served after every caller's (FIX 8821), and this call drains it.
#[cfg(feature = "sync")]
pub fn recover_vault_window(
    vault: &crate::Vault,
    materializer: &crate::sync::bridge::Materializer,
    manifest_path: impl AsRef<Path>,
    snapshot: &CanonicalSnapshot,
    budget: RecoveryBudget,
) -> Result<PreparedRecovery> {
    super::work::RecoveryWork::new(manifest_path.as_ref(), snapshot, budget, None)
        .drain(vault, materializer)
}

/// Verifies a replayed recovery a page of checks at a time (FIX 8821), in
/// the order one run takes them: each pad row the artifact names by bare
/// reference completes only with its pad here, its stored row's or current
/// custody's: one not here stays pending, refused as not here yet, never a
/// Healthy or repaired manifest (KS-5). Then the recapture must be
/// equivalent to the artifact, a check of the whole: forward replay may
/// quarantine semantic/authority failures, and a partial replay is never
/// complete merely because that door reported its row count. Then every
/// entity and edge must have landed, and last the window's pads are carried.
/// `at` counts the checks done; returns whether all are.
#[cfg(feature = "sync")]
pub(super) fn verify_page(
    vault: &crate::Vault,
    prepared: &PreparedRecovery,
    snapshot: &CanonicalSnapshot,
    at: &mut usize,
    page: usize,
) -> Result<bool> {
    let entities = snapshot.entity_blobs.len();
    let landed_edges = 2 * entities + 1;
    let total = landed_edges + snapshot.base_edges.len() + 1;
    let end = at.saturating_add(page.max(1)).min(total);
    while *at < end {
        let check = *at;
        if check == entities {
            let actual =
                super::capture_canonical_window(vault, &snapshot.window, &prepared.window)?;
            if &pad_equivalent(vault, actual, snapshot) != snapshot {
                return Err(invalid("recovery materialization is not equivalent"));
            }
        } else if check + 1 == total {
            carry_window_pads(vault, &prepared.window)?;
        } else if check < entities {
            let entity = &snapshot.entity_blobs[check];
            let txn = vault.store.env.read_txn()?;
            let id = crate::EntityId::from_bytes(entity.id)?;
            if let Some(waits) = crate::world_keys::pad_reference_waits_in_txn(
                &vault.store,
                &txn,
                &id,
                &entity.blob,
            )? {
                return Err(waits);
            }
        } else if check < landed_edges {
            entity_landed(vault, &snapshot.entity_blobs[check - entities - 1])?;
        } else {
            edge_landed(vault, &snapshot.base_edges[check - landed_edges])?;
        }
        *at += 1;
    }
    Ok(*at == total)
}

/// A pad row the artifact names by reference rests with its pad: it landed
/// when the same key's pad is here (KS-5).
#[cfg(feature = "sync")]
fn entity_landed(vault: &crate::Vault, entity: &super::CanonicalEntity) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let id = crate::EntityId::from_bytes(entity.id)?;
    let landed = match crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &id)? {
        Some(stored) => {
            stored == entity.blob
                || crate::world_keys::pad_echo_equal(&vault.store, &stored, &entity.blob)
        }
        None => false,
    };
    if !landed {
        return Err(invalid("entity materialization incomplete"));
    }
    Ok(())
}

/// Local invalidation outranks the image's support stamp: the replay lands
/// it retracted where every local wrapper withdrew.
#[cfg(feature = "sync")]
fn edge_landed(vault: &crate::Vault, edge: &super::CanonicalBaseEdge) -> Result<()> {
    let txn = vault.store.env.read_txn()?;
    let source = crate::EntityId::from_bytes(edge.source)?;
    let target = crate::EntityId::from_bytes(edge.target)?;
    let kind = crate::EdgeKind::try_from_u8(edge.kind)
        .ok_or_else(|| invalid("edge kind materialization"))?;
    let stored = crate::ports::EdgeStoreStaging::port_edge_encoded(
        &vault.store,
        &txn,
        &source,
        kind,
        &target,
    )?;
    let landed = match stored.as_deref() {
        Some(stored) => {
            stored == edge.value.as_slice()
                || crate::provenance::holds_withdrawn_image(
                    &vault.store,
                    &txn,
                    &crate::provenance::EdgeRef::new(source, kind, target),
                    &edge.value,
                    stored,
                )?
        }
        None => false,
    };
    if !landed {
        return Err(invalid("edge materialization incomplete"));
    }
    Ok(())
}

/// `actual`, a recapture of a recovered window, with each pad row naming the
/// same header, key and pad as `wanted`'s taken as `wanted`'s: a carrier an
/// artifact kept where custody could not take its pad reads back as its
/// reference once the recovery published that pad (KS-5).
#[cfg(feature = "sync")]
pub(super) fn pad_equivalent(
    vault: &crate::Vault,
    mut actual: CanonicalSnapshot,
    wanted: &CanonicalSnapshot,
) -> CanonicalSnapshot {
    for (entity, want) in actual.entity_blobs.iter_mut().zip(&wanted.entity_blobs) {
        if entity.id == want.id
            && entity.blob != want.blob
            && crate::world_keys::image_pad_row_of(&entity.blob).is_some()
            && crate::world_keys::pad_echo_equal(&vault.store, &entity.blob, &want.blob)
        {
            entity.blob.clone_from(&want.blob);
        }
    }
    actual
}

/// Fills each pad row the rebuilt `window` names by bare reference, and
/// whose pad current custody does not hold, with its carrier: from the row
/// just landed, never from the artifact (KS-5). Each pad a landed row holds
/// that custody lacks is taken into current custody first and read back
/// (FIX 7293), so the window keeps its references, as its durable state and
/// the WindowSync pad envelope do (FIX 7107), and a re-bootstrap installs
/// no carrier. A pad custody still cannot take keeps its carrier (KEEP
/// TODAY, Engine 10-22); a pad not here stays a reference.
#[cfg(feature = "sync")]
fn carry_window_pads(vault: &crate::Vault, window: &LoroDoc) -> Result<()> {
    use super::canonical::{binary_rows, id, insert, parse_id};
    super::canonical::prepare_artifact_pads(vault);
    let txn = vault.store.env.read_txn()?;
    let mut carried = false;
    for (key, blob) in binary_rows(window, "entities")? {
        let Some(row) = crate::world_keys::image_pad_row_of(&blob).filter(|row| !row.held) else {
            continue;
        };
        // A reference whose pad current custody holds stays one: the
        // window's durable state takes it, and a send that goes as the
        // carrier inflates it from custody (FIX 7107).
        if matches!(vault.store.world_pad_in_custody(&row.item), Ok(Some(_))) {
            continue;
        }
        let Some(stored) = crate::ports::EntityStoreRead::port_entity_raw(
            &vault.store,
            &txn,
            &id(parse_id(&key)?)?,
        )?
        else {
            continue;
        };
        if let Some(carrier) = crate::world_keys::live_route_row(&vault.store, stored)
            && crate::world_keys::image_pad_row_of(&carrier).is_some_and(|row| row.held)
        {
            insert(window, "entities", &key, &carrier)?;
            carried = true;
        }
    }
    if carried {
        window.commit();
    }
    Ok(())
}
