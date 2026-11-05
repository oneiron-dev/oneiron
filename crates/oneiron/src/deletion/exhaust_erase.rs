//! Canonical BYOA exhausts reached by an accepted source erase (FIX 7617).
//!
//! The original queue source subsets select a native terminal capture. The
//! borrowed accepted actor/restore writer authorizes the first operation;
//! only this module writes its persisted continuation. Missing capture or
//! instance evidence remains owed, never proof that keys were destroyed.

use std::collections::BTreeSet;

use crate::Vault;
use crate::attempt_queue::{AttemptId, ErasedByoaPayloads};
use crate::batch::EntityMetadataHeader;
use crate::dispatch_byoa::{CanonicalCapture, canonical_capture_in_txn};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::secret_custody::EraseOwnerAct;
use crate::side_table::{self, Named, SideTable};

/// Whether an actual full native purge completed; missing metadata alone
/// never establishes completion.
#[derive(Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Teardown {
    #[default]
    Pending,
    Purged,
}

/// A private accepted continuation, not a caller-supplied artifact selector.
/// All fields are structural history; no output or key bytes are stored here.
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedExhaustErase {
    sources: BTreeSet<EntityId>,
    capture: Option<CanonicalCapture>,
    hashes: BTreeSet<[u8; 32]>,
    covered_hashes: BTreeSet<[u8; 32]>,
    expected_instances: BTreeSet<[u8; 16]>,
    hash_inventory_complete: bool,
    teardown: Teardown,
    retirements: BTreeSet<String>,
}

const ERASES: SideTable<[u8; 16], AcceptedExhaustErase, Named> =
    SideTable::new(&side_table::BYOA_EXHAUST_ERASE);

/// An actual native purge's inventory, captured before its first reference
/// release. It is temporary data, including when that purge preceded the
/// accepted queue-family join.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct ArtifactInventory {
    hashes: Vec<[u8; 32]>,
    covered_hashes: BTreeSet<[u8; 32]>,
    expected_instances: BTreeSet<[u8; 16]>,
    inline_assets: Vec<EntityId>,
    complete: bool,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ActivePurge {
    inventory: Option<ArtifactInventory>,
}

/// Only the native full purge writes this transaction-local context.
/// Every successful or failed purge clears it before returning to a caller.
const ACTIVE_PURGES: SideTable<EntityId, ActivePurge, Named> =
    SideTable::new(&side_table::BYOA_EXHAUST_ACTIVE_PURGE);

pub(in crate::deletion) fn begin_native_purge_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    let inventory = match vault.store.port_entity_raw(txn, id)? {
        Some(raw)
            if EntityMetadataHeader::parse(&raw).is_some_and(|header| {
                header.entity_type == crate::registry::ENTITY_TYPE_BLOB_ARTIFACT
            }) =>
        {
            Some(capture_inventory_in_txn(vault, txn, id, &raw)?)
        }
        _ => None,
    };
    ACTIVE_PURGES.put(&vault.store, txn, id, &ActivePurge { inventory })
}

pub(in crate::deletion) fn finish_native_purge_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    // Record only an actual completed native purge of an already accepted
    // family. Neither an absent row nor the active marker grants authority.
    let keys = ERASES.scan_keys(&vault.store, txn, &[])?;
    for key in keys {
        let Some(mut accepted) = ERASES.get(&vault.store, txn, &key)? else {
            continue;
        };
        if accepted
            .capture
            .as_ref()
            .is_some_and(|capture| capture.artifact() == *id)
        {
            accepted.teardown = Teardown::Purged;
            bind_names_in_txn(vault, txn, &mut accepted)?;
            ERASES.put(&vault.store, txn, &key, &accepted)?;
        }
    }
    Ok(())
}

/// Matching cleanup runs even if a native caller catches the purge's
/// error and continues its writer. No committed in-flight context remains.
pub(in crate::deletion) fn end_native_purge_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    ACTIVE_PURGES.delete(&vault.store, txn, id)?;
    Ok(())
}

pub(crate) fn erase_owned_byoa_exhausts_in_txn(
    erase: &mut super::ActorErasureWriter<'_, '_>,
    owned: &ErasedByoaPayloads,
    act: Option<&EraseOwnerAct<'_>>,
) -> Result<Vec<(AttemptId, u32)>> {
    let (vault, txn, _) = erase.parts();
    accept_in_txn(vault, txn, owned, act)
}

pub(crate) fn erase_restored_byoa_exhausts_in_txn(
    restore: &mut crate::recovery::checkpoint::RestoreActorScrubWriter<'_, '_>,
    owned: &ErasedByoaPayloads,
) -> Result<Vec<(AttemptId, u32)>> {
    let (vault, txn, _) = restore.parts();
    accept_in_txn(vault, txn, owned, None)
}

fn accept_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owned: &ErasedByoaPayloads,
    act: Option<&EraseOwnerAct<'_>>,
) -> Result<Vec<(AttemptId, u32)>> {
    let mut cancelled = Vec::new();
    for (attempt, sources) in owned.sources() {
        let mut accepted = ERASES
            .get(&vault.store, txn, attempt.as_bytes())?
            .unwrap_or_default();
        accepted.sources.extend(sources.iter().copied());
        cancelled.extend(settle_in_txn(vault, txn, *attempt, &mut accepted, act)?);
        ERASES.put(&vault.store, txn, attempt.as_bytes(), &accepted)?;
    }
    Ok(cancelled)
}

impl Vault {
    /// Replays only private persisted accepted continuations. A marker alone
    /// never creates an artifact selection or a new erase operation.
    pub(in crate::deletion) fn settle_owed_byoa_exhaust_erases_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<Vec<(AttemptId, u32)>> {
        let mut cancelled = Vec::new();
        let keys = ERASES.scan_keys(&self.store, txn, &[])?;
        for key in keys {
            // A preceding native purge can recursively settle another family.
            // Reload here instead of overwriting that progress with a snapshot.
            let Some(mut accepted) = ERASES.get(&self.store, txn, &key)? else {
                continue;
            };
            let attempt = AttemptId::from_bytes(&key)?;
            cancelled.extend(settle_in_txn(self, txn, attempt, &mut accepted, None)?);
            ERASES.put(&self.store, txn, &key, &accepted)?;
        }
        Ok(cancelled)
    }

    pub(in crate::deletion) fn byoa_exhaust_erases_owed_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        sources: &[EntityId],
    ) -> Result<bool> {
        for row in ERASES.iter_from(&self.store, txn, &[])? {
            let (_, accepted) = row?;
            if sources
                .iter()
                .any(|source| accepted.sources.contains(source))
                && !finished_in_txn(self, txn, &accepted)?
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn finished_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    accepted: &AcceptedExhaustErase,
) -> Result<bool> {
    if accepted.capture.is_none()
        || accepted.teardown != Teardown::Purged
        || !accepted.hash_inventory_complete
        || accepted.hashes.is_empty()
        || !accepted.hashes.is_subset(&accepted.covered_hashes)
    {
        return Ok(false);
    }
    let names: Vec<String> = accepted.retirements.iter().cloned().collect();
    #[cfg(unix)]
    if !vault
        .store
        .erase_retirement_names_cover_body_instances(&names, &accepted.expected_instances)?
    {
        return Ok(false);
    }
    #[cfg(not(unix))]
    return Ok(false);
    #[cfg(unix)]
    vault.store.erase_custody_retired_in_txn(txn, &names)
}

fn settle_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    accepted: &mut AcceptedExhaustErase,
    act: Option<&EraseOwnerAct<'_>>,
) -> Result<Vec<(AttemptId, u32)>> {
    let mut cancelled = Vec::new();
    if accepted.capture.is_none() {
        match canonical_capture_in_txn(&vault.store, txn, attempt) {
            Ok(capture) => accepted.capture = capture,
            Err(_) => {
                // An unreadable fact cannot select a generic attached result.
                return Ok(cancelled);
            }
        }
    }
    let Some(capture) = accepted.capture.as_ref() else {
        return Ok(cancelled);
    };
    let artifact = capture.artifact();
    let canonical_hash = capture.content_hash();
    let raw = vault.store.port_entity_raw(txn, &artifact)?;
    if let Some(raw) = raw {
        let Some(header) = EntityMetadataHeader::parse(&raw)
            .filter(|header| header.entity_type == crate::registry::ENTITY_TYPE_BLOB_ARTIFACT)
        else {
            return Ok(cancelled);
        };
        // Even a previously torn-down family is purged again when an image
        // restores its metadata. Its independent inventory and names remain.
        accepted.teardown = Teardown::Pending;
        let active = ACTIVE_PURGES.get(&vault.store, txn, &artifact)?;
        let inventory = match active.and_then(|active| active.inventory) {
            Some(inventory) => inventory,
            None => capture_inventory_in_txn(vault, txn, &artifact, &raw)?,
        };
        let ArtifactInventory {
            hashes,
            covered_hashes,
            expected_instances,
            inline_assets,
            complete,
        } = inventory;
        accepted.hash_inventory_complete = complete
            && (hashes.contains(&canonical_hash) || accepted.hashes.contains(&canonical_hash));
        accepted.hashes.extend(hashes.iter().copied());
        accepted.covered_hashes.extend(covered_hashes);
        accepted.expected_instances.extend(expected_instances);
        if crate::blob_artifact::artifact_payload_held_in_txn(
            &vault.store,
            txn,
            &artifact,
            &hashes,
        )? || !purge_guards_allow_in_txn(vault, txn, &artifact)
        {
            return Ok(cancelled);
        }
        #[cfg(unix)]
        for source in &accepted.sources {
            crate::store::erase_bodies_for_owner_in_txn(
                &vault.store,
                txn,
                source,
                &artifact,
                &hashes,
                true,
            )?;
            // An INLINE note needs its real raw ASSET descriptor. Missing
            // descriptors never enter this list or the zero-digest fallback.
            for asset in &inline_assets {
                crate::store::erase_bodies_for_owner_in_txn(
                    &vault.store,
                    txn,
                    source,
                    asset,
                    &[],
                    true,
                )?;
            }
        }
        // All source notes and independent inventory are in the SAME writer
        // before the native purge releases even its first reference.
        ERASES.put(&vault.store, txn, attempt.as_bytes(), accepted)?;
        if ACTIVE_PURGES.contains(&vault.store, txn, &artifact)? {
            // The native finishing hook records this teardown after its last
            // destructive hook. Keep the original caller's marker order.
            return Ok(cancelled);
        }
        super::stage_engine_row_hard_erasure_at_in_txn(
            &vault.store,
            txn,
            &artifact,
            super::window_label_from_timestamp(header.learned_at),
            &super::TombstoneValueV2 {
                reason: super::TombstoneReason::UserHardDelete,
                deleted_at: vault.store.clock.now_recorded_at(),
                request_id: *artifact.as_bytes(),
            },
        )?;
        // The native full purge already calls the artifact lifecycle. Never
        // invoke that lifecycle a second time or use its marker-last tear.
        let (_, _, purged_cancelled) =
            match vault.purge_entity_active_store_in_txn(txn, &artifact, None, true, act) {
                Ok(purged) => purged,
                Err(error) => {
                    // Includes a guard or begin-context error before the native
                    // body's matching cleanup has started.
                    end_native_purge_in_txn(vault, txn, &artifact)?;
                    return Err(error);
                }
            };
        cancelled.extend(purged_cancelled);
        accepted.teardown = Teardown::Purged;
        if let Some(joined) = ERASES.get(&vault.store, txn, attempt.as_bytes())? {
            accepted.sources.extend(joined.sources);
        }
    }
    // Missing metadata only preserves an actual earlier teardown. It never
    // establishes a new one or replaces names with an empty later binding.
    bind_names_in_txn(vault, txn, accepted)?;
    Ok(cancelled)
}

fn capture_inventory_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    artifact: &EntityId,
    raw: &[u8],
) -> Result<ArtifactInventory> {
    let hashes =
        crate::blob_artifact::held_content_hashes_in_txn(&vault.store, txn, artifact, raw)?;
    let mut inventory = ArtifactInventory {
        hashes,
        complete: true,
        ..Default::default()
    };
    for hash in &inventory.hashes {
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(hash)?;
        let Some(raw) = vault.store.port_entity_raw(txn, &asset)? else {
            continue;
        };
        let actual = crate::blob_artifact::carrier_content_hash(&vault.store, txn, &asset, &raw);
        if !matches!(actual, Ok(Some(actual)) if actual == *hash) {
            continue;
        }
        inventory.covered_hashes.insert(*hash);
        #[cfg(unix)]
        if crate::store::asset_file_in_txn(
            &vault.store,
            txn,
            &asset,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        )?
        .is_none()
        {
            inventory.inline_assets.push(asset);
        }
    }
    #[cfg(unix)]
    match crate::store::governed_body_instances_in_txn(
        &vault.store,
        txn,
        &inventory.hashes,
        &inventory.inline_assets,
    ) {
        Ok(instances) => inventory.expected_instances = instances,
        Err(_) => inventory.complete = false,
    }
    Ok(inventory)
}

fn bind_names_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    accepted: &mut AcceptedExhaustErase,
) -> Result<()> {
    #[cfg(unix)]
    {
        let sources: Vec<EntityId> = accepted.sources.iter().copied().collect();
        accepted
            .retirements
            .extend(vault.store.body_erase_retirement_names_in_txn(
                txn,
                &sources,
                &accepted.expected_instances,
            )?);
    }
    Ok(())
}

/// Preflight the original purge's native protections before its hard marker
/// is staged. An unavailable/protected family remains owed; the accepted
/// source erase is not converted into a refusal. The purge repeats them in
/// the same writer and owns every destructive hook.
fn purge_guards_allow_in_txn(vault: &Vault, txn: &heed::RwTxn<'_>, artifact: &EntityId) -> bool {
    let check = || -> Result<()> {
        vault
            .store
            .reject_legal_hold_in_txn(txn, artifact.as_bytes())?;
        crate::world_keys::reject_held_pad_world_in_txn(&vault.store, txn, &[*artifact])?;
        crate::store::base_agent::guard_actor_delete(artifact)?;
        crate::blob_artifact::esign::reject_event_delete(&vault.store, txn, artifact)?;
        vault
            .store
            .delete_guards
            .refuse_revision_delete(&vault.store, txn, artifact)?;
        crate::store::task_authority_guard::reject_fact_delete(&vault.store, txn, artifact)?;
        vault
            .store
            .delete_guards
            .reject_audience_edit_delete(&vault.store, txn, artifact)?;
        vault.guard_active_merge_hard_delete_in_txn(txn, artifact)?;
        Ok(())
    };
    check().is_ok()
}
