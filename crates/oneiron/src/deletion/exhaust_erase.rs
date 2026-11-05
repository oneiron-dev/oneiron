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

/// Purging exists only inside the owning write transaction: recursive
/// native actor sweeps join sources without purging the same artifact twice.
#[derive(Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum Teardown {
    #[default]
    Pending,
    Purging,
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

pub(crate) fn erase_owned_byoa_exhausts_in_txn(
    erase: &mut super::ActorErasureWriter<'_, '_>,
    owned: &ErasedByoaPayloads,
    act: Option<&EraseOwnerAct<'_>>,
) -> Result<()> {
    let (vault, txn, _) = erase.parts();
    accept_in_txn(vault, txn, owned, act)
}

pub(crate) fn erase_restored_byoa_exhausts_in_txn(
    restore: &mut crate::recovery::checkpoint::RestoreActorScrubWriter<'_, '_>,
    owned: &ErasedByoaPayloads,
) -> Result<()> {
    let (vault, txn, _) = restore.parts();
    accept_in_txn(vault, txn, owned, None)
}

fn accept_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    owned: &ErasedByoaPayloads,
    act: Option<&EraseOwnerAct<'_>>,
) -> Result<()> {
    for (attempt, sources) in owned.sources() {
        let mut accepted = ERASES
            .get(&vault.store, txn, attempt.as_bytes())?
            .unwrap_or_default();
        accepted.sources.extend(sources.iter().copied());
        settle_in_txn(vault, txn, *attempt, &mut accepted, act)?;
        ERASES.put(&vault.store, txn, attempt.as_bytes(), &accepted)?;
    }
    Ok(())
}

impl Vault {
    /// Replays only private persisted accepted continuations. A marker alone
    /// never creates an artifact selection or a new erase operation.
    pub(in crate::deletion) fn settle_owed_byoa_exhaust_erases_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
    ) -> Result<()> {
        let mut rows = Vec::new();
        for row in ERASES.iter_from(&self.store, txn, &[])? {
            rows.push(row?);
        }
        for (key, mut accepted) in rows {
            let attempt = AttemptId::from_bytes(&key)?;
            settle_in_txn(self, txn, attempt, &mut accepted, None)?;
            ERASES.put(&self.store, txn, &key, &accepted)?;
        }
        Ok(())
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
) -> Result<()> {
    if accepted.teardown == Teardown::Purging {
        return Ok(());
    }
    if accepted.capture.is_none() {
        match canonical_capture_in_txn(&vault.store, txn, attempt) {
            Ok(capture) => accepted.capture = capture,
            Err(_) => {
                // An unreadable fact cannot select a generic attached result.
                return Ok(());
            }
        }
    }
    let Some(capture) = accepted.capture.as_ref() else {
        return Ok(());
    };
    let artifact = capture.artifact();
    let canonical_hash = capture.content_hash();
    let raw = vault.store.port_entity_raw(txn, &artifact)?;
    if let Some(raw) = raw {
        let Some(header) = EntityMetadataHeader::parse(&raw)
            .filter(|header| header.entity_type == crate::registry::ENTITY_TYPE_BLOB_ARTIFACT)
        else {
            return Ok(());
        };
        // Even a previously torn-down family is purged again when an image
        // restores its metadata. Its independent inventory and names remain.
        accepted.teardown = Teardown::Pending;
        let hashes =
            crate::blob_artifact::held_content_hashes_in_txn(&vault.store, txn, &artifact, &raw)?;
        accepted.hash_inventory_complete |= hashes.contains(&canonical_hash);
        accepted.hashes.extend(hashes.iter().copied());
        let mut inline_assets = Vec::new();
        for hash in &hashes {
            let asset = crate::blob_artifact::blob_artifact_asset_entity_id(hash)?;
            let Some(raw) = vault.store.port_entity_raw(txn, &asset)? else {
                continue;
            };
            // These are the native descriptor's exact bytes, not artifact
            // names, result_ref strings, or digests guessed from missing rows.
            let actual =
                crate::blob_artifact::carrier_content_hash(&vault.store, txn, &asset, &raw);
            if !matches!(actual, Ok(Some(actual)) if actual == *hash) {
                continue;
            }
            accepted.covered_hashes.insert(*hash);
            #[cfg(unix)]
            if crate::store::asset_file_in_txn(
                &vault.store,
                txn,
                &asset,
                &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            )?
            .is_none()
            {
                inline_assets.push(asset);
            }
        }
        #[cfg(unix)]
        accepted
            .expected_instances
            .extend(crate::store::governed_body_instances_in_txn(
                &vault.store,
                txn,
                &hashes,
                &inline_assets,
            )?);
        if crate::blob_artifact::artifact_payload_held_in_txn(
            &vault.store,
            txn,
            &artifact,
            &hashes,
        )? || !purge_guards_allow_in_txn(vault, txn, &artifact)
        {
            return Ok(());
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
        accepted.teardown = Teardown::Purging;
        ERASES.put(&vault.store, txn, attempt.as_bytes(), accepted)?;
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
        vault.purge_entity_active_store_in_txn(txn, &artifact, None, true, act)?;
        accepted.teardown = Teardown::Purged;
        if let Some(joined) = ERASES.get(&vault.store, txn, attempt.as_bytes())? {
            accepted.sources.extend(joined.sources);
        }
    }
    // Missing metadata only preserves an actual earlier teardown. It never
    // establishes a new one or replaces names with an empty later binding.
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
