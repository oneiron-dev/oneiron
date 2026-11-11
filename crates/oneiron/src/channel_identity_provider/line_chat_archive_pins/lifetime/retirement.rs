//! The independent instance inventory and native completion proof of a
//! captured version erase, retained until its actual keys are retired.

use std::collections::{BTreeMap, BTreeSet};

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{ArchiveRelease, RELEASES};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

#[derive(Serialize, Deserialize)]
pub(super) struct ReleaseInventory {
    digests: BTreeMap<[u8; 32], BTreeSet<[u8; 16]>>,
    inline: BTreeSet<[u8; 16]>,
    retirements: BTreeSet<String>,
}

/// Captures before any version or carrier releases a reference. Missing
/// metadata after an earlier teardown never invents a completed inventory.
pub(super) fn capture_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    release: &mut ArchiveRelease,
) -> Result<()> {
    if !release.erase || !release.owns_version() || release.released {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let Some(pin) = release.pin.as_ref() else {
            return Ok(());
        };
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&pin.content_hash)?;
        if super::exact_version_stands(store, txn, pin)? {
            let mut digests: Vec<_> =
                crate::provenance::body::owned_bodies_in_txn(store, txn, &asset)?
                    .iter()
                    .filter_map(|body| body.state.held().map(|held| held.blake3))
                    .collect();
            // Also cover earlier file instances of this immutable content,
            // including a file-to-inline switch before the observation erase.
            digests.push(pin.content_hash);
            digests.sort_unstable();
            digests.dedup();
            let inline = crate::store::INLINE_ASSETS.get(store, txn, &asset)?;
            let digests = store.body_instance_bindings_in_txn(txn, &digests)?;
            let inventory = release.inventory.get_or_insert_with(|| ReleaseInventory {
                digests: BTreeMap::new(),
                inline: BTreeSet::new(),
                retirements: BTreeSet::new(),
            });
            for (digest, instances) in digests {
                inventory
                    .digests
                    .entry(digest)
                    .or_default()
                    .extend(instances);
            }
            inventory.inline.extend(inline);
        }
    }
    #[cfg(not(unix))]
    let _ = (store, txn);
    Ok(())
}

/// Notes the accepted sources only once holds and version consumers permit
/// the actual release. Inventory capture alone never retires a held copy.
pub(super) fn note_sources_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    release: &ArchiveRelease,
) -> Result<()> {
    #[cfg(unix)]
    if release.erase && release.owns_version() {
        let (Some(pin), Some(inventory)) = (release.pin.as_ref(), release.inventory.as_ref())
        else {
            return Ok(());
        };
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&pin.content_hash)?;
        for source in release.sources.keys() {
            for (digest, instances) in &inventory.digests {
                store.erase_captured_body_instances_in_txn(txn, source, digest, instances)?;
            }
            for instance in &inventory.inline {
                store.erase_captured_inline_asset_in_txn(
                    txn,
                    source,
                    &asset,
                    instance,
                    &pin.content_hash,
                )?;
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (store, txn, release);
    Ok(())
}

/// Once the version went, keep the LIVE obligation until the real native
/// retirement names cover the independent inventory and have completed.
pub(super) fn finish_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    claim: &EntityId,
    mut release: ArchiveRelease,
) -> Result<()> {
    if !release.erase || !release.owns_version() {
        RELEASES.delete(store, txn, claim)?;
        return Ok(());
    }
    // Never re-read or mark a later same-hash carrier after this version
    // released. Only the independently captured original instances count.
    #[cfg(unix)]
    if let Some(inventory) = release.inventory.as_mut() {
        let sources: Vec<_> = release.sources.keys().copied().collect();
        let expected = inventory.expected_instances();
        inventory
            .retirements
            .extend(store.body_erase_retirement_names_in_txn(txn, &sources, &expected)?);
        if inventory_complete_in_txn(store, txn, inventory)? {
            RELEASES.delete(store, txn, claim)?;
            return Ok(());
        }
    }
    RELEASES.put(store, txn, claim, &release)
}

#[cfg(unix)]
fn inventory_complete_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    inventory: &ReleaseInventory,
) -> Result<bool> {
    // No governed instance existed at the independently observed teardown.
    let expected = inventory.expected_instances();
    if expected.is_empty() {
        return Ok(true);
    }
    let names: Vec<_> = inventory.retirements.iter().cloned().collect();
    Ok(
        store.erase_retirement_names_cover_body_instances(&names, &expected)?
            && store.erase_custody_retired_in_txn(txn, &names)?,
    )
}

impl ReleaseInventory {
    fn expected_instances(&self) -> BTreeSet<[u8; 16]> {
        self.digests
            .values()
            .flat_map(|instances| instances.iter())
            .chain(self.inline.iter())
            .copied()
            .collect()
    }
}
