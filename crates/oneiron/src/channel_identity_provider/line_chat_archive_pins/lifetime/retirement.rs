//! The independent instance inventory and native completion proof of a
//! captured version erase, retained until its actual keys are retired.

use std::collections::BTreeSet;

use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize};

use super::{ArchiveRelease, RELEASES};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::EntityStoreRead as _;
use crate::store::Store;

#[derive(Serialize, Deserialize)]
pub(super) struct ReleaseInventory {
    digests: Vec<[u8; 32]>,
    inline: Option<[u8; 16]>,
    expected: BTreeSet<[u8; 16]>,
    retirements: BTreeSet<String>,
}

/// Captures before any version or carrier releases a reference. Missing
/// metadata after an earlier teardown never invents a completed inventory.
pub(super) fn capture_in_txn(
    store: &Store,
    txn: &mut RwTxn<'_>,
    release: &mut ArchiveRelease,
) -> Result<()> {
    if !release.erase || !release.owns_version() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&release.pin.content_hash)?;
        if super::exact_version_stands(store, txn, &release.pin)? {
            let mut digests: Vec<_> =
                crate::provenance::body::owned_bodies_in_txn(store, txn, &asset)?
                    .iter()
                    .filter_map(|body| body.state.held().map(|held| held.blake3))
                    .collect();
            // Also cover earlier file instances of this immutable content,
            // including a file-to-inline switch before the observation erase.
            digests.push(release.pin.content_hash);
            digests.sort_unstable();
            digests.dedup();
            let inline = crate::store::INLINE_ASSETS.get(store, txn, &asset)?;
            let expected =
                crate::store::governed_body_instances_in_txn(store, txn, &digests, &[asset])?;
            match release.inventory.as_mut() {
                Some(inventory) => {
                    inventory.digests.extend(digests);
                    inventory.digests.sort_unstable();
                    inventory.digests.dedup();
                    inventory.expected.extend(expected);
                    inventory.inline = inline;
                }
                None => {
                    release.inventory = Some(ReleaseInventory {
                        digests,
                        inline,
                        expected,
                        retirements: BTreeSet::new(),
                    });
                }
            }
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
    if release.erase && super::exact_version_stands(store, txn, &release.pin)? {
        let asset = crate::blob_artifact::blob_artifact_asset_entity_id(&release.pin.content_hash)?;
        let Some(inventory) = release.inventory.as_ref() else {
            return Ok(());
        };
        let retained = store.port_entity_raw(txn, &asset)?.is_some_and(|raw| {
            raw.len() > crate::batch::ENTITY_METADATA_HEADER_LEN
                && raw[0] == crate::registry::ENTITY_TYPE_ASSET
        });
        for source in release.sources.keys() {
            crate::store::erase_bodies_for_owner_in_txn(
                store,
                txn,
                source,
                &asset,
                &inventory.digests,
                retained,
            )?;
            crate::store::note_settled_inline_in_txn(store, txn, source, &asset, inventory.inline)?;
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
        inventory
            .retirements
            .extend(store.body_erase_retirement_names_in_txn(
                txn,
                &sources,
                &inventory.expected,
            )?);
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
    if inventory.expected.is_empty() {
        return Ok(true);
    }
    let names: Vec<_> = inventory.retirements.iter().cloned().collect();
    Ok(
        store.erase_retirement_names_cover_body_instances(&names, &inventory.expected)?
            && store.erase_custody_retired_in_txn(txn, &names)?,
    )
}
