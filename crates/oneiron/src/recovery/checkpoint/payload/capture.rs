//! KS7-5 capture: the snapshot's rows placed in its own read transaction
//! ([`project_image`]), then, once that read closes, sealed
//! ([`seal_image`]): each owner's compartment minted or read in one write
//! under the custody read guard the snapshot holds, each bundle sealed under
//! it, and every row a compartment holds taken out of the image. While
//! [`CHECKPOINT_PAYLOADS_ENABLED`] is off nothing here reads, mints or seals
//! anything, and the artifact is written with no payload, as before.

use std::collections::{BTreeMap, BTreeSet};

use heed::RoTxn;

#[cfg(not(feature = "sync"))]
use super::Deferred;
#[cfg(feature = "sync")]
use super::SyncCarriers;
use super::{
    Compartment, ImageFilter, PayloadStreams, Projected, Projection, db_name, project, structure,
};
use crate::Vault;
use crate::error::Result;
use crate::recovery::checkpoint::CanonicalRows;
use crate::store::checkpoint_payload::CHECKPOINT_PAYLOADS_ENABLED;
use crate::store::checkpoint_payload::rows::OwnerRef;

/// What a capture hands its artifact once its rows are sealed: the
/// payload's section and streams.
pub(in crate::recovery::checkpoint) struct CapturedPayload {
    pub(in crate::recovery::checkpoint) streams: PayloadStreams,
}

/// Where the rows of the image `txn` reads go (KS7-2b), through `filter`,
/// the snapshot's own: `None` while CHECKPOINT_PAYLOADS_ENABLED is off,
/// before anything is read. A masked repo copy's rows go under its source
/// (FIX 7608); a read of the aliases that fails leaves today's placement.
pub(in crate::recovery::checkpoint) fn project_image(
    vault: &Vault,
    txn: &RoTxn<'_>,
    filter: &ImageFilter,
) -> Result<Option<Projected>> {
    if !CHECKPOINT_PAYLOADS_ENABLED {
        return Ok(None);
    }
    #[cfg(feature = "sync")]
    let carriers = SyncCarriers::new(&vault.store).with_copy_aliases(
        crate::sync::selector::RepoCopyAliases::read_in_txn(vault, txn).unwrap_or_default(),
    );
    #[cfg(not(feature = "sync"))]
    let carriers = Deferred;
    Ok(match project(&vault.store, txn, filter, &carriers)? {
        Projection::Unchanged => None,
        Projection::Projected(projected) => Some(projected),
    })
}

/// Seals `projected` for `vault` (KS7-5) and takes every row a compartment
/// holds out of `databases`, the image's rows. Each whole structure row a
/// getter keeps that the image does not hold (the ledger's unavailable
/// calls, FIX 6260) goes in, as `filter` takes it, so it outlives its owner.
/// An owner erased since the read has no compartment: its rows leave the
/// image unsealed, and every row holding an id link to it goes with them
/// (FIX 6376). `None` for an archived vault, whose image is taken whole.
///
/// # Errors
///
/// Custody, storage and sealing faults.
pub(in crate::recovery::checkpoint) fn seal_image(
    vault: &Vault,
    projected: &Projected,
    filter: &ImageFilter,
    databases: &mut BTreeMap<String, CanonicalRows>,
) -> Result<Option<CapturedPayload>> {
    let owners = projected.owners();
    let Some(minted) = vault.store.checkpoint_payload_compartments(&owners)? else {
        return Ok(None);
    };
    let mut compartments = BTreeMap::new();
    for (instance, key) in minted {
        let owner = OwnerRef {
            subtype: instance.item.subtype(),
            owner32: *instance.item.owner(),
        };
        compartments.insert(
            owner,
            Compartment {
                item: instance.item,
                generation: instance.generation,
                key,
            },
        );
    }
    let streams = projected.seal(vault.vault_id().as_bytes(), &compartments)?;
    let mut sealed: BTreeMap<&'static str, BTreeSet<Vec<u8>>> = BTreeMap::new();
    for (db, key) in &projected.sealed {
        sealed.entry(db_name(*db)).or_default().insert(key.clone());
    }
    structure::strip(databases, &sealed);
    carry_structure(projected, filter, databases);
    let erased: BTreeSet<OwnerRef> = owners
        .into_iter()
        .filter(|owner| !compartments.contains_key(owner))
        .collect();
    if !erased.is_empty() {
        let getters = getter_links(projected);
        let links: Vec<&structure::Link> = projected.links.iter().chain(&getters).collect();
        let dependents = structure::dependents(&links, &erased);
        let dropped = structure::strip(databases, &dependents);
        tracing::info!(
            erased = erased.len(),
            dropped,
            "checkpoint payload owners erased since the snapshot's read left it, with the rows \
             that name them"
        );
    }
    if !projected.not_compartmented.is_empty() {
        tracing::warn!(
            families = ?projected.not_compartmented,
            "not compartmented: erase can't reach these families' rows in this checkpoint"
        );
    }
    Ok(Some(CapturedPayload { streams }))
}

/// Every whole structure row a getter keeps that holds an id link, with
/// the owners it links to: an edge's ends, a sync row's holders.
fn getter_links(projected: &Projected) -> Vec<structure::Link> {
    projected
        .captures
        .iter()
        .flat_map(|(_, captured)| &captured.structure)
        .filter(|row| row.at.path.is_empty() && !row.dependencies.is_empty())
        .map(|row| structure::Link {
            database: db_name(row.at.db),
            key: row.at.key.clone(),
            on: row.dependencies.clone(),
        })
        .collect()
}

/// Puts each whole structure row a getter keeps into `databases` where the
/// image does not hold it already, in key order, as `filter` takes it.
fn carry_structure(
    projected: &Projected,
    filter: &ImageFilter,
    databases: &mut BTreeMap<String, CanonicalRows>,
) {
    let rows = projected
        .captures
        .iter()
        .flat_map(|(_, captured)| &captured.structure)
        .filter(|row| row.at.path.is_empty());
    for row in rows {
        let database = db_name(row.at.db);
        if !filter.takes(database, &row.at.key, &row.value) {
            continue;
        }
        let Some(held) = databases.get_mut(database) else {
            continue;
        };
        if let Err(at) = held.binary_search_by(|(key, _)| key.as_slice().cmp(&row.at.key)) {
            held.insert(at, (row.at.key.clone(), row.value.clone()));
        }
    }
}
