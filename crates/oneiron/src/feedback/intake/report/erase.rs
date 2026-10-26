//! A report cluster's members and their erase (FIX 9856). A cluster keeps a
//! copy of each member ISSUE's vector and a centroid made from them, keyed
//! by its first ISSUE, the root. An ISSUE's hard erase (its permanent
//! hard-delete marker, or the physical deindex of its row) removes its
//! vector from every cluster and remakes each centroid from the members
//! left; a cluster whose root is erased goes whole, since intake reads a
//! cluster only through its root, and its other ISSUEs stay as they are.
//! An ordinary delete keeps every cluster, so a soft delete stays
//! restorable: intake reads past a deleted member, counting it nowhere,
//! until it is restored.
//!
//! A checkpoint image carries each cluster row whole, owned by every member
//! it names, so any member's erase retires every image's copy.

use crate::ports::{DeletionMarker, DependentWalkDoor, TombstoneStoreRead};
use crate::store::{ResponseCarriage, ResponseScan, Store};
use crate::{EntityId, Error, Result, Vault};

use super::super::normalized;
use super::{CLUSTERS, ReportCluster};

/// Forgets `id` in every report cluster, in the caller's transaction, once
/// its erase is hard: a physical deindex (`door` is the purge), or its
/// permanent hard-delete marker stands. Any other door keeps every cluster
/// as it is. The table is scanned whole; a row that does not decode is
/// left as it is.
pub(crate) fn forget_report_cluster_member_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    door: DependentWalkDoor,
) -> Result<()> {
    if door != DependentWalkDoor::Purge && !hard_erased_in_txn(store, txn, id)? {
        return Ok(());
    }
    forget_member_in_txn(store, txn, id)
}

/// [`forget_report_cluster_member_in_txn`] as the cluster table's actor
/// scrub (FIX 3520): it runs on every delete, so only the hard-delete
/// marker forgets.
pub(crate) fn forget_report_cluster_source_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    if !hard_erased_in_txn(&vault.store, txn, id)? {
        return Ok(());
    }
    forget_member_in_txn(&vault.store, txn, id)
}

/// Whether `id`'s permanent hard-delete marker stands in `txn`.
fn hard_erased_in_txn(store: &Store, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<bool> {
    store.port_deletion_marked(txn, DeletionMarker::HardDelete, id)
}

/// Removes `id` from every cluster: the cluster it roots goes whole, an
/// emptied one goes, and every other it was in is remade from the members
/// left. One whose members no longer agree on their dimensions cannot be
/// remade and is unusable to intake: it goes whole too, so the erase
/// always lands.
fn forget_member_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    let member = id.to_hex();
    let mut dropped = Vec::new();
    let mut remade = Vec::new();
    for row in CLUSTERS.iter_from(store, &*txn, &[])? {
        let Ok((root, mut cluster)) = row else {
            continue;
        };
        if root == *id {
            dropped.push(root);
            continue;
        }
        if cluster.members.remove(&member).is_none() {
            continue;
        }
        if cluster.members.is_empty() {
            dropped.push(root);
        } else {
            remade.push((root, cluster));
        }
    }
    for root in dropped {
        CLUSTERS.delete(store, txn, &root)?;
    }
    for (root, mut cluster) in remade {
        if recompute_centroid(&mut cluster).is_ok() {
            CLUSTERS.put(store, txn, &root, &cluster)?;
        } else {
            CLUSTERS.delete(store, txn, &root)?;
        }
    }
    Ok(())
}

/// Whether an incoming ISSUE's id is already erased or deleted, as its
/// deletion markers say in `txn`: a stale ingestion clusters nothing. A
/// fresh ISSUE is not stored yet when it is clustered, so only its markers
/// are read, never its row.
pub(super) fn incoming_erased_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(hard_erased_in_txn(store, txn, id)? || store.port_deletion_state(txn, id)?.deleted)
}

/// How intake may read one member now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Standing {
    /// Stored, neither deleted nor archived: it counts.
    Live,
    /// Deleted or archived, but restorable: it stays in its cluster,
    /// counted nowhere, and counts again once restored.
    Restorable,
    /// Hard-erased, or no longer stored: it leaves its cluster.
    Gone,
}

/// Where the stored ISSUE `id` stands in `txn`.
fn standing_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, id: &EntityId) -> Result<Standing> {
    if hard_erased_in_txn(&vault.store, txn, id)?
        || vault.get_entity_type_in_txn(txn, id)?.is_none()
    {
        return Ok(Standing::Gone);
    }
    let state = vault.store.port_deletion_state(txn, id)?;
    Ok(if state.deleted || state.archived {
        Standing::Restorable
    } else {
        Standing::Live
    })
}

/// Reads `cluster` as intake may use it now, in `txn`: a member hard-erased
/// or no longer stored leaves it (its erase's own write removes it too); a
/// member deleted or archived but restorable stays, counted nowhere, so it
/// rejoins once restored. The centroid is remade from the members that
/// count, `incoming` (the ISSUE being clustered, not stored yet) among
/// them. A member whose key names no id counts as it did. `false` when none
/// counts, or those that count disagree on their dimensions: intake reads
/// the cluster past then.
pub(super) fn remake_live_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    cluster: &mut ReportCluster,
    incoming: Option<&str>,
) -> Result<bool> {
    let mut gone = Vec::new();
    let mut counted = Vec::new();
    for member in cluster.members.keys() {
        let standing = if incoming == Some(member.as_str()) {
            Standing::Live
        } else if let Ok(id) = EntityId::from_hex(member) {
            standing_in_txn(vault, txn, &id)?
        } else {
            Standing::Live
        };
        match standing {
            Standing::Live => counted.push(member.clone()),
            Standing::Restorable => {}
            Standing::Gone => gone.push(member.clone()),
        }
    }
    for member in &gone {
        cluster.members.remove(member);
    }
    let vectors: Vec<&[f32]> = counted
        .iter()
        .filter_map(|member| cluster.members.get(member))
        .map(Vec::as_slice)
        .collect();
    let Ok(Some(centroid)) = centroid_of(&vectors) else {
        return Ok(false);
    };
    cluster.centroid = centroid;
    Ok(true)
}

/// Remakes `cluster`'s centroid from every member it keeps, as a hard
/// erase leaves it; intake remakes it from the members that count before
/// it reads it ([`remake_live_in_txn`]).
///
/// # Errors
/// Members of more than one dimension.
fn recompute_centroid(cluster: &mut ReportCluster) -> Result<()> {
    let vectors: Vec<&[f32]> = cluster.members.values().map(Vec::as_slice).collect();
    if let Some(centroid) = centroid_of(&vectors)? {
        cluster.centroid = centroid;
    }
    Ok(())
}

/// The normalized sum of `vectors`; `None` for none.
///
/// # Errors
/// Vectors of more than one dimension.
fn centroid_of(vectors: &[&[f32]]) -> Result<Option<Vec<f32>>> {
    let Some(first) = vectors.first() else {
        return Ok(None);
    };
    let mut centroid = vec![0.0; first.len()];
    for vector in vectors {
        if vector.len() != centroid.len() {
            return Err(Error::CorruptedIndex("report cluster dimensions"));
        }
        for (sum, value) in centroid.iter_mut().zip(vector.iter()) {
            *sum += value;
        }
    }
    normalized(&centroid).map(Some)
}

/// What a checkpoint carries of the cluster row `value`: the whole row, and
/// nothing once retired (its retirement drops the row, in images and live
/// alike). A row that does not decode is carried whole as an opaque
/// response.
pub(crate) fn report_cluster_carriage(value: &[u8]) -> ResponseScan {
    if CLUSTERS.decode_value(value).is_err() {
        return ResponseScan::opaque_row();
    }
    ResponseScan::Decoded(ResponseCarriage {
        keep: 0,
        stub: Vec::new(),
        retired: 0,
    })
}

/// Who owns the cluster row `value`: every member ISSUE whose vector it
/// copied, so any one's erase retires every image's copy; none for a row
/// that does not decode.
pub(crate) fn report_cluster_owners(value: &[u8]) -> Vec<EntityId> {
    CLUSTERS
        .decode_value(value)
        .map(|cluster| {
            cluster
                .members
                .keys()
                .filter_map(|member| EntityId::from_hex(member).ok())
                .collect()
        })
        .unwrap_or_default()
}
