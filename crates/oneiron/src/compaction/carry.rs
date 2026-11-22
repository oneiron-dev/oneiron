//! The working set an epoch SUMMARY carries (CROSS-ARCH-0011 amendment
//! "workingSet"; CROSS-ARCH-0002b #ep-6-2-3 `packetId`). The epoch summary
//! is the stored compaction packet (CROSS-ARCH-0011 "Unification": one event,
//! two faces), so the host's working set lands on it as `carries` edges, its
//! carried-over manifest, in the mint's own transaction. A context pack that
//! rehydrates from the summary reads them back as its working set while the
//! summary is its lineage's newest live epoch.

use heed::{RoTxn, RwTxn};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EdgeValueFields};
use crate::context_pack::MAX_WORKING_SET_REFS;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{EdgeDirection, EdgeStoreRead, EntityStoreRead, TombstoneStoreRead};
use crate::store::Store;
use crate::vault::Vault;

use super::epoch::prior_epoch_in_txn;
use super::stored_epoch::{StoredEpoch, stored_epoch_in};
use super::withdrawn::{WithdrawnKeyframe, stored_keyframe};

/// How much lower each carried row's weight is than the row before it. The
/// first row weighs 1.0; at most [`MAX_WORKING_SET_REFS`] rows are carried,
/// so the last weighs 1/64, inside the edge weight range, and every step is
/// exact in `f32`. The weights are the carried order: an owner's later
/// weight rewrite on a `carries` edge reorders what a pack seeds.
const CARRY_WEIGHT_STEP: f32 = 1.0 / 64.0;

const _: () = assert!(MAX_WORKING_SET_REFS == 64);

/// Writes `summary ─carries→ row` for each of `refs` (deduplicated, at most
/// [`MAX_WORKING_SET_REFS`]) that is stored, not erased and not withdrawn in
/// `wtxn`, the first highest. A missing, erased or withdrawn ref is passed
/// by, as a pack drops it. Returns how many rows the summary carries.
///
/// The `host.compact` caller is the owner, so only liveness is checked here;
/// whether a reader may read a carried row is judged when a pack rehydrates,
/// against that reader's lane.
pub(super) fn carry_working_set_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    summary: &EntityId,
    refs: &[EntityId],
) -> Result<u32> {
    let created_at = crate::ports::recorded_at_in_txn(&vault.store, wtxn)?;
    let mut batch = vault.batch_in();
    let mut carried = 0_u32;
    let mut weight = 1.0_f32;
    for row in refs {
        let deletion = TombstoneStoreRead::port_deletion_state(&vault.store, wtxn, row)?;
        if deletion.deleted
            || deletion.stale
            || EntityStoreRead::port_entity_raw(&vault.store, wtxn, row)?.is_none()
        {
            continue;
        }
        // The kind's creation is the mint's alone: the internal write lands
        // it with neutral VAD, no flags and the transaction's clock.
        batch = batch.edge_with_value_fields(
            summary,
            EdgeKind::Carries,
            row,
            EdgeValueFields {
                weight,
                created_at,
                vad: oneiron_contracts::affect::Vad::NEUTRAL,
                provenance: None,
            },
        );
        carried += 1;
        weight -= CARRY_WEIGHT_STEP;
    }
    if carried > 0 {
        batch.apply(wtxn)?;
    }
    Ok(carried)
}

/// The rows the epoch SUMMARY `summary` carries, first first, while it is a
/// live epoch summary and the newest epoch of its lineage. `None` is a stale
/// packet: no epoch summary, a withdrawn one, one a later epoch of its
/// lineage (or that epoch's floor) has passed, or one carrying more than
/// [`MAX_WORKING_SET_REFS`] rows, which no mint writes (only a peer's
/// received edges can). The caller judges whether its reader may read the
/// summary and each row.
pub(crate) fn carried_rows_in(
    store: &Store,
    rtxn: &RoTxn<'_>,
    summary: &EntityId,
) -> Result<Option<Vec<EntityId>>> {
    let Some(envelope) = EntityStoreRead::port_entity_raw(store, rtxn, summary)? else {
        return Ok(None);
    };
    let Some(keyframe) = stored_keyframe(&envelope) else {
        return Ok(None);
    };
    let body = &envelope[ENTITY_METADATA_HEADER_LEN..];
    // A withdrawn epoch keeps only its keyframe: its words, and what they
    // carried, are gone.
    if WithdrawnKeyframe::decode(body).is_ok()
        || stored_epoch_in(store, rtxn, summary, body)? != StoredEpoch::Yes
    {
        return Ok(None);
    }
    if prior_epoch_in_txn(store, rtxn, &keyframe.scope())?
        .is_some_and(|newest| newest.epoch() > keyframe.epoch)
    {
        return Ok(None);
    }
    let mut carried = Vec::new();
    for edge in EdgeStoreRead::port_edges(
        store,
        rtxn,
        summary,
        EdgeDirection::Out,
        Some(EdgeKind::Carries),
        None,
    )? {
        let edge = edge?;
        carried.push((edge.weight, edge.target));
    }
    if carried.len() > MAX_WORKING_SET_REFS {
        return Ok(None);
    }
    carried.sort_by(|left, right| right.0.total_cmp(&left.0).then(left.1.cmp(&right.1)));
    Ok(Some(carried.into_iter().map(|(_, row)| row).collect()))
}

/// Whether `summary` is stored as an epoch SUMMARY in `rtxn`, live,
/// withdrawn or with its text on the document plane: the one row a `carries`
/// edge leaves. A whole-vault import restores an archived carried manifest
/// only from one.
pub(crate) fn is_epoch_summary_in(
    store: &Store,
    rtxn: &RoTxn<'_>,
    summary: &EntityId,
) -> Result<bool> {
    Ok(EntityStoreRead::port_entity_raw(store, rtxn, summary)?
        .is_some_and(|envelope| stored_keyframe(&envelope).is_some()))
}
