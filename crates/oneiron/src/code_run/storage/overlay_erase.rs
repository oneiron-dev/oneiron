//! An actor's erase in the rooms that are live (FIX 7366): a room session's
//! code runs write their replay records, owner rows and wait memberships
//! into the room's overlay, where the vault's erase of their actor never
//! looks. Two parts reach them.
//!
//! - The fence ([`fence_overlay_replay_in_txn`]): a replay record a room's
//!   run puts in its overlay reads, in that writer, whether its owner row is
//!   erased or the actor it or its live run binding names is gone in the
//!   vault; if so it lands with its replies erased and its owner row erased,
//!   as the vault's own fence lands a base record. A write after the erase
//!   stays erased.
//! - The sweep ([`erase_gone_actors_in_live_overlays`]): once a delete's
//!   transaction commits, every live room's overlay rewrites what it already
//!   holds of a gone actor's runs: each such replay record takes its erased
//!   form, its owner row says Erased, each membership naming the actor says
//!   Erased and the delivery it holds takes its erased form. Only rows the
//!   overlay stages are touched; a base row is the vault's own erase's.
//!
//! The gone marker commits first, so from that commit every read of the
//! room's run already answers erased (`code_run_response_erased`, the wait
//! holder gate); the sweep is the cleanup of rows nothing reads any more.
//! A room that is closing, sealed or gone takes no segment and is left to
//! its close, which drops the overlay whole. The overlay's raw output
//! bytes stay until that close: an overlay raw put publishes no body
//! descriptor yet, so nothing maps a record's outputs to them.
//!
//! Lock order is the vault writer, then the overlay's segment permit, as a
//! routed write takes them. No session entry lock is taken.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::Arc;

use super::records::REPLAY_RECORDS;
use super::replay_bodies::erase_replies;
use super::replay_capsule::actor_gone_in_store;
use super::response_owners::{ResponseOwner, mark_response_erased_in_txn, response_owner_in_txn};
use super::wait_delivery::canonical_store;
use crate::code_run::CodeRunReplayRecord;
use crate::session_overlay::{OverlayKeyspace, SessionOverlay, SnapshotMergeRow};
use crate::side_table::{Erased, RoutedDbs, SideKey};
use crate::store::executor_wait_delivery::{DELIVERIES, HOLDERS, WaitHolder};
use crate::{EntityId, Result, Vault};

/// `record` as a room's run may put it along `dbs`, an overlay route, read
/// in that writer (FIX 7366): as given while its replies are kept, else its
/// erased form, its owner row then marked Erased. Its replies are erased
/// once its owner row says so, or once the actor that row, `stamped` (the
/// run and actor this writer stamped it for, which the writer's view does
/// not show yet) or its live run binding names is gone in the vault. The caller puts
/// what this returns: the view reads the snapshot before this writer's
/// own puts, so the record is fenced as supplied, never read back.
///
/// # Errors
///
/// Storage errors.
pub(super) fn fence_overlay_replay_in_txn<'r>(
    dbs: &RoutedDbs<'_>,
    txn: &mut heed::RwTxn<'_>,
    mut record: Cow<'r, CodeRunReplayRecord>,
    stamped: Option<(EntityId, EntityId)>,
) -> Result<Cow<'r, CodeRunReplayRecord>> {
    let base = canonical_store(dbs);
    let owner = response_owner_in_txn(dbs, txn, &record.run_id)?;
    let live = record.live_run.as_ref().map(|live| live.actor);
    let read: &heed::RoTxn<'_> = txn;
    let erased = owner.as_ref().is_some_and(ResponseOwner::erased)
        || owner
            .as_ref()
            .and_then(ResponseOwner::actor)
            .into_iter()
            .chain(stamped.map(|(_, actor)| actor))
            .chain(live)
            .any(|actor| actor_gone_in_store(base, read, &actor));
    if !erased {
        return Ok(record);
    }
    let run = owner.as_ref().map_or_else(
        || stamped.map_or(record.run_id, |(run, _)| run),
        |owner| owner.run,
    );
    erase_replies(record.to_mut())?;
    mark_response_erased_in_txn(dbs, txn, record.run_id, run)?;
    Ok(record)
}

/// Erases, in every live room's overlay, what it holds of the runs of each
/// actor in `ids` that is gone in the vault now (FIX 7366). Runs after the
/// delete of `ids` committed, holding no vault writer. An id that is no
/// actor, or an actor that is only archived, names nothing. A room whose
/// sweep fails is logged and the next one runs; its reads already answer
/// erased.
pub(crate) fn erase_gone_actors_in_live_overlays(vault: &Vault, ids: &[EntityId]) {
    if ids.is_empty() {
        return;
    }
    for overlay in vault.store.off_record_sessions.live_overlay_handles() {
        if let Err(error) = erase_in_overlay(vault, &overlay, ids) {
            tracing::warn!(
                kind = ?error.kind(),
                "a room's rows of an erased actor stay unreadable until the room closes"
            );
        }
    }
}

/// The keys of the rows `overlay` stages under `prefix`, as one snapshot
/// reads them; deletions over base are none of them. Under this thread's
/// installed segment the snapshot is that segment's view.
fn staged_keys(overlay: &Arc<SessionOverlay>, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
    let snapshot = overlay.snapshot()?;
    let plan = snapshot.merge_plan(OverlayKeyspace::VaultMeta, |key| key.starts_with(prefix));
    Ok(plan
        .rows
        .into_iter()
        .filter_map(|row| match row {
            SnapshotMergeRow::Single {
                key,
                value: Some(_),
            } => Some(key),
            _ => None,
        })
        .collect())
}

/// One room's sweep. The keys are read only once this writer holds the vault
/// writer and the overlay's segment permit: the permit waits for any room
/// write still publishing its segment, and the snapshot taken under it
/// shows that write, so no record of an in-flight put is missed.
fn erase_in_overlay(vault: &Vault, overlay: &Arc<SessionOverlay>, ids: &[EntityId]) -> Result<()> {
    let gone_in = |txn: &heed::RoTxn<'_>| -> BTreeSet<EntityId> {
        ids.iter()
            .copied()
            .filter(|id| actor_gone_in_store(&vault.store, txn, id))
            .collect()
    };
    if gone_in(&vault.store.env.read_txn()?).is_empty() {
        return Ok(());
    }
    let record_prefix = REPLAY_RECORDS.decl().prefix;
    let holder_prefix = HOLDERS.decl().prefix;
    let segment = vault.with_write_txn_grouped(|wtxn| {
        let gone = {
            let txn: &heed::RoTxn<'_> = wtxn;
            gone_in(txn)
        };
        let segment = overlay.install_txn_segment()?;
        let records: Vec<EntityId> = staged_keys(overlay, record_prefix)?
            .iter()
            .filter_map(|key| key.strip_prefix(record_prefix))
            .filter_map(<EntityId as SideKey>::decode_key)
            .collect();
        let holders: Vec<(EntityId, EntityId, u64)> = staged_keys(overlay, holder_prefix)?
            .iter()
            .filter_map(|key| key.strip_prefix(holder_prefix))
            .filter_map(<(EntityId, EntityId, u64) as SideKey>::decode_key)
            .collect();
        if records.is_empty() && holders.is_empty() {
            return Ok(segment);
        }
        let view = vault.store.session_view(overlay.clone())?;
        let dbs = RoutedDbs::Session(&view);
        for record_id in &records {
            erase_record_in_txn(&dbs, wtxn, *record_id, &gone)?;
        }
        for key in &holders {
            erase_membership_in_txn(&dbs, wtxn, key, &gone)?;
        }
        Ok(segment)
    })?;
    segment.commit()
}

/// `record_id`'s replay record in its erased form and its owner row Erased,
/// when its owner row or its live run binding names an actor in `gone`.
fn erase_record_in_txn(
    dbs: &RoutedDbs<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    record_id: EntityId,
    gone: &BTreeSet<EntityId>,
) -> Result<()> {
    let Some(record) = REPLAY_RECORDS.get_lenient(dbs, wtxn, &record_id)? else {
        return Ok(());
    };
    let owner = response_owner_in_txn(dbs, wtxn, &record_id)?;
    if owner.as_ref().is_some_and(ResponseOwner::erased) {
        return Ok(());
    }
    let named = owner
        .as_ref()
        .and_then(ResponseOwner::actor)
        .into_iter()
        .chain(record.live_run.as_ref().map(|live| live.actor))
        .any(|actor| gone.contains(&actor));
    if !named {
        return Ok(());
    }
    let run = owner.as_ref().map_or(record.run_id, |owner| owner.run);
    REPLAY_RECORDS.put_erased(dbs, wtxn, &record_id, Erased::of(record)?)?;
    mark_response_erased_in_txn(dbs, wtxn, record_id, run)
}

/// The membership `key` (wait, run, generation) Erased, and the delivery
/// its run was given in its erased form, when it names an actor in `gone`.
/// A shared settled reply and every other membership stay.
fn erase_membership_in_txn(
    dbs: &RoutedDbs<'_>,
    wtxn: &mut heed::RwTxn<'_>,
    key: &(EntityId, EntityId, u64),
    gone: &BTreeSet<EntityId>,
) -> Result<()> {
    let Some(WaitHolder::Kept { actor: Some(actor) }) = HOLDERS.get_lenient(dbs, wtxn, key)? else {
        return Ok(());
    };
    if !gone.contains(&actor) {
        return Ok(());
    }
    HOLDERS.put(dbs, wtxn, key, &WaitHolder::Erased)?;
    let (wait_id, run, generation) = *key;
    let row = (run, wait_id, generation);
    if let Some(delivery) = DELIVERIES.get_lenient(dbs, wtxn, &row)?
        && !delivery.erased
    {
        DELIVERIES.put_erased(dbs, wtxn, &row, Erased::of(delivery)?)?;
    }
    Ok(())
}
