//! A world the owner keeps on one other machine leaves this one (DEC-0005 fix
//! 3: "A returning old device learns it no longer holds the world. It then
//! deletes its copy"; CLIP-SYNC = A, "this Mac only"; FIX 14534).
//!
//! The pass runs on every install, from its own authority fold, and touches
//! only its own copy. A world is placed elsewhere when its settings read on
//! one machine that is not this install, that machine still stands as one of
//! the owner's own, and every live settings edit of the world was signed by
//! that machine: the owner turned "this Mac only" on there, on the copy he
//! keeps. Any other loss of reading (a conflicted root, this install no
//! longer marked "yours", an edit carried by another machine) evicts nothing:
//! the doors stop sending, and the rows stay until a rule here covers the
//! case (Engine call CLIP-SYNC eviction scope, CALLS.md).
//!
//! No write is lost to it. A window goes only once nothing in it is this
//! install's alone: no queued send for it waits, no local write still owes
//! it a row (a pending-mirror marker), and the home's version vector for it,
//! as this device last exchanged it (`sv:hw:`, kept across restarts and
//! taken from the home's vector frames even after the world left), covers
//! every operation its persisted copy holds, as a demotion asks. A window
//! with a member its document does not carry, or one with local work
//! pending, is left whole on either path, named on the report, so a later
//! pass or the owner's discard finds it again; nothing of it goes while the
//! rest of its rows would (FIX 14534). A window the home never held, or holds less of, stays, named on the
//! pass's report, until the owner discards this install's copy himself
//! ([`discard_world_copy_as`]). A window open with no handle but the
//! manager's is unloaded first; one a handle holds waits for the next pass. The thin read caches of the world's items
//! (`ri:b:`, `ri:d:`, `ro:e:`, their touch and index rows) go at once: each is
//! a copy of an item the home holds. A cache a legal hold names stays.
//!
//! The eviction is local and writes nothing that travels: for each window,
//! with the window closed, the demotion tear
//! (`remove_local_replica_window_in_txn`) removes every member the window's
//! document carries with its projections, then the window's document rows;
//! its promotion marker and its thin index rows go with the last step, and
//! the world's sealing mirrors once every window is gone. No tombstone,
//! deletion op, audit row or receipt is written, so nothing reaches the
//! machine that keeps the world. The world's row, its settings, its key
//! records and pads stay: the fold needs them to keep refusing the world and
//! to take it back if the owner turns the switch off. A window held open, or
//! a member a keep rule holds, waits for the next pass.

use std::collections::{BTreeSet, HashMap};

use loro::VersionVector;

use super::{ContentWorld, WindowIndexEntry};
use crate::EntityId;
use crate::Vault;
use crate::authority::{AuthorityFold, EffectiveRead};
use crate::error::{Error, Result};
use crate::ports::EntityStoreRead;
use crate::store::legal_hold::{HoldActor, is_hold_refusal};
use crate::store::local_replica::{
    KeepControls, KeepReason, discard_bundle_payload_in_txn, remove_local_members_in_txn,
    remove_local_replica_window_in_txn,
};
use crate::sync::WindowKey;

/// Whether `fold` keeps `world` on one machine other than `me`, by the owner's
/// act on that machine: its read names that machine alone, the machine stands
/// as one of the owner's own, and it signed every live settings edit.
#[must_use]
pub(crate) fn world_placed_elsewhere_in(
    fold: &AuthorityFold,
    me: EntityId,
    world: EntityId,
) -> bool {
    if fold.vault_root_is_conflicted() {
        return false;
    }
    let Some(folded) = fold.worlds.get(&world) else {
        return false;
    };
    let EffectiveRead::OneMachine(holder) = folded.effective.read else {
        return false;
    };
    holder != me
        && fold.trusted_machine(holder).is_some()
        && !folded.live.is_empty()
        && folded.live.values().all(|signer| *signer == holder)
}

/// The worlds this install's fold keeps on one other machine
/// ([`world_placed_elsewhere_in`]). None before this install has a machine.
///
/// # Errors
/// Store or fold errors.
pub(crate) fn worlds_placed_elsewhere(vault: &Vault) -> Result<BTreeSet<EntityId>> {
    let Some(me) = vault.local_machine()?.map(|local| local.id) else {
        return Ok(BTreeSet::new());
    };
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    Ok(fold
        .worlds
        .keys()
        .copied()
        .filter(|world| world_placed_elsewhere_in(&fold, me, *world))
        .collect())
}

/// Whether this install's fold keeps `world` on one other machine.
///
/// # Errors
/// Store or fold errors.
pub(crate) fn world_placed_elsewhere(vault: &Vault, world: EntityId) -> Result<bool> {
    let Some(me) = vault.local_machine()?.map(|local| local.id) else {
        return Ok(false);
    };
    let txn = vault.store.env.read_txn()?;
    let fold = vault.authority_view_readonly_in_txn(&txn)?;
    Ok(world_placed_elsewhere_in(&fold, me, world))
}

/// What one eviction pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WorldEviction {
    /// Worlds kept on one other machine.
    pub worlds: usize,
    /// Windows of those worlds whose local copy is gone.
    pub windows_evicted: usize,
    /// Windows held open, or deferred by a queued send, left for the next
    /// pass.
    pub windows_busy: usize,
    /// Windows that may hold a write only this install has: the home is not
    /// known to hold every operation of them. They stay until the home does,
    /// or the owner discards this install's copy.
    pub windows_unconfirmed: usize,
    /// Entity rows removed with their projections.
    pub removed: usize,
    /// Members a keep rule held (controls, holds, deletion state).
    pub kept: usize,
    /// Windows left whole because a member only this install may hold stays
    /// in them: one its document does not carry, or one with local work
    /// pending. They wait for a rule that may drop such a member.
    pub windows_with_local_members: usize,
    /// Thin read caches of the worlds' items removed.
    pub cached_items_removed: usize,
    /// Thin read caches a legal hold keeps.
    pub cached_items_held: usize,
    /// Sealed updates this install made of the worlds and the home had not
    /// stored, which the owner's discard took.
    pub sealed_sends_discarded: usize,
}

/// The home's version vector of world window `window_key`, as this device
/// last exchanged it (FIX 14534).
fn home_window_vv_key(window_key: &str) -> String {
    format!(
        "{}{window_key}",
        String::from_utf8_lossy(crate::side_table::SYNC_HOME_WINDOW_VV.prefix)
    )
}

/// Keeps `home`, the home's version vector of world window `window_key`,
/// as this device just exchanged it.
///
/// # Errors
/// Store errors.
pub(crate) fn put_home_window_vv(
    vault: &Vault,
    window_key: &str,
    home: &VersionVector,
) -> Result<()> {
    vault.sync_state_put(&home_window_vv_key(window_key), &home.encode())
}

/// Evicts this install's local copy of every world its fold keeps on one
/// other machine ([`world_placed_elsewhere_in`]), losing no write: a window
/// goes only once the home's version vector for it, as this device last
/// exchanged it, covers its persisted copy and no queued send for it waits.
/// Local only: see the module note. Safe to run at any time and again: a
/// pass that finds nothing writes nothing.
///
/// # Errors
/// Store or fold errors; a window's removal error.
pub fn evict_worlds_placed_elsewhere(vault: &Vault) -> Result<WorldEviction> {
    let worlds = worlds_placed_elsewhere(vault)?;
    evict(vault, &worlds, Confirmation::Home)
}

/// Discards this install's copy of `world` on the owner's word (FIX 14534):
/// every window of it goes as the pass's would, its queued sends and the
/// rows its local writes still owed it with it, once the owner keeps the
/// world on one other machine. The owner's act: nothing here waits for the
/// home. A member its document does not carry, or one whose only pending
/// local work is its promotion pickup, document frames or NOTE requests,
/// goes too, with that work and every edge it touches (Engine 11-06 08:34 =
/// A); a pending tombstone still travels, as an id. Then every CLAIM of the
/// world its claim posting list names, still in one of its windows, goes the
/// same way, and so does each row of the world alone that sits in a BASE
/// window (`world_base_rows`). What a legal hold, a control or the fold's own
/// records keep stays.
///
/// # Errors
/// An owner proof that no longer stands; [`Error::InvalidConfig`] while this
/// install still holds the world; store errors; a window's removal error.
pub fn discard_world_copy_as(
    vault: &Vault,
    owner: &crate::consent::AuthenticatedOwner,
    world: EntityId,
) -> Result<WorldEviction> {
    {
        let rtxn = vault.store.env.read_txn()?;
        owner.revalidate_in_txn(vault, &rtxn)?;
    }
    if !world_placed_elsewhere(vault, world)? {
        return Err(Error::InvalidConfig(
            "this install still holds the world: only a copy the owner keeps on one other machine \
             is discarded"
                .into(),
        ));
    }
    evict(vault, &BTreeSet::from([world]), Confirmation::Owner)
}

/// What lets a window go.
#[derive(Clone, Copy)]
enum Confirmation {
    /// The home holds every operation of it, and no queued send for it waits.
    Home,
    /// The owner discards this install's copy, queued sends with it.
    Owner,
}

fn evict(
    vault: &Vault,
    worlds: &BTreeSet<EntityId>,
    confirmation: Confirmation,
) -> Result<WorldEviction> {
    let mut report = WorldEviction {
        worlds: worlds.len(),
        ..WorldEviction::default()
    };
    if worlds.is_empty() {
        return Ok(report);
    }
    let (removed, held) = evict_cached_items(vault, worlds)?;
    report.cached_items_removed = removed;
    report.cached_items_held = held;
    // Every member the passes' writes take, for the bundles that span them.
    let mut taken = BTreeSet::new();
    for window in local_world_windows(vault, worlds)? {
        if matches!(confirmation, Confirmation::Home) && !home_holds_window(vault, &window)? {
            report.windows_unconfirmed += 1;
            continue;
        }
        // A window open with no handle but the manager's is put away first,
        // so the fence can hold it closed; one a handle holds waits.
        vault.unload_idle_window(&window)?;
        match vault.while_window_closed(&window, || evict_window(vault, &window, confirmation)) {
            None => report.windows_busy += 1,
            Some(step) => {
                let step = step?;
                report.removed += step.removed.len();
                report.kept += step.kept;
                taken.extend(step.removed);
                match step.progress {
                    Progress::Complete => report.windows_evicted += 1,
                    Progress::Busy => report.windows_busy += 1,
                    Progress::LocalMembers => report.windows_with_local_members += 1,
                    Progress::Unconfirmed => report.windows_unconfirmed += 1,
                }
            }
        }
    }
    // The owner's discard takes the world's CLAIMs its windows no longer
    // list too (FIX 14534, Engine 11-06 08:34 = A).
    if matches!(confirmation, Confirmation::Owner) {
        for world in worlds {
            let leftover = discard_leftover_claims(vault, *world)?;
            report.removed += leftover.removed.len();
            report.kept += leftover.kept;
            report.windows_busy += leftover.windows_busy;
            taken.extend(leftover.removed);
            // And its rows that sit in BASE windows (Engine call 1 = A).
            let base = super::world_base_rows::discard_base_rows(vault, *world)?;
            report.removed += base.removed.len();
            report.kept += base.kept;
            report.windows_busy += base.windows_busy;
            taken.extend(base.removed);
        }
        // A bundle whose members two of those writes took goes once all have
        // (call 4 = A).
        if !taken.is_empty() {
            vault.with_write_txn_grouped(|wtxn| {
                discard_bundle_payload_in_txn(&vault.store, wtxn, &taken)
            })?;
        }
    }
    if report.windows_busy == 0
        && report.windows_unconfirmed == 0
        && report.windows_with_local_members == 0
    {
        report.sealed_sends_discarded = vault.with_write_txn_grouped(|wtxn| {
            let mut discarded = 0;
            for world in worlds {
                crate::world_keys::purge_world_mirrors_in_txn(&vault.store, wtxn, *world)?;
                // The owner's discard takes its unsent sealed updates of the
                // world too, once nothing of it waits here (call 3 = A).
                if matches!(confirmation, Confirmation::Owner) {
                    discarded +=
                        super::sealed_updates::discard_world_outbox_in_txn(vault, wtxn, *world)?;
                }
            }
            Ok(discarded)
        })?;
    }
    Ok(report)
}

/// Whether the home's version vector for `window`, as this device last
/// exchanged it, covers every operation its persisted copy holds. One that
/// does not read covers nothing.
fn home_holds_window(vault: &Vault, window: &WindowKey) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    home_holds_window_in_txn(vault, &txn, window)
}

/// [`home_holds_window`] in `txn`: the destructive write proves it again over
/// the window it closed, as a mirror may have persisted a local write since
/// the pass first read it.
fn home_holds_window_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    window: &WindowKey,
) -> Result<bool> {
    let key = home_window_vv_key(window.as_str());
    let Some(home) = vault.store.sync_state.get(txn, &key)? else {
        return Ok(false);
    };
    let Ok(home) = VersionVector::decode(&home) else {
        return Ok(false);
    };
    let held = super::prune::persisted_window_vv(&vault.store, txn, window)?;
    Ok(home.includes_vv(&held))
}

/// The world of the window `label` names, when it is one of `worlds`.
fn of_worlds(label: &str, worlds: &BTreeSet<EntityId>) -> bool {
    WindowKey::try_new(label)
        .and_then(|key| key.world())
        .is_some_and(|world| worlds.contains(&world))
}

/// Every window of `worlds` this install keeps rows for: a persisted
/// snapshot, a persisted update or a queued send.
fn local_world_windows(vault: &Vault, worlds: &BTreeSet<EntityId>) -> Result<Vec<WindowKey>> {
    let txn = vault.store.env.read_txn()?;
    let mut labels = BTreeSet::new();
    for prefix in ["d:w:", "u:w:"] {
        for row in vault.store.sync_state.prefix_iter(&txn, prefix)? {
            let (key, _) = row?;
            let rest = &key[prefix.len()..];
            let label = if prefix == "u:w:" {
                rest.rsplit_once(':').map_or(rest, |(label, _)| label)
            } else {
                rest
            };
            labels.insert(label.to_owned());
        }
    }
    labels.extend(crate::sync::queue::queued_window_labels_in_txn(
        vault, &txn,
    )?);
    Ok(labels
        .into_iter()
        .filter(|label| of_worlds(label, worlds))
        .filter_map(WindowKey::try_new)
        .collect())
}

/// Removes the thin read caches of `worlds`' items. An item an opened
/// marker (`ro:e:`) maps to one of their windows, or a thin index row
/// (`ri:w:{window}:{item}`) of one lists, is that world's by its window: its
/// cache goes whole, with every index row that lists it. A copy fetched or
/// listed in any other window, a base one included, goes when the home
/// witnessed its row as of one of `worlds` alone (FIX 14534, Engine 11-06
/// 08:34 call 5 = A): that copy only, as another fetch or listing of the
/// same item may witness it shared. A copy with no witness, or a shared or
/// base one, stays, and so does a cache a legal hold names. Returns the
/// fetched copies removed and the items held.
fn evict_cached_items(vault: &Vault, worlds: &BTreeSet<EntityId>) -> Result<(usize, usize)> {
    vault.with_write_txn_grouped(|txn| {
        let mut items = BTreeSet::new();
        for row in vault.store.sync_state.prefix_iter(txn, "ro:e:")? {
            let (key, window) = row?;
            if of_worlds(&String::from_utf8_lossy(&window), worlds)
                && let Some(item) = key
                    .strip_prefix("ro:e:")
                    .and_then(|id| EntityId::from_hex(id).ok())
            {
                items.insert(item);
            }
        }
        let witnessed = |witness: ContentWorld| {
            witness
                .exclusive()
                .is_some_and(|world| worlds.contains(&world))
        };
        let mut copies = BTreeSet::new();
        for row in vault.store.sync_state.prefix_iter(txn, "ri:c:")? {
            let (key, witness) = row?;
            if witnessed(ContentWorld::decode(&witness))
                && let Some(item) = key
                    .strip_prefix("ri:c:")
                    .and_then(|id| EntityId::from_hex(id).ok())
            {
                copies.insert(item);
            }
        }
        let mut listings = Vec::new();
        for row in vault.store.sync_state.prefix_iter(txn, "ri:w:")? {
            let (key, entry) = row?;
            let Some((window, item)) = key
                .strip_prefix("ri:w:")
                .and_then(|rest| rest.rsplit_once(':'))
            else {
                continue;
            };
            let Ok(item) = EntityId::from_hex(item) else {
                continue;
            };
            if of_worlds(window, worlds) {
                items.insert(item);
            } else if rmp_serde::from_slice::<WindowIndexEntry>(&entry)
                .is_ok_and(|entry| witnessed(entry.content_world))
            {
                listings.push((item, key.to_string()));
            }
        }
        let mut held = BTreeSet::new();
        let mut erased = Vec::new();
        for item in items {
            if cache_held(vault, txn, item)? {
                held.insert(item);
            } else {
                erased.push(item);
            }
        }
        let mut removed = 0;
        for item in &erased {
            if vault
                .store
                .sync_state
                .get(txn, &format!("ri:b:{}", item.to_hex()))?
                .is_some()
            {
                removed += 1;
            }
        }
        // Each erased item's cache rows go with its index rows, in whichever
        // window listed it.
        super::prune::erase_item_caches_in_txn(&vault.store, txn, &erased)?;
        for item in copies {
            if held.contains(&item) || cache_held(vault, txn, item)? {
                held.insert(item);
                continue;
            }
            if vault
                .store
                .sync_state
                .get(txn, &format!("ri:b:{}", item.to_hex()))?
                .is_some()
            {
                removed += 1;
            }
            super::prune::clear_thin_item_cache_in_txn(&vault.store, txn, item)?;
        }
        for (item, key) in listings {
            if held.contains(&item) || cache_held(vault, txn, item)? {
                held.insert(item);
                continue;
            }
            vault.store.sync_state.delete(txn, &key)?;
        }
        Ok((removed, held.len()))
    })
}

/// Whether a legal hold keeps `item`'s cache; any other failure fails.
fn cache_held(vault: &Vault, txn: &heed::RoTxn<'_>, item: EntityId) -> Result<bool> {
    match vault
        .store
        .reject_legal_holds_in_txn(txn, &[item], &HoldActor::UNATTRIBUTED)
    {
        Ok(()) => Ok(false),
        Err(error) if is_hold_refusal(&error) => Ok(true),
        Err(error) => Err(error),
    }
}

/// Removes `window`'s local copy in bounded steps, with the window held
/// closed by the caller: its members and document rows, then its promotion
/// marker. A queued send for it defers the step, unless the owner discards
/// the copy, whose sends go with its last step. Returns the rows removed,
/// the members kept and whether the window's rows are gone.
/// The tear's keep controls on each path. The automatic pass leaves a window
/// whole while a member only this install may hold stays; the owner's
/// discard releases such a member, with its local work and every edge it
/// touches, and keeps what every other rule keeps (FIX 14534).
fn keep_controls(confirmation: Confirmation) -> KeepControls {
    let discard = matches!(confirmation, Confirmation::Owner);
    KeepControls {
        defer_on_queued_writes: !discard,
        defer_on_local_members: !discard,
        release_local_members: discard,
        ..KeepControls::default()
    }
}

/// The world CLAIMs a discard took after their windows' rows went.
#[derive(Default)]
struct Leftover {
    removed: Vec<EntityId>,
    kept: usize,
    windows_busy: usize,
}

/// The CLAIMs one page of the world's claim posting list reads.
const LEFTOVER_PAGE: usize = 256;

/// Takes the CLAIMs of `world` this install still keeps after its windows'
/// rows went: each one its claim posting list names whose row still sits in
/// one of the world's windows, through the tear's own rules for that window,
/// held closed ([`remove_local_members_in_txn`]). A claim a keep rule holds
/// stays; a window held open waits for the next discard.
fn discard_leftover_claims(vault: &Vault, world: EntityId) -> Result<Leftover> {
    let mut leftover = Leftover::default();
    let keep = keep_controls(Confirmation::Owner);
    let mut after = None;
    loop {
        let mut by_window: HashMap<WindowKey, Vec<EntityId>> = HashMap::new();
        let page = {
            let txn = vault.store.env.read_txn()?;
            let page = crate::store::claim_projection::claim_ids_for_world_page_in_txn(
                &vault.store,
                &txn,
                world,
                after,
                LEFTOVER_PAGE,
            )?;
            for id in &page {
                let Some(raw) = vault.store.port_entity_raw(&txn, id)? else {
                    continue;
                };
                let Ok(window) = super::residence_window_for_blob(&raw) else {
                    continue;
                };
                if window.world() == Some(world) {
                    by_window.entry(window).or_default().push(*id);
                }
            }
            page
        };
        for (window, ids) in by_window {
            vault.unload_idle_window(&window)?;
            let step = vault.while_window_closed(&window, || {
                vault.with_write_txn_grouped(|txn| {
                    remove_local_members_in_txn(&vault.store, txn, &window, &ids, keep.clone())
                })
            });
            match step {
                None => leftover.windows_busy += 1,
                Some(step) => {
                    let step = step?;
                    leftover.removed.extend_from_slice(&step.removed);
                    leftover.kept += step.kept.len();
                }
            }
        }
        match page.last() {
            Some(last) if page.len() == LEFTOVER_PAGE => after = Some(*last),
            _ => return Ok(leftover),
        }
    }
}

/// How far one window's eviction got.
enum Progress {
    /// Its copy is gone.
    Complete,
    /// A handle, a queued send or a pending mirror holds it: the next pass.
    Busy,
    /// A member only this install may hold stays, so the window is whole.
    LocalMembers,
    /// The home is not known to hold every operation it persists now.
    Unconfirmed,
}

/// What one window's eviction did.
struct WindowStep {
    removed: Vec<EntityId>,
    kept: usize,
    progress: Progress,
}

fn evict_window(
    vault: &Vault,
    window: &WindowKey,
    confirmation: Confirmation,
) -> Result<WindowStep> {
    let discard = matches!(confirmation, Confirmation::Owner);
    let keep = keep_controls(confirmation);
    let mut removed = Vec::new();
    loop {
        let step = vault.with_write_txn_grouped(|txn| {
            if !discard {
                // A local write the mirror has not taken yet is in no
                // persisted copy the home holds: the pass waits for it.
                if crate::sync::manager::window_owes_mirror_in_txn(vault, txn, window)? {
                    return Ok(Err(Progress::Busy));
                }
                // The proof the pass read before it closed the window is not
                // this write's: a mirror may have persisted a local write
                // since. The home must hold what is persisted now (FIX 14534).
                if !home_holds_window_in_txn(vault, txn, window)? {
                    return Ok(Err(Progress::Unconfirmed));
                }
            }
            let step = remove_local_replica_window_in_txn(&vault.store, txn, window, keep.clone())?;
            if step.complete {
                if discard {
                    crate::sync::queue::scrub_window_updates_in_txn(vault, txn, window.as_str())?;
                    crate::sync::manager::discard_window_mirrors_in_txn(vault, txn, window)?;
                }
                vault
                    .store
                    .sync_state
                    .delete(txn, &format!("rp:w:{window}"))?;
                vault
                    .store
                    .sync_state
                    .delete(txn, &home_window_vv_key(window.as_str()))?;
            }
            Ok(Ok(step))
        })?;
        let step = match step {
            Ok(step) => step,
            Err(progress) => {
                return Ok(WindowStep {
                    removed,
                    kept: 0,
                    progress,
                });
            }
        };
        removed.extend_from_slice(&step.removed);
        let local = step
            .kept
            .iter()
            .any(|(_, reason)| matches!(reason, KeepReason::NotCarried | KeepReason::Pending));
        let progress = if step.complete {
            Progress::Complete
        } else if local {
            Progress::LocalMembers
        } else {
            Progress::Busy
        };
        if step.complete || step.removed.is_empty() {
            return Ok(WindowStep {
                removed,
                kept: step.kept.len(),
                progress,
            });
        }
    }
}
