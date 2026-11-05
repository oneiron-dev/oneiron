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
//! install's alone: no queued send for it waits, and the home's version
//! vector for it, as this connection last exchanged it, covers every
//! operation its persisted copy holds, as a demotion asks. A window the home
//! never held, or holds less of, stays, named on the pass's report, until
//! the owner discards this install's copy himself
//! ([`discard_world_copy_as`]). The thin read caches of the world's items
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

use crate::EntityId;
use crate::Vault;
use crate::authority::{AuthorityFold, EffectiveRead};
use crate::error::{Error, Result};
use crate::store::legal_hold::{HoldActor, is_hold_refusal};
use crate::store::local_replica::{KeepControls, remove_local_replica_window_in_txn};
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
    /// Members a keep rule held (controls, pending, uncarried rows).
    pub kept: usize,
    /// Thin read caches of the worlds' items removed.
    pub cached_items_removed: usize,
    /// Thin read caches a legal hold keeps.
    pub cached_items_held: usize,
}

/// Evicts this install's local copy of every world its fold keeps on one
/// other machine ([`world_placed_elsewhere_in`]), losing no write: a window
/// goes only once `home`, the home's version vector for each window as this
/// connection last exchanged it, covers its persisted copy and no queued
/// send for it waits. Local only: see the module note. Safe to run at any
/// time and again: a pass that finds nothing writes nothing.
///
/// # Errors
/// Store or fold errors; a window's removal error.
pub fn evict_worlds_placed_elsewhere(
    vault: &Vault,
    home: &HashMap<String, VersionVector>,
) -> Result<WorldEviction> {
    let worlds = worlds_placed_elsewhere(vault)?;
    evict(vault, &worlds, Confirmation::Home(home))
}

/// Discards this install's copy of `world` on the owner's word (FIX 14534):
/// every window of it goes as the pass's would, its queued sends and any
/// write only this install held with it, once the owner keeps the world on
/// one other machine. The owner's act: nothing here waits for the home.
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
enum Confirmation<'h> {
    /// The home holds every operation of it, and no queued send for it waits.
    Home(&'h HashMap<String, VersionVector>),
    /// The owner discards this install's copy, queued sends with it.
    Owner,
}

fn evict(
    vault: &Vault,
    worlds: &BTreeSet<EntityId>,
    confirmation: Confirmation<'_>,
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
    for window in local_world_windows(vault, worlds)? {
        if let Confirmation::Home(home) = confirmation
            && !home_holds_window(vault, home, &window)?
        {
            report.windows_unconfirmed += 1;
            continue;
        }
        match vault.while_window_closed(&window, || evict_window(vault, &window, confirmation)) {
            None => report.windows_busy += 1,
            Some(step) => {
                let (removed, kept, complete) = step?;
                report.removed += removed;
                report.kept += kept;
                if complete {
                    report.windows_evicted += 1;
                } else {
                    report.windows_busy += 1;
                }
            }
        }
    }
    if report.windows_busy == 0 && report.windows_unconfirmed == 0 {
        vault.with_write_txn_grouped(|wtxn| {
            for world in worlds {
                crate::world_keys::purge_world_mirrors_in_txn(&vault.store, wtxn, *world)?;
            }
            Ok(())
        })?;
    }
    Ok(report)
}

/// Whether the home's version vector for `window`, as this connection last
/// exchanged it, covers every operation its persisted copy holds.
fn home_holds_window(
    vault: &Vault,
    home: &HashMap<String, VersionVector>,
    window: &WindowKey,
) -> Result<bool> {
    let Some(home) = home.get(window.as_str()) else {
        return Ok(false);
    };
    let txn = vault.store.env.read_txn()?;
    let held = super::prune::persisted_window_vv(&vault.store, &txn, window)?;
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

/// Removes the thin read caches of `worlds`' items: each item an opened
/// marker (`ro:e:`) maps to one of their windows, or a thin index row
/// (`ri:w:{window}:{item}`) of one lists, with every index row of those
/// windows' index rows. A cache a legal hold names stays. Returns the caches
/// removed and the ones held.
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
        for row in vault.store.sync_state.prefix_iter(txn, "ri:w:")? {
            let (key, _) = row?;
            let Some((window, item)) = key
                .strip_prefix("ri:w:")
                .and_then(|rest| rest.rsplit_once(':'))
            else {
                continue;
            };
            if of_worlds(window, worlds)
                && let Ok(item) = EntityId::from_hex(item)
            {
                items.insert(item);
            }
        }
        let mut erased = Vec::new();
        let mut held = 0;
        for item in items {
            match vault
                .store
                .reject_legal_holds_in_txn(txn, &[item], &HoldActor::UNATTRIBUTED)
            {
                Ok(()) => erased.push(item),
                Err(error) if is_hold_refusal(&error) => held += 1,
                Err(error) => return Err(error),
            }
        }
        let cached = erased
            .iter()
            .map(|item| format!("ri:b:{}", item.to_hex()))
            .collect::<Vec<_>>();
        let mut removed = 0;
        for key in &cached {
            if vault.store.sync_state.get(txn, key)?.is_some() {
                removed += 1;
            }
        }
        // Each erased item's cache rows go with its index rows, in whichever
        // window listed it.
        super::prune::erase_item_caches_in_txn(&vault.store, txn, &erased)?;
        Ok((removed, held))
    })
}

/// Removes `window`'s local copy in bounded steps, with the window held
/// closed by the caller: its members and document rows, then its promotion
/// marker. A queued send for it defers the step, unless the owner discards
/// the copy, whose sends go with its last step. Returns the rows removed,
/// the members kept and whether the window's rows are gone.
fn evict_window(
    vault: &Vault,
    window: &WindowKey,
    confirmation: Confirmation<'_>,
) -> Result<(usize, usize, bool)> {
    let discard = matches!(confirmation, Confirmation::Owner);
    let keep = KeepControls {
        defer_on_queued_writes: !discard,
        ..KeepControls::default()
    };
    let mut removed = 0;
    loop {
        let step = vault.with_write_txn_grouped(|txn| {
            let step = remove_local_replica_window_in_txn(&vault.store, txn, window, keep.clone())?;
            if step.complete {
                if discard {
                    crate::sync::queue::scrub_window_updates_in_txn(vault, txn, window.as_str())?;
                }
                vault
                    .store
                    .sync_state
                    .delete(txn, &format!("rp:w:{window}"))?;
            }
            Ok(step)
        })?;
        removed += step.removed.len();
        if step.complete || step.removed.is_empty() {
            return Ok((removed, step.kept.len(), step.complete));
        }
    }
}
