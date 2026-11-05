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
//! The eviction is local and writes nothing that travels: for each of the
//! world's windows here, with the window closed, the demotion tear
//! (`remove_local_replica_window_in_txn`) removes every member the window's
//! document carries with its projections, then the window's document rows;
//! the window's queued sends, its promotion marker and its thin index rows
//! go with the last step, and the world's sealing mirrors after. No
//! tombstone, deletion op, audit row or receipt is written, so nothing reaches
//! the machine that keeps the world. The world's row, its settings, its key
//! records and pads stay: the fold needs them to keep refusing the world and
//! to take it back if the owner turns the switch off. A window held open, or
//! a member a keep rule holds, waits for the next pass.

use std::collections::BTreeSet;

use crate::EntityId;
use crate::Vault;
use crate::authority::{AuthorityFold, EffectiveRead};
use crate::error::Result;
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

/// What one [`evict_worlds_placed_elsewhere`] pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WorldEviction {
    /// Worlds kept on one other machine.
    pub worlds: usize,
    /// Windows of those worlds whose local copy is gone.
    pub windows_evicted: usize,
    /// Windows held open, left for the next pass.
    pub windows_busy: usize,
    /// Entity rows removed with their projections.
    pub removed: usize,
    /// Members a keep rule held (controls, pending, uncarried rows).
    pub kept: usize,
}

/// Evicts this install's local copy of every world its fold keeps on one
/// other machine ([`world_placed_elsewhere_in`]). Local only: see the module
/// note. Safe to run at any time and again: a pass that finds nothing writes
/// nothing.
///
/// # Errors
/// Store or fold errors; a window's removal error.
pub fn evict_worlds_placed_elsewhere(vault: &Vault) -> Result<WorldEviction> {
    let worlds = worlds_placed_elsewhere(vault)?;
    let mut report = WorldEviction {
        worlds: worlds.len(),
        ..WorldEviction::default()
    };
    if worlds.is_empty() {
        return Ok(report);
    }
    for window in local_world_windows(vault, &worlds)? {
        match vault.while_window_closed(&window, || evict_window(vault, &window)) {
            None => report.windows_busy += 1,
            Some(step) => {
                let (removed, kept, complete) = step?;
                report.removed += removed;
                report.kept += kept;
                if complete {
                    report.windows_evicted += 1;
                }
            }
        }
    }
    if report.windows_busy == 0 {
        vault.with_write_txn_grouped(|wtxn| {
            for world in &worlds {
                crate::world_keys::purge_world_mirrors_in_txn(&vault.store, wtxn, *world)?;
            }
            Ok(())
        })?;
    }
    Ok(report)
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
        .filter_map(WindowKey::try_new)
        .filter(|key| key.world().is_some_and(|world| worlds.contains(&world)))
        .collect())
}

/// Removes `window`'s local copy in bounded steps, with the window held
/// closed by the caller: its members and document rows, then its queued
/// sends, its promotion marker and its thin index rows with their item
/// caches. Returns the rows removed, the members kept and whether the
/// window's rows are gone.
fn evict_window(vault: &Vault, window: &WindowKey) -> Result<(usize, usize, bool)> {
    let keep = KeepControls {
        // The world leaves this install whatever its outbox holds: the sends
        // go with its last step.
        defer_on_queued_writes: false,
        ..KeepControls::default()
    };
    let mut removed = 0;
    loop {
        let step = vault.with_write_txn_grouped(|txn| {
            let step = remove_local_replica_window_in_txn(&vault.store, txn, window, keep.clone())?;
            if step.complete {
                crate::sync::queue::scrub_window_updates_in_txn(vault, txn, window.as_str())?;
                vault
                    .store
                    .sync_state
                    .delete(txn, &format!("rp:w:{window}"))?;
                let prefix = format!("ri:w:{window}:");
                let listed: Vec<String> = vault
                    .store
                    .sync_state
                    .prefix_iter(txn, &prefix)?
                    .map(|row| row.map(|(key, _)| key.to_string()))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let items: Vec<EntityId> = listed
                    .iter()
                    .filter_map(|key| key.rsplit_once(':'))
                    .filter_map(|(_, item)| EntityId::from_hex(item).ok())
                    .collect();
                for key in &listed {
                    vault.store.sync_state.delete(txn, key)?;
                }
                super::prune::erase_item_caches_in_txn(&vault.store, txn, &items)?;
            }
            Ok(step)
        })?;
        removed += step.removed.len();
        if step.complete || step.removed.is_empty() {
            return Ok((removed, step.kept.len(), step.complete));
        }
    }
}
