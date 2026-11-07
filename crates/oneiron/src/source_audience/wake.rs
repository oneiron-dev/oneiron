//! The wake of the windows a changed policy rides (fix list row 17203).
//!
//! A window's `source_audiences` map carries the policies its bound rows'
//! closures reach, and a policy change reached a window only at that
//! window's next export or persist: a cold window not exported kept the old
//! readers. Each export and persist now files the window under every policy
//! its map carries ([`note_policy_windows`]), and every real change to a
//! policy (its readers, its open state, a thread's shares, an actor's
//! erase, a higher replica revision or a receipt merged in) leaves the
//! policy's wake in the change's own transaction ([`wake_policy_in_txn`]).
//! The sync manager's live mirror drains the wakes: each window filed under
//! the policy is persisted again, which refreshes its map to this vault's
//! current word and routes the change, and the wake is retired once every
//! window took it (`sync::source_audiences::wake`). A newer change of the
//! same policy starts its wake over; an older drain never retires it.

#[cfg(feature = "sync")]
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Vault};

/// One policy's pending wake: its generation, and the last window the
/// drain took, by the BLAKE3 of its label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PolicyWake {
    pub(crate) generation: u64,
    /// Read by the sync drain only.
    #[cfg_attr(not(feature = "sync"), allow(dead_code))]
    pub(crate) after: Option<[u8; 32]>,
}

/// Each policy's pending wake, by the policy's id.
const WAKES: SideTable<EntityId, PolicyWake, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_POLICY_WAKE);
/// Each window a policy rides, its label by the policy's id and the BLAKE3
/// of the label.
#[cfg(feature = "sync")]
const WINDOWS: SideTable<(EntityId, [u8; 32]), String, Named> =
    SideTable::new(&side_table::SOURCE_AUDIENCE_POLICY_WINDOW);

#[cfg(feature = "sync")]
fn window_hash(label: &str) -> [u8; 32] {
    *blake3::hash(label.as_bytes()).as_bytes()
}

/// Leaves `policy`'s wake in `txn`, the transaction that changed it: a new
/// generation, its drain from the first window again.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn wake_policy_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    policy: &EntityId,
) -> Result<()> {
    let generation = WAKES
        .get(&vault.store, txn, policy)?
        .map_or(1, |held| held.generation.wrapping_add(1));
    WAKES.put(
        &vault.store,
        txn,
        policy,
        &PolicyWake {
            generation,
            after: None,
        },
    )
}

#[cfg(feature = "sync")]
/// Up to `limit` pending wakes, in policy order.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn policy_wakes(vault: &Vault, limit: usize) -> Result<Vec<(EntityId, PolicyWake)>> {
    let txn = vault.store.env.read_txn()?;
    let wakes = WAKES
        .iter_from(&vault.store, &txn, &[])?
        .take(limit)
        .collect::<Result<Vec<_>>>()?;
    Ok(wakes)
}

#[cfg(feature = "sync")]
/// Up to `limit` windows `policy` rides past `wake`'s last one, in hash
/// order, each with its hash.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn policy_windows_after(
    vault: &Vault,
    policy: &EntityId,
    wake: &PolicyWake,
    limit: usize,
) -> Result<Vec<([u8; 32], String)>> {
    let txn = vault.store.env.read_txn()?;
    let mut windows = Vec::new();
    for row in WINDOWS.iter_from(&vault.store, &txn, policy.as_bytes())? {
        let ((filed, hash), label) = row?;
        if filed != *policy {
            break;
        }
        if wake.after.is_some_and(|after| hash <= after) {
            continue;
        }
        windows.push((hash, label));
        if windows.len() == limit {
            break;
        }
    }
    Ok(windows)
}

#[cfg(feature = "sync")]
/// Records how far `policy`'s wake of generation `wake.generation` went:
/// to the window hashed `last`, or, with `None`, to its end, which retires
/// it. A newer wake of the policy stands untouched.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn advance_policy_wake(
    vault: &Vault,
    policy: &EntityId,
    wake: &PolicyWake,
    last: Option<[u8; 32]>,
) -> Result<()> {
    vault.with_write_txn_grouped(|txn| match WAKES.get(&vault.store, txn, policy)? {
        Some(held) if held.generation == wake.generation => match last {
            Some(last) => WAKES.put(
                &vault.store,
                txn,
                policy,
                &PolicyWake {
                    generation: wake.generation,
                    after: Some(last),
                },
            ),
            None => WAKES.delete(&vault.store, txn, policy).map(drop),
        },
        _ => Ok(()),
    })
}

#[cfg(feature = "sync")]
/// Files the window `label` under each policy of `carried` it does not stand
/// under yet, what its export or persist found its map carrying, each with
/// the revision it carries (`None` for a head that conflicts). A window filed
/// with a revision older than this vault's, read in the filing writer, wakes
/// its policy: the change it missed may have drained before the window was
/// filed. So does one filed behind a pending wake's cursor, whatever the wake
/// is for (a receipt-only change included): that drain would never reach it.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn note_policy_windows(
    vault: &Vault,
    label: &str,
    carried: &BTreeMap<EntityId, Option<u64>>,
) -> Result<()> {
    if carried.is_empty() {
        return Ok(());
    }
    let hash = window_hash(label);
    let missing: Vec<(EntityId, Option<u64>)> = {
        let txn = vault.store.env.read_txn()?;
        let mut missing = Vec::new();
        for (policy, revision) in carried {
            if WINDOWS.get(&vault.store, &txn, &(*policy, hash))?.is_none() {
                missing.push((*policy, *revision));
            }
        }
        missing
    };
    if missing.is_empty() {
        return Ok(());
    }
    let label = label.to_owned();
    vault.with_write_txn_grouped(|txn| {
        for (policy, revision) in &missing {
            if WINDOWS.get(&vault.store, txn, &(*policy, hash))?.is_some() {
                continue;
            }
            WINDOWS.put(&vault.store, txn, &(*policy, hash), &label)?;
            let current = super::POLICIES
                .get(&vault.store, txn, policy)?
                .map(|held| held.revision);
            let stale = current.is_some() && (revision.is_none() || current > *revision);
            // A wake whose drain went past this window already, whatever it
            // was for (a receipt-only change included), starts over.
            let behind = WAKES
                .get(&vault.store, txn, policy)?
                .and_then(|wake| wake.after)
                .is_some_and(|after| hash <= after);
            if stale || behind {
                wake_policy_in_txn(vault, txn, policy)?;
            }
        }
        Ok(())
    })
}

#[cfg(feature = "sync")]
/// Takes the window hashed `hash` off `policy`'s list: it no longer
/// carries the policy, or this vault no longer stores it.
///
/// # Errors
///
/// Storage failures.
pub(crate) fn forget_policy_window(vault: &Vault, policy: &EntityId, hash: [u8; 32]) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        WINDOWS
            .delete(&vault.store, txn, &(*policy, hash))
            .map(drop)
    })
}
