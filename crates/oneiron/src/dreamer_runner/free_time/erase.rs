//! An erased agent's free time (FIX 5664): the erase of an actor takes its
//! free-time rows with it, in the erase's own writer.
//!
//! The owner's policy and the clock go by the agent's key; its cycles (each
//! holding its note to its human) and its receipts go by the agent's key
//! prefix. An item binding is keyed by the attempt its cycle queued, so it
//! goes when a cycle of the agent's names its attempt, or when the binding
//! itself names the agent. A binding that does not decode goes only when a
//! cycle of the agent's names its key; any other stays as it is. A cycle row
//! under the agent's key goes whole, whether or not it decodes.
//!
//! Another agent's rows keep the erased actor only as attribution (FIX
//! 8875): its policy names the actor as its setter or its linked machine, or
//! its cycle holds a note the actor wrote. The erase leaves those rows in
//! place without that attribution or note, through the one field scrub per
//! row kind (`actor_content`).
//!
//! Calls already made settle normally: the erase takes the free-time rows,
//! never a spend record or an act that already landed. A writer that lands
//! after the erase (an item's receipt or note, its suggestion) rechecks the
//! erase in its own writer and lands nothing.

use std::collections::BTreeSet;

use super::actor_content::{scrub_cycle_note, scrub_policy_attribution};
use super::{CLOCK, CYCLE, ITEM, POLICY, RECEIPT};
use crate::attempt_queue::AttemptId;
use crate::side_table::SideKey;
use crate::{EntityId, Result, Vault};

/// The erase hook of the five free-time families (`side_table::decls`): it
/// runs in the purge's transaction, once per erased actor.
///
/// # Errors
/// A store read or write that fails.
pub(crate) fn erase_free_time_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if let Some(attempts) = cycle_attempts_in_txn(vault, txn, actor)? {
        for attempt in item_keys_in_txn(vault, txn, actor, &attempts)? {
            ITEM.delete(&vault.store, txn, &attempt)?;
        }
    }
    POLICY.delete(&vault.store, txn, actor)?;
    CLOCK.delete(&vault.store, txn, actor)?;
    CYCLE.delete_from(&vault.store, txn, actor.as_bytes())?;
    RECEIPT.delete_from(&vault.store, txn, actor.as_bytes())?;
    scrub_other_rows_in_txn(vault, txn, actor)
}

/// Every other agent's policy and cycle without `actor`'s attribution or
/// note (FIX 8875): each row stays, rewritten only where it named `actor`.
/// A row that does not decode names no one by proof and stays as it is.
fn scrub_other_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    let mut policies = Vec::new();
    for row in POLICY.iter_raw_from(&vault.store, txn, &[])? {
        let (key, bytes) = row?;
        let Some(agent) = <EntityId as SideKey>::decode_key(&key) else {
            continue;
        };
        if let Ok(mut record) = POLICY.decode_value(&bytes)
            && scrub_policy_attribution(&mut record, actor)
        {
            policies.push((agent, record));
        }
    }
    for (agent, record) in policies {
        POLICY.put(&vault.store, txn, &agent, &record)?;
    }
    let mut cycles = Vec::new();
    for row in CYCLE.iter_raw_from(&vault.store, txn, &[])? {
        let (key, bytes) = row?;
        let Some(key) = <(EntityId, u64) as SideKey>::decode_key(&key) else {
            continue;
        };
        if let Ok(mut cycle) = CYCLE.decode_value(&bytes)
            && scrub_cycle_note(&mut cycle, actor)
        {
            cycles.push((key, cycle));
        }
    }
    for (key, cycle) in cycles {
        CYCLE.put(&vault.store, txn, &key, &cycle)?;
    }
    Ok(())
}

/// Whether an erase removed `agent` (FIX 5661): a home move lands none of an
/// erased agent's free-time rows, as no writer after its erase does. A move
/// never fences the erase itself: it takes this node's rows, frozen history
/// included, and a later move carries no copy back.
#[cfg(feature = "sync")]
pub(super) fn erased_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    agent: &EntityId,
) -> Result<bool> {
    crate::ports::removed_in_txn(&vault.store, txn, agent)
}

/// The attempts `actor`'s cycles queued, read before any row goes; `None`
/// when no cycle row lies under its key. Items are bound in the commit that
/// writes their cycle, so an actor with no cycle row has no item binding.
fn cycle_attempts_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
) -> Result<Option<BTreeSet<[u8; 16]>>> {
    let mut any = false;
    let mut attempts = BTreeSet::new();
    for row in CYCLE.iter_raw_from(&vault.store, txn, actor.as_bytes())? {
        let (_, bytes) = row?;
        any = true;
        // A cycle that does not decode names no attempt; its row still goes.
        if let Ok(cycle) = CYCLE.decode_value(&bytes) {
            attempts.extend(cycle.items.iter().filter_map(|item| item.attempt));
        }
    }
    Ok(any.then_some(attempts))
}

/// The item bindings that are `actor`'s: keyed by an attempt its cycles
/// queued, or naming it as their agent.
fn item_keys_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: &EntityId,
    attempts: &BTreeSet<[u8; 16]>,
) -> Result<Vec<AttemptId>> {
    let mut keys = Vec::new();
    for row in ITEM.iter_raw_from(&vault.store, txn, &[])? {
        let (key, bytes) = row?;
        // A key that spells no attempt is no cycle's item.
        let Ok(attempt) = AttemptId::from_bytes(&key) else {
            continue;
        };
        let ours = attempts.contains(attempt.as_bytes())
            || ITEM
                .decode_value(&bytes)
                .is_ok_and(|binding| binding.agent == *actor);
        if ours {
            keys.push(attempt);
        }
    }
    Ok(keys)
}
