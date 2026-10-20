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
//! Calls already made settle normally: the erase takes the free-time rows,
//! never a spend record or an act that already landed. A writer that lands
//! after the erase (an item's receipt or note, its suggestion) rechecks the
//! erase in its own writer and lands nothing.

use std::collections::BTreeSet;

use super::{CLOCK, CYCLE, ITEM, POLICY, RECEIPT};
use crate::attempt_queue::AttemptId;
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
