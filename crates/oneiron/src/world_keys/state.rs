//! The no-kit warning (ruling fix 10): a typed state. Clients word it; the engine
//! stores no sentence. Beside it, whether the pad the world's current key
//! needs is on this machine (FIX 348): kit coverage counts wraps, never pads.

use super::RecoveryRootId;
use super::pads::{pad_in_txn, world_keys_destroyed_in_txn};
use crate::authority::{AuthorityFold, EffectiveRead};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Whether a lost machine would take the world with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldRecoveryState {
    /// The world reads everywhere: the vault's own recovery covers it.
    NotPrivate,
    /// The world's current key has a wrap to this install's pinned root.
    Covered,
    /// A private world whose current key this install's kit cannot open: no pinned
    /// root, no key yet, or no wrap to the pinned root.
    NoKit,
}

/// - `private`: the world's effective read is not everywhere.
/// - `pinned`: this install's root (R1). A root this install does not pin never
///   counts.
/// - `current_key_roots`: the roots the world's current key is wrapped to.
#[must_use]
pub fn recovery_state(
    private: bool,
    pinned: Option<RecoveryRootId>,
    current_key_roots: &[RecoveryRootId],
) -> WorldRecoveryState {
    match (private, pinned) {
        (false, _) => WorldRecoveryState::NotPrivate,
        (true, Some(root)) if current_key_roots.contains(&root) => WorldRecoveryState::Covered,
        (true, _) => WorldRecoveryState::NoKit,
    }
}

/// Whether the pad the world's current key needs is on this machine (FIX
/// 348), apart from its kit coverage ([`WorldRecoveryState`]): a covered world
/// whose pad never arrived here still opens nowhere here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldPadAvailability {
    /// The current key's pad is here: in its row, or in key custody.
    Present,
    /// The world has a current key and its pad has not reached this machine.
    Missing,
    /// A private world with no key yet: no pad is owed.
    NoCurrentKey,
    /// The world's keys were destroyed here with the world.
    Destroyed,
    /// The world reads everywhere and has no key: none is needed.
    NotRequired,
    /// The pad's state could not be read here.
    Unavailable,
}

/// `world`'s pad availability, read in `txn` from `fold`. A read fault is
/// [`WorldPadAvailability::Unavailable`], never an error of its own.
pub(super) fn world_pad_availability_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    world: EntityId,
) -> WorldPadAvailability {
    let read = || -> Result<WorldPadAvailability> {
        if world_keys_destroyed_in_txn(store, txn, world)? {
            return Ok(WorldPadAvailability::Destroyed);
        }
        let Some(current) = fold.current_world_key(world) else {
            return Ok(
                if fold.world_privacy(world).read == EffectiveRead::Everywhere {
                    WorldPadAvailability::NotRequired
                } else {
                    WorldPadAvailability::NoCurrentKey
                },
            );
        };
        Ok(if pad_in_txn(store, txn, &current.id)?.is_some() {
            WorldPadAvailability::Present
        } else {
            WorldPadAvailability::Missing
        })
    };
    read().unwrap_or(WorldPadAvailability::Unavailable)
}
