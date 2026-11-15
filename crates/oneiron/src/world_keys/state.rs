//! The no-kit warning (ruling fix 10): a typed state. Clients word it; the engine
//! stores no sentence. Beside it, whether the pad the world's current key
//! needs is on this machine (FIX 348): kit coverage counts wraps, never pads.

use super::RecoveryRootId;
use super::pads::{pad_in_txn, world_keys_destroyed_in_txn};
use crate::authority::{AuthorityFold, EffectiveRead};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

#[doc(hidden)]
pub use oneiron_records::world_keys::state::{WorldPadAvailability, WorldRecoveryState};

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
