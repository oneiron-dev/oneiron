//! Where a carried turn-program row goes in a checkpoint (KS7-3a): moved
//! whole out of `replica`, which says what each row is.

use super::replica::{ArmingRow, WakeRow, arming_key, decode_arming, decode_wake, wake_key};
use crate::entity_id::EntityId;

/// Where a carried row of either map goes in a checkpoint.
pub(crate) enum RowPlacement {
    /// In its actor's compartment, held while each dependency is.
    Owned {
        owner: EntityId,
        dependencies: Vec<EntityId>,
    },
    /// Ids alone, dropped with each entity it names.
    Structure { dependencies: Vec<EntityId> },
    /// A row whose own key differs from the key that files it, which admit
    /// refuses and no writer files (FIX SYNC-DISCARD-KEEPS-UNBOUND-WHOLE-ROW).
    KeyMismatch,
}

/// Where the arming row `bytes`, filed under `map_key`, goes: its actor's,
/// held while the conversation it listens to is. A key mismatch for an
/// arming filed under another registration (FIX
/// SYNC-CHECKPOINT-TURN-PROGRAM-KEY-UNUSED). `None` for bytes that read as
/// no arming.
pub(crate) fn arming_row_placement(map_key: &str, bytes: &[u8]) -> Option<RowPlacement> {
    let row = decode_arming(bytes).ok()?;
    if arming_key(row.registration()) != map_key {
        return Some(RowPlacement::KeyMismatch);
    }
    Some(match row {
        ArmingRow::Armed(arming) => RowPlacement::Owned {
            owner: arming.actor,
            dependencies: arming.conversation.into_iter().collect(),
        },
        ArmingRow::Disarmed { actor, .. } => RowPlacement::Owned {
            owner: actor,
            dependencies: Vec::new(),
        },
    })
}

/// Where the wake row `bytes`, filed under `map_key`, goes: an `Owed` row is
/// its actor's, held while its turn and conversation are; a `Retracted` or
/// `Released` row is its actor's, with no dependency; an `Admitted` row is
/// ids alone, held while its turn is. A key mismatch for a wake filed under
/// another wake's key. `None` for bytes that read as no wake.
pub(crate) fn wake_row_placement(map_key: &str, bytes: &[u8]) -> Option<RowPlacement> {
    let row = decode_wake(bytes).ok()?;
    if wake_key(row.key()) != map_key {
        return Some(RowPlacement::KeyMismatch);
    }
    Some(match row {
        WakeRow::Owed(wake) => RowPlacement::Owned {
            owner: wake.authority.actor(),
            dependencies: vec![wake.turn.turn, wake.turn.conversation],
        },
        // No TURN dependency: the row stands when its TURN left the window.
        WakeRow::Retracted { actor, .. } | WakeRow::Released { actor, .. } => RowPlacement::Owned {
            owner: actor,
            dependencies: Vec::new(),
        },
        WakeRow::Admitted { turn, .. } => RowPlacement::Structure {
            dependencies: vec![turn],
        },
    })
}
