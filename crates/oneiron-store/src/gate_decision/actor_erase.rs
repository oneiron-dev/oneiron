//! An erased actor out of the Gate decision ledger (FIX 4230, 4231).

use heed::RwTxn;

use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;

/// What an actor's erase does with the Gate decisions that name it as the
/// actor they judged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAttributionErase {
    /// Each decision stays in place with its id, its time, its outcome, its
    /// reasons, its class, its policy, its grant, its diff and its frontier,
    /// and names no actor.
    ClearActorRefOnly,
}

/// A Gate decision is the receipt of what was decided, so it stays; who
/// asked for it goes with that actor's erase (FIX 4230, 4231; a call).
pub const ACTOR_ERASE_GATE_ATTRIBUTION: GateAttributionErase =
    GateAttributionErase::ClearActorRefOnly;
