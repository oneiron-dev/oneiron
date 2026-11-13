//! Door for `tests/comm_late_stop_after_clear.rs` (COMM-STOP-LATE-ARRIVAL):
//! a STOP that arrives as a peer's copy its peer already projected, and
//! whether it still holds sends on this replica.

use crate::Vault;
use crate::comm::CommResult;
use crate::entity_id::EntityId;

/// Rewrites the STOP recorded on `party`'s `channel_class` at `occurred_at`
/// as a peer's projected copy, keeping its hold armed. Answers its event id.
///
/// # Errors
///
/// No such unprojected STOP; storage errors.
pub fn mark_recorded_stop_peer_projected(
    vault: &Vault,
    party: &str,
    channel_class: &str,
    occurred_at: u64,
) -> CommResult<EntityId> {
    crate::comm::mark_recorded_stop_peer_projected(vault, party, channel_class, occurred_at)
}

/// Whether the STOP `event_id` still holds sends as one this replica has not
/// settled.
///
/// # Errors
///
/// Storage errors.
pub fn recorded_stop_holds(vault: &Vault, event_id: &EntityId) -> CommResult<bool> {
    crate::comm::recorded_stop_holds(vault, event_id)
}
