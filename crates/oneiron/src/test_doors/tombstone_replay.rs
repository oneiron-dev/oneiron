//! Door for `tests/actor_binding_liveness.rs` (round-1 P1 of #7900): replay
//! one peer tombstone through the reason-aware replay primitive, as the sync
//! bridge replays a peer's delete. The test builds the wire value with the
//! public [`crate::deletion::TombstoneValueV2`] codec.

use crate::{EntityId, Result, Vault};

/// Replays a peer's tombstone wire value for `id`: a soft value keeps the
/// shell, a hard value purges the row and records the permanent `dt:` marker.
///
/// # Errors
///
/// The replay's: a protection-gate refusal, or a read or write failure.
pub fn replay_tombstone(vault: &Vault, id: &EntityId, raw_value: &[u8]) -> Result<()> {
    vault.apply_replayed_tombstone(id, raw_value)?;
    Ok(())
}
