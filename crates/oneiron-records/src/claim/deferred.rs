//! Moved from `crates/oneiron/src/claim/deferred.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize)]
pub enum DeferredAction {
    Supersede {
        old: [u8; 16],
        old_hash: [u8; 32],
    },
    Decay(f32),
    Weaken(f32),
    Stale,
    /// The claim's own author retracts it once the holder consents
    /// (`retract`). Rows are named msgpack, so rows parked before this
    /// variant still decode.
    Retract,
}

impl DeferredAction {
    /// A decay or the stale mark only restricts the claim it rewrites, so it
    /// settles on a held machine history; every other action waits for it.
    fn demotes_in_place(&self) -> bool {
        matches!(self, Self::Decay(_) | Self::Stale)
    }

    /// Whether the action only restricts its claim, so it reads a held
    /// history whole: an in-place demotion, or a retraction.
    fn only_restricts(&self) -> bool {
        self.demotes_in_place() || matches!(self, Self::Retract)
    }
}
