//! Moved from `crates/oneiron/src/sync/selector/peer_confidence.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One peer's owner-set scale.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfidence {
    /// Multiplies a peer claim's confidence: above 0, at most 1. A peer is
    /// never believed above the owner's own word.
    pub scale: f32,
    pub set_at: u64,
}
