//! Moved from `crates/oneiron/src/recovery/canonical/peer_origins.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// One row's peer origin: the blake3 digest of the whole entity blob a
/// peer's import brought for it, which the snapshot's row still holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPeerOrigin {
    pub id: [u8; 16],
    pub digest: [u8; 32],
}
