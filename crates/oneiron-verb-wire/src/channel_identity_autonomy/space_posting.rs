//! Moved from `crates/oneiron/src/channel_identity_autonomy/space_posting.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use rmpv::Value;

/// Posting identity is data. Even owner mode must pass the normal outbound gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpacePostingMode {
    NamedParticipant,
    PostAsOwner,
}
