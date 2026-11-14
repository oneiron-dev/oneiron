//! Moved from `crates/oneiron/src/reaction/signal.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

pub const CURSOR_BYTES: usize = 25;

/// A put or a removal of a reaction to one of the reader's messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactionSignal {
    pub reaction: EntityId,
    pub message: EntityId,
    pub by: EntityId,
    pub glyph: String,
    pub occurred_at: u64,
    pub recorded_at: u64,
    pub revoked: bool,
}

impl ReactionSignal {
    /// `reaction.put` or `reaction.revoked`.
    #[must_use]
    pub const fn event(&self) -> &'static str {
        if self.revoked {
            "reaction.revoked"
        } else {
            "reaction.put"
        }
    }

    fn key(&self) -> [u8; CURSOR_BYTES] {
        let mut key = [0u8; CURSOR_BYTES];
        key[..8].copy_from_slice(&self.recorded_at.to_be_bytes());
        key[8..24].copy_from_slice(self.reaction.as_bytes());
        key[24] = u8::from(self.revoked);
        key
    }
}
