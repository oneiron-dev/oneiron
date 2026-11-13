//! Moved from `crates/oneiron/src/memory/chat.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::*;
use serde::Deserialize;
use serde::Serialize;

impl Effort {
    /// The retrieval effort priced by a chat request.
    #[must_use]
    pub const fn effort(self) -> Self {
        self
    }
}
