//! Moved from `crates/oneiron/src/office_body/actor_erase.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::office_body::records::ForkState;
use oneiron_contracts::entity_id::EntityId;
#[cfg(feature = "sync")]
use std::collections::BTreeSet;

impl ForkState {
    /// Makes the one who settled the fork no one when it is `actor`; whether
    /// it was.
    fn forget(&mut self, actor: EntityId) -> bool {
        match self {
            Self::Open => false,
            Self::Merged { by, .. } | Self::Discarded { by, .. } => by.forget(actor),
        }
    }
}
