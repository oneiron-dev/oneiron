//! Moved from `crates/oneiron/src/typed_body/body_actor.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::typed_body::TypedForkState;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_store::typed_body::body_actor::*;

impl TypedForkState {
    /// Makes the one who settled the fork no one when it is `actor`; whether
    /// it was.
    fn forget(&mut self, actor: EntityId) -> bool {
        match self {
            Self::Open => false,
            Self::Merged { by, .. } | Self::Discarded { by, .. } => by.forget(actor),
        }
    }
}
