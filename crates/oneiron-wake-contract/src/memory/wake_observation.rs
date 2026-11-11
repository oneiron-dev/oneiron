//! Moved from `crates/oneiron/src/memory/wake_observation.rs` (core split slice 3: wake contract below core).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::attempt_id::AttemptId;
use serde::Deserialize;
use serde::Serialize;

/// One wake pass's observation handle: the store-issued id its rows are
/// keyed by. A pass, never a recipe, attempt or budget id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WakeRef(pub EntityId);

impl WakeRef {
    /// The pass a stored id names.
    #[must_use]
    pub const fn from_entity_id(id: EntityId) -> Self {
        Self(id)
    }

    /// The id the pass's rows are keyed by.
    #[must_use]
    pub const fn entity_id(self) -> EntityId {
        self.0
    }
}

/// Why a pass authored its claims single-pass under a promoted
/// claim-authoring default (FIX 897). Never a refusal: the pass ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimAuthoringFallback {
    /// Several bound campaigns carry the default, in root order; none is
    /// chosen for the host (Engine 10-18).
    AmbiguousCampaigns { roots: Vec<AttemptId> },
}
