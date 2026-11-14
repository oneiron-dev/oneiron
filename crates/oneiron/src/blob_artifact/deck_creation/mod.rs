//! Typed outline approval, design and emission doors over the native deck engine.
mod operations;
pub use oneiron_store::blob_artifact::deck_creation::outline;
pub use oneiron_store::blob_artifact::deck_creation::plan;
pub use oneiron_store::blob_artifact::deck_creation::record;

use crate::blob_artifact::deck_creation::record::{ArtifactVersionRef, KeptOutline};
use outline::DeckOutline;
use plan::DeckPlanView;
use serde::Serialize;

#[doc(hidden)]
pub use oneiron_verb_wire::blob_artifact::deck_creation::{
    DeckDesignRequest, DeckDesignView, DeckEmissionNames, DeckEmissionOutcome, DeckEmissionRequest,
    DeckKeepBinding, DeckOutlineDeclined, DeckOutlineProposeRequest, DeckOutlineRefRequest,
    DeckOutlineSettleRequest, DeckOutlineView, DeckPresentation, KeptOutlineOmissionReason,
};
