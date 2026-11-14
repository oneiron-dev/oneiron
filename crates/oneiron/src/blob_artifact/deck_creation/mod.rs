//! Typed outline approval, design and emission doors over the native deck engine.
mod operations;
pub use oneiron_store::blob_artifact::deck_creation::outline;
pub use oneiron_store::blob_artifact::deck_creation::plan;
pub use oneiron_store::blob_artifact::deck_creation::record;

use crate::blob_artifact::deck_creation::record::{
    ArtifactVersionRef, DeckCreationRecord, DesignSpec, EvidenceChange, KeptOutline,
    OutlineFreshness,
};
use crate::write_envelope::provenance::made_by::MadeByTrigger;
use oneiron_docedit::graphic::GraphicLimits;
use outline::DeckOutline;
use plan::DeckPlanView;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[doc(hidden)]
pub use oneiron_verb_wire::blob_artifact::deck_creation::{
    DeckDesignRequest, DeckDesignView, DeckEmissionNames, DeckEmissionOutcome, DeckEmissionRequest,
    DeckKeepBinding, DeckOutlineDeclined, DeckOutlineProposeRequest, DeckOutlineRefRequest,
    DeckOutlineSettleRequest, DeckOutlineView, DeckPresentation, KeptOutlineOmissionReason,
};
