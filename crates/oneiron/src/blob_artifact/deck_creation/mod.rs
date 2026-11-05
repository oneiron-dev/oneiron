//! Core half of `blob_artifact::deck_creation`: its store-layer items live in `oneiron_store::blob_artifact::deck_creation` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::blob_artifact::deck_creation::*;

use crate::blob_artifact::deck_creation::record::{
    ArtifactVersionRef, DeckCreationRecord, DesignSpec, EvidenceChange, KeptOutline,
    OutlineFreshness,
};
use crate::write_envelope::provenance::made_by::MadeByTrigger;
pub use oneiron_store::blob_artifact::deck_creation::outline;
pub use oneiron_store::blob_artifact::deck_creation::plan;
pub use oneiron_store::blob_artifact::deck_creation::record;
use outline::DeckOutline;
use plan::DeckPlanView;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod operations;
