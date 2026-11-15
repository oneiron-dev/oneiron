//! Moved from `crates/oneiron/src/blob_artifact/verbs.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::blob_artifact::verbs::ArtifactAdmitSubmit;
pub use oneiron_verb_wire::blob_artifact::verbs::ArtifactAskSubmit;
pub use oneiron_verb_wire::blob_artifact::verbs::ArtifactAskUnits;
pub use oneiron_verb_wire::blob_artifact::verbs::ArtifactExportRequest;
pub use oneiron_verb_wire::blob_artifact::verbs::ArtifactRefRequest;
pub use oneiron_verb_wire::blob_artifact::verbs::BornFromRequest;
pub use oneiron_verb_wire::blob_artifact::verbs::DeckProposeRequest;
pub use oneiron_verb_wire::blob_artifact::verbs::FolderItemInput;
pub use oneiron_verb_wire::blob_artifact::verbs::NativeOutputRequest;
pub use oneiron_verb_wire::blob_artifact::verbs::ProposalSettleRequest;
pub use oneiron_verb_wire::blob_artifact::verbs::SlideReviewSubmit;
pub use oneiron_verb_wire::blob_artifact::verbs::SlideReviewUnitInput;
pub use oneiron_verb_wire::blob_artifact::verbs::SlideUnitRefused;
use serde::Deserialize;
use serde::Serialize;

/// Whether a held organ call was let go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedWait {
    pub released: bool,
}
