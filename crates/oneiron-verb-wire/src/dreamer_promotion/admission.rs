//! Moved from `crates/oneiron/src/dreamer_promotion/admission.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_store::write_envelope::claim_body::CursorSpan;
pub use oneiron_store::write_envelope::claim_body::EvidenceKind;
pub use oneiron_store::write_envelope::claim_body::EvidenceRef;
pub(crate) use oneiron_store::write_envelope::claim_body::public_evidence_refs;
pub(crate) use oneiron_store::write_envelope::claim_body::public_evidence_value;
use serde::Deserialize;
use serde::Serialize;

/// Why a visible source does not corroborate a generated claim. These are
/// evidence decisions, never an outbound authorization or a consent grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PromotionEvidenceReason {
    Missing,
    NotEvidence,
    NotSurfaceable,
    UnvettedGenerated,
    UnvettedTaint,
    GeneratedOrigin,
    PendingCriticalConfirmation,
    UnsupportedTurnRole,
}
