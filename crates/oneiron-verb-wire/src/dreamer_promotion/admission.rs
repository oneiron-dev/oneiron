//! Moved from `crates/oneiron/src/dreamer_promotion/admission.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::claim_history_handoff::claim_consolidatable;
use oneiron_authority::claim_history_handoff::claim_evidence_admissible;
use oneiron_authority::claim_history_handoff::claim_generated_origin;
use oneiron_authority::claim_history_handoff::claim_surfaceable;
use oneiron_base::error::Result;
use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_base::registry::ENTITY_TYPE_PERSON;
use oneiron_base::registry::ENTITY_TYPE_SESSION;
use oneiron_base::registry::ENTITY_TYPE_TURN;
use oneiron_contracts::claim::ClaimApprovalStatus;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::consolidation_reader::ConsolidationReader;
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
