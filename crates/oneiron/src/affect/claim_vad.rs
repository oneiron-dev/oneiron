//! Claim VAD records and aggregation are defined in core write vocabulary.

pub use crate::write_envelope::claim_vad::{
    CLAIM_VAD_REAPPRAISAL_PREDICATE, ClaimVadConsolidation, ClaimVadReappraisal,
    ClaimVadTurnEvidence,
};
pub(super) use crate::write_envelope::claim_vad::{
    claim_vad_evidence_value, claim_vad_value, collect_claim_turn_evidence_refs, mean_vad,
};
