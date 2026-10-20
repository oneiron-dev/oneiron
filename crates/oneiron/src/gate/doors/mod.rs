//! Claim write doors: policy gating for local claim writes.

mod burst_inputs;
mod claim_write;
mod consent;
mod dreamer_run;
mod peripheral;
mod recorded;

pub(crate) use claim_write::{
    check_claim_policy_for_write, check_claim_policy_for_write_with_preflight_decision,
    check_claim_policy_for_write_with_record, claim_source_trust_admits_auto,
};
pub(super) use consent::{
    GateConsentBinding, claim_gate_input, enforce_gate_decision,
    gate_decision_matches_pending_candidate,
};
pub(crate) use consent::{claim_consent_binding_parts, external_effect_decision_on};
#[cfg(test)]
pub(super) use dreamer_run::dreamer_run_id_from_write_envelope;
#[cfg(feature = "sync")]
pub(crate) use peripheral::check_federated_claim_admission;
pub(super) use peripheral::edge_actor_class_str;
pub(crate) use peripheral::{
    ClaimGateWrite, GateWriteMode, check_edge_provenance_claim_policy, check_reserved_claim_policy,
    check_unattributed_claim_lineage, standing_outbound_grant_binding_parts,
    validate_write_envelope,
};
pub(crate) use recorded::RecordedClaimGateDecision;
