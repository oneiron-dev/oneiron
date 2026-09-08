//! Claim write doors: policy gating for local claim writes.

mod breaker_staging;
mod claim_write;
mod consent;
mod dreamer_run;
mod peripheral;

use dreamer_run::pending_consent_dreamer_run_id;

pub(super) use breaker_staging::check_claim_policy_for_write_with_owner_bundle_replay;
pub(crate) use breaker_staging::{
    RecordedClaimGateDecision, apply_staged_claim_gate_in_txn,
    check_claim_policy_for_write_as_original_event,
};
// Doors-private names the record seam's `use super::*` glob reaches: they stay
// private imports here rather than `pub(super)` re-exports, which the
// compiler rejects for items narrower than the gate.
use claim_write::check_claim_policy_for_write_with_record_inner;
pub(crate) use claim_write::{
    check_claim_policy_for_write, check_claim_policy_for_write_with_preflight_decision,
    check_claim_policy_for_write_with_record,
};
pub(crate) use consent::claim_consent_binding_parts;
use consent::enforce_claim_gate_decision_with_consent;
pub(super) use consent::{
    GateConsentBinding, claim_gate_input, enforce_gate_decision,
    gate_decision_matches_pending_candidate,
};
pub(super) use dreamer_run::dreamer_run_id_from_write_envelope;
#[cfg(feature = "sync")]
pub(crate) use peripheral::check_federated_claim_admission;
pub(super) use peripheral::edge_actor_class_str;
use peripheral::write_envelope_actor_ref;
pub(crate) use peripheral::{
    ClaimGateWrite, GateWriteMode, check_edge_provenance_claim_policy, check_reserved_claim_policy,
    standing_outbound_grant_binding_parts, validate_write_envelope,
};

// The record seam's `use super::*` glob resolves through this module: the
// names below are the crate/super imports the pre-split doors.rs header
// provided to it, kept here so `breaker_staging.rs` stays byte-identical.
use super::decision::{GateDecision, GateOutcome, GateReasonCode, record_gate_decision_metrics};
use super::input::GateEvaluatorInput;
use super::resolution::{PolicyManifestResolution, check_claim_source_trust};
use crate::claim::{ClaimApprovalStatus, ClaimBody};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::store::{GateDecisionId, GateDecisionRecord, PendingGateConsentRecord, Store};
use crate::write_envelope::WriteEnvelope;
