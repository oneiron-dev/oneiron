use super::*;

use crate::agent_def::{AgentDefinition, AgentScope, encode_agent_definition};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
    claim_body_decode_count, decode_claim_body, reset_claim_body_decode_count,
};
use crate::connector_key::{
    ConnectorKeyStatus, EffectorBudgetChargeOutcome, EffectorBudgetOnExhaust,
};
use crate::context_pack::ContextEntity;
use crate::context_pack::ContextPack;
use crate::context_pack::PackItemAccounting;
use crate::context_pack::PackStats;
use crate::context_pack::PackTokenStats;
use crate::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyContactStatus, CounterpartyFirstTouch,
    CounterpartyOptOutReason,
};
use crate::edge::{EdgeActorClass, EdgeConfirmationStatus, EdgeKind, EdgeProvenanceFlags};
use crate::error::{ErrorKind, GateDenialOutcome, GateDenialReason};
use crate::pipeline::ScoredEntity;
use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use crate::receipt::{ReceiptKind, ReceiptQuery, StandingOutboundGrantsLensQuery};
use crate::registry::{ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON};
use crate::run_tree::{
    GATE_CONSENT_BUNDLE_FALLBACK_LABEL, GATE_CONSENT_BUNDLE_SCHEMA_VERSION, GateConsentBundleAction,
};
use crate::temporal::TimeRange;
use crate::write_envelope::ClaimCandidate;
use crate::write_envelope::WriteActor;
use crate::write_envelope::WriteProvenance;
use std::time::Duration;

use crate::test_util::{entity as test_id, entity_record, put_policy_manifest_bytes};

fn first_party_connector_actor_ref() -> String {
    super::first_party_connector_actor_ref()
}

mod pending_lookup;

#[path = "../repair_tests.rs"]
mod repair_tests;

mod actor_fork;
mod auto_checker;
mod budget_policy;
mod charter_ceiling;
mod claim_candidate_lineage;
mod connector_budget;
mod consent_bundle;
mod critical_confirm_index;
mod critical_confirm_lifecycle;
mod delegation;
mod dreamer_precommit;
mod effect_policy;
mod evaluator_core;
mod external_effect_grants;
mod gate_door;
mod isolation_persona;
mod manifest_auto;
mod policy_inputs;
mod posture_override;
mod scoped_read;
mod special_doors;
mod support;
mod trust_boundary;
mod vad_vetting;
mod witness_message;

#[path = "breaker.rs"]
mod breaker;

use charter_ceiling::scoped_capability_connector;
use connector_budget::{
    check_effect, connector_key_line_send_manifest, connector_key_two_verb_manifest, day_window,
};
use consent_bundle::{consent_bundle_owner, consent_bundle_receipts, park_consent_bundle_member};
use critical_confirm_lifecycle::{
    critical_confirm_owner_entry, critical_confirm_pending, put_critical_auto_claim,
};
use dreamer_precommit::{
    PRECOMMIT_EVIDENCE_REFS_KEY, PRECOMMIT_RUN_ID, precommit_body, precommit_evidence,
    seed_precommit_evidence_entity,
};
use effect_policy::{coalescing_effect_record, coalescing_ledger_in_txn};
use special_doors::gate_rejection_parts;
#[cfg(feature = "sync")]
use support::{
    access_grant_blob, authority_log_blob, federated_claim_update, policy_manifest_blob,
    source_trust_claim_data,
};
use support::{
    actor_ceiling_row, actor_ceiling_row_for_ref, agent_def_fixture, append_actor_ceiling,
    assert_auto_source_gate_rejected, assert_auto_source_rejected, assert_gate_rejected,
    assert_metric_counter_advanced, budgeted_core_read_scoped_grant_entry,
    check_external_effect_policy_with_budget, claim_candidate_from_body,
    claim_candidate_write_parts, claim_candidate_write_parts_for_actor,
    core_read_scoped_grant_entry, core_read_world_grant_manifest,
    dreamer_claim_candidate_write_parts, edge_provenance_flags,
    encode_first_party_default_policy_manifest, encode_policy_manifest, external_effect_gate_input,
    external_effect_scoped_grant_entry, first_party_connector_actor_id, gate_evaluator_input,
    gate_reason_strs, has_pending_gate_consent, pinned_actor_id, public_stamped, put_agent_def_row,
    put_claim_body, put_claim_text_body, put_dangling_short_id, put_malformed_access_grant_bytes,
    put_raw_entity_row, put_text_entity, put_vector_entity,
    receipt_required_core_read_scoped_grant_entry, replace_actor_ceilings, resolve,
    resolved_ceiling, rewrite_policy_manifest_entries, scoped_grants_entry, signatures_entry,
    source_trust_claim, source_trust_entry, source_trust_entry_without_auto_permit,
    stored_claim_body, sweep_id, temp_vault, test_time, trust_human_candidate_actor,
};
