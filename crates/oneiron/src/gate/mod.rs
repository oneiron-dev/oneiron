//! DEC-0005 Gate policy manifest resolver.
//!
//! GATE-001 added stable decision inputs. GATE-002 routes local write doors
//! through the evaluator while keeping replicated replay trust-blind.

mod bundle;
mod ceiling;
mod confirm;
mod constants;
mod decision;
mod decode;
mod default_manifest;
mod definition_ceiling;
mod doors;
mod effect;
mod grants;
mod input;
mod resolution;

#[cfg(test)]
mod tests;

pub(crate) use self::ceiling::{
    OwnerRowAction, PolicyApprovalCeiling, dispatched_agent_effective_ceiling,
};
pub use self::confirm::{
    CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS, CriticalWriteConfirmBinding,
    CriticalWriteConfirmResolution, GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED,
    GATE_REASON_CRITICAL_CONFIRM_DECLINED, GATE_REASON_CRITICAL_CONFIRM_TIMEOUT,
};
pub(crate) use self::confirm::{
    critical_write_confirm_binding, reconcile_critical_write_confirm_on_replicated_overwrite,
};
#[cfg(test)]
pub(crate) use self::constants::{
    FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID, POLICY_LEGAL_FLOOR_ROWS_KEY,
    POLICY_OWNER_POLICY_DOCUMENT_KEY, POLICY_OWNER_POLICY_ENABLED_KEY,
    POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY, POLICY_OWNER_POLICY_PATTERNS_KEY,
    POLICY_OWNER_POLICY_ROWS_KEY, POLICY_ROW_ACTION_KEY, POLICY_ROW_ACTIVE_KEY, POLICY_ROW_REF_KEY,
    POLICY_ROW_TEXT_KEY, POLICY_ROW_WORLD_REF_KEY,
};
pub(crate) use self::constants::{POLICY_SCHEMA_VERSION, SCOPED_READ_EFFECTOR_CORE_READ};
#[cfg(test)]
pub(crate) use self::decision::gate_metric_emission_count_for_test;
pub(crate) use self::decision::{GateDecision, GateOutcome, GateReasonCode};
pub(crate) use self::default_manifest::{
    DEFAULT_POLICY_MANIFEST_TIMESTAMP, default_policy_manifest, default_policy_manifest_id,
};
pub(crate) use self::definition_ceiling::agent_definition_ceiling_for_actor;
#[cfg(test)]
pub(crate) use self::definition_ceiling::first_party_eiri_connector_actor_ref;
#[cfg(feature = "sync")]
pub(crate) use self::doors::check_federated_claim_admission;
pub(crate) use self::doors::{
    ClaimGateWrite, GateWriteMode, RecordedClaimGateDecision, check_claim_policy_for_write,
    check_claim_policy_for_write_with_preflight_decision, check_claim_policy_for_write_with_record,
    check_edge_provenance_claim_policy, check_reserved_claim_policy, claim_consent_binding_parts,
    standing_outbound_grant_binding_parts, validate_write_envelope,
};
#[cfg(test)]
pub(crate) use self::effect::scoped_mcp_credential_connector_key;
pub(crate) use self::effect::{
    ExternalEffectGovernance, check_external_effect_policy, evaluate_external_effect_policy,
    is_scoped_capability_connector_key, record_external_effect_policy,
};
pub(crate) use self::grants::{
    PolicyScopedGrant, companion_profile_access_grant, scoped_read_claim_allowed,
};
pub(crate) use self::input::{
    ConsentGateContext, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor,
    GateProvenanceHandles, consent_gate_reason_codes,
};
pub(crate) use self::resolution::{PolicyManifestResolution, resolve_policy_manifest};

// gate.rs was one flat module: its private `use` header and every item in it
// were in scope for the inline test module through `use super::*`. After the
// directory split the seam re-imports both so the sibling `tests.rs` resolves
// exactly as it did before.
#[cfg(test)]
use self::ceiling::*;
#[cfg(test)]
use self::confirm::*;
#[cfg(test)]
use self::constants::*;
#[cfg(test)]
use self::decision::*;
#[cfg(test)]
use self::decode::*;
#[cfg(test)]
use self::effect::*;
#[cfg(test)]
use self::grants::*;
#[cfg(test)]
use self::input::*;
#[cfg(test)]
use self::resolution::*;
#[cfg(test)]
use crate::agent_def::AgentCeiling;
#[cfg(test)]
use crate::authority::CriticalWriteConfirmDisposition;
#[cfg(test)]
use crate::batch::EntityMetadataHeader;
#[cfg(test)]
use crate::claim::ClaimSource;
#[cfg(test)]
use crate::connector_key::EffectorBudgetCharge;
#[cfg(test)]
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
#[cfg(test)]
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
#[cfg(test)]
use crate::error::{Error, Result};
#[cfg(test)]
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
#[cfg(test)]
use crate::llm::{BudgetExhaustionPolicy, BudgetPolicySelector, CallPurpose};
#[cfg(test)]
use crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT;
#[cfg(test)]
use crate::registry::{
    ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_OUTBOUND_GRANT,
    ENTITY_TYPE_POLICY_MANIFEST,
};
#[cfg(test)]
use crate::store::{GateDecisionId, GateDecisionRecord, PendingGateConsentRecord, Store};
#[cfg(test)]
use crate::write_envelope::WriteEnvelope;
#[cfg(test)]
use rmpv::Value;
#[cfg(test)]
use std::io::Cursor;
