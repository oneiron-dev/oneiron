//! DEC-0005 Gate policy manifest resolver.
//!
//! GATE-001 added stable decision inputs. GATE-002 routes local write doors
//! through the evaluator while keeping replicated replay trust-blind.

mod ask_policy;
mod auto_signals;
mod bundle;
mod ceiling;
pub(crate) mod class_policy;
pub(crate) mod manifest_authenticity;
#[cfg(test)]
pub(crate) use manifest_authenticity::stamp_manifest_origin;
pub(crate) use manifest_authenticity::{seeded_manifest_key, trusted_manifest_key};
mod carry_forward_policy;
mod confirm;
mod connector_admission;
mod constants;
mod decision;
mod decode;
mod default_manifest;
mod definition_ceiling;
mod docedit_resource;
pub(crate) use docedit_resource::shipped_docedit_package_limits;
mod docx_budget;
mod doors;
mod dreamer_precommit;
mod effect;
pub(crate) mod fanout_policy;
mod foreign_agent;
mod grants;
mod hosted_tts_policy;
mod input;
pub(crate) mod mail_policy;
mod operational_policy;
mod owner_policy_mutation;
mod pack_install_policy;
pub(crate) mod policy_values;
mod project_conversion;
pub(crate) mod project_depth;
pub(crate) mod proposal_observation;
mod repair;
mod resolution;
mod tracker_limits;
pub use tracker_limits::LiveQueryTrackerLimits;
mod retrieval_filter;
pub(crate) mod retrieval_retention;
pub(crate) mod retry_source_policy;
mod room_policy;
mod room_thread;
#[cfg(feature = "test-support")]
mod run_proposal_fixture;
pub use room_thread::RoomThreadFill;
pub(crate) use room_thread::{RoomThreadManifest, RoomThreadSettings};
mod share;
mod skill_edit_goal_policy;
mod skill_tradeoff_policy;
pub(crate) mod voice_serving;
mod weave_correction_policy;
pub(crate) mod weave_policy;
mod witness_message;
pub(crate) use weave_correction_policy::WeaveCorrectionPolicy;

#[cfg(test)]
mod tests;

pub(crate) use self::ask_policy::{AskOperationalPolicy, AskPolicySurface};
pub use self::bundle::{
    GATE_BUNDLE_CONTENT_KIND, GATE_BUNDLE_OUTCOME_APPROVED, GATE_BUNDLE_OUTCOME_DECLINED,
    GATE_BUNDLE_REASON_APPROVED, GATE_BUNDLE_REASON_DECLINED,
};
pub(crate) use self::ceiling::{
    OwnerRowAction, PolicyApprovalCeiling, PolicyCriticality, dispatched_agent_effective_ceiling,
};
pub use self::confirm::{
    CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS, CriticalWriteConfirmBinding,
    CriticalWriteConfirmResolution, GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED,
    GATE_REASON_CRITICAL_CONFIRM_DECLINED, GATE_REASON_CRITICAL_CONFIRM_TIMEOUT,
};
pub(crate) use self::confirm::{
    critical_write_confirm_binding, reconcile_critical_write_confirm_on_replicated_overwrite,
};
pub(crate) use self::connector_admission::ConnectorAdmissionQuotas;
pub(crate) use self::constants::POLICY_OWNER_POLICY_NOTIFY_KEY;
#[cfg(test)]
pub(crate) use self::constants::{
    FIRST_PARTY_CONNECTOR_ACTOR_ID, POLICY_OWNER_POLICY_DOCUMENT_KEY,
    POLICY_OWNER_POLICY_ENABLED_KEY, POLICY_OWNER_POLICY_OUTPUT_CONTRACT_KEY,
    POLICY_OWNER_POLICY_PATTERNS_KEY, POLICY_OWNER_POLICY_ROWS_KEY, POLICY_PPTX_COMMENT_LIMITS_KEY,
    POLICY_ROW_ACTION_KEY, POLICY_ROW_ACTIVE_KEY, POLICY_ROW_REF_KEY, POLICY_ROW_TEXT_KEY,
    POLICY_ROW_WORLD_REF_KEY,
};
pub(crate) use self::constants::{
    POLICY_CONSULT_FANOUT_APPROVAL_THRESHOLD_KEY, POLICY_CONSULT_FANOUT_CONTROLS_KEY,
    POLICY_CONSULT_FANOUT_SCOPE_ROWS_KEY,
};
pub(crate) use self::constants::{
    POLICY_SCHEMA_VERSION, POLICY_SHARED_ACT_POLICIES_KEY, SCOPED_READ_EFFECTOR_CORE_READ,
};
#[cfg(test)]
pub(crate) use self::decision::gate_metric_emission_count_for_test;
pub(crate) use self::decision::{GateDecision, GateMetrics, GateOutcome, GateReasonCode};
pub(crate) use self::decode::normalize_policy_manifest_scope;
#[cfg(test)]
pub(crate) use self::default_manifest::default_consult_fanout_approval_threshold;
pub(crate) use self::default_manifest::{
    DEFAULT_POLICY_MANIFEST_TIMESTAMP, default_consult_fanout_policy, default_policy_manifest,
    default_policy_manifest_id, seeded_project_depth_default,
};
#[cfg(test)]
pub(crate) use self::definition_ceiling::first_party_connector_actor_ref;
pub(crate) use self::definition_ceiling::{
    agent_definition_ceiling_for_actor, definition_only_ceiling_for_actor,
};
#[cfg(feature = "sync")]
pub(crate) use self::doors::check_federated_claim_admission;
pub(crate) use self::doors::{
    ClaimGateWrite, GateWriteMode, RecordedClaimGateDecision, check_claim_policy_for_write,
    check_claim_policy_for_write_with_preflight_decision, check_claim_policy_for_write_with_record,
    check_edge_provenance_claim_policy, check_reserved_claim_policy, claim_consent_binding_parts,
    standing_outbound_grant_binding_parts, validate_write_envelope,
};
pub(crate) use self::foreign_agent::{
    introduced_foreign_agents, resolve as resolve_foreign_agent_ceiling,
};
pub use self::pack_install_policy::PackInstallPolicyOverride;
pub(crate) use self::pack_install_policy::{
    EffectivePackInstallPolicy, HolderInstallRow, PackInstallPolicy, PackInstallRuleRow,
};
// The validator itself is reached through the write door; the direct
// visibility below exists for the tests that pin its checks in isolation.
#[cfg(test)]
use self::dreamer_precommit::{
    DREAMER_DEGENERATE_VALUE_PREFIXES, DREAMER_RUNTIME_RECORD_PREDICATES, DreamerPrecommitInput,
    validate_dreamer_precommit,
};
pub(crate) use self::effect::{
    ApprovalContext, ExternalEffectGovernance, check_external_effect_policy,
    check_external_effect_policy_pair, counterparty_send_override_in_txn,
    evaluate_external_effect_policy, external_effect_approval_digest,
    hydrate_external_effect_contact, native_mail_cold_approval_digest,
    record_external_effect_policy,
};
pub(crate) use self::grants::{
    PolicyScopedGrant, companion_profile_access_grant, scoped_read_claim_allowed,
    scoped_read_record_allowed,
};
pub(crate) use self::hosted_tts_policy::{HostedTtsLimits, resolve_hosted_tts_limits};
pub(crate) use self::input::{
    ConsentGateContext, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor,
    GateProvenanceHandles, consent_gate_reason_codes,
};
#[cfg(test)]
pub(crate) use self::operational_policy::default_manifest_with_linear_sync_pages_for_test;
pub(crate) use self::operational_policy::{
    LinearMirrorPolicy, LinearSyncBudget, WaveHandoffPolicy,
};
pub(crate) use self::owner_policy_mutation::apply_owner_policy_row_change_in_txn;
pub use self::owner_policy_mutation::{
    PolicyRowAction, PolicyRowChange, PolicyRowScope, PolicyWhySource,
};
pub(crate) use self::project_conversion::{
    LeaderFallback, ProjectConversionPolicy, RosterSelection, TaskHolderFallback,
};
pub(crate) use self::repair::{evaluate_repair_consent, repair_criticality};
pub(crate) use self::resolution::{
    GateDecisionRetentionPolicy, GateRetentionContext, LeaderChatDefault, PolicyManifestResolution,
    ProjectWidenAskFallback, ResidenceOperationBudgetLimits, ResidenceOperationBudgetPrecedence,
    ResidenceOperationBudgetRow, resolve_credential_lifetimes, resolve_gate_decision_retention,
    resolve_policy_manifest, resolve_project_depth_max, retention_edit_target,
};
pub use self::retrieval_filter::RetrievalFilter;
pub(crate) use self::retrieval_filter::{
    ResolvedRetrievalFilter, RetrievalPolicyFloor, narrow_retrieval_filter,
};
pub(crate) use self::room_policy::{RoomAction, allows as room_policy_allows};
pub(crate) use self::share::check_share_create_policy;
#[cfg(test)]
pub(crate) use self::share::share_create_effect;
pub(crate) use self::skill_edit_goal_policy::SkillEditGoalPolicy;
pub(crate) use self::skill_tradeoff_policy::{SkillTradeoffLimits, skill_tradeoff_limits_in_txn};
pub(crate) use self::voice_serving::VoiceServingLimits;
#[cfg(test)]
pub(crate) use self::witness_message::canonical_witness_message_body_for_test;
pub(crate) use self::witness_message::{
    MAX_WITNESS_MESSAGE_ORDER, WITNESS_AUTHOR_COMPANION, WITNESS_AUTHOR_SYSTEM,
    WITNESS_AUTHOR_USER, WitnessMessageAuthorization, WitnessMessageEnvelope,
    check_witness_message_ceiling, validate_canonical_witness_message_body,
    validate_replicated_witness_message_body,
};

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
