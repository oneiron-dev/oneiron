//! DEC-0005 Gate policy manifest resolver.
//!
//! GATE-001 added stable decision inputs. GATE-002 routes local write doors
//! through the evaluator while keeping replicated replay trust-blind.

use std::cmp::Ordering;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimSource, ScopedReadActorKey, claim_sensitivity_band,
    sensitivity_band_from_value,
};
use crate::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyFirstTouch, counterparty_contact_index_key,
    decode_counterparty_contact_body, decode_counterparty_contact_index_value,
};
use crate::dreamer_runner::DREAMER_RUNNER_JOB_KIND;
use crate::error::{Error, Result};
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::llm::BudgetExhaustionPolicy;
use crate::outbound_grant::{
    StandingOutboundGrant, decode_standing_outbound_grant_body,
    encode_standing_outbound_grant_body, standing_outbound_grant_principal_index_entity_id,
    standing_outbound_grant_principal_index_prefix,
};
use crate::provenance::PREDICATE_EDGE_PROVENANCE;
use crate::store::{GateDecisionId, GateDecisionRecord, PendingGateConsentRecord, Store};
use crate::types::{
    ENTITY_ID_LEN, ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_COUNTERPARTY_CONTACT,
    ENTITY_TYPE_OUTBOUND_GRANT, ENTITY_TYPE_POLICY_MANIFEST, EdgeActorClass, EntityId,
    WriteEnvelope, bytes_to_hex_lower,
};

const POLICY_SCHEMA_VERSION_KEY: &str = "schema_version";
const POLICY_SCHEMA_VERSION: &str = "1.1";
const POLICY_PACK_ID_KEY: &str = "pack_id";
const POLICY_PACK_VERSION_KEY: &str = "pack_version";
const POLICY_MIN_ENGINE_VERSION_KEY: &str = "min_engine_version";
const POLICY_DEFAULTS_KEY: &str = "defaults";
const POLICY_RULES_KEY: &str = "rules";
const POLICY_ACTOR_CEILINGS_KEY: &str = "actor_ceilings";
const POLICY_SOURCE_TRUST_KEY: &str = "source_trust";
const POLICY_SCOPED_GRANTS_KEY: &str = "scoped_grants";
const POLICY_SIGNATURE_KEY: &str = "signature";
const POLICY_SIGNATURES_KEY: &str = "signatures";
const POLICY_ON_BUDGET_EXHAUSTED_KEY: &str = "on_budget_exhausted";
pub(crate) const POLICY_LEGAL_FLOOR_ROWS_KEY: &str = "legal_floor_rows";
pub(crate) const POLICY_OWNER_POLICY_ROWS_KEY: &str = "owner_policy_rows";

const AXIS_CRITICALITY_KEY: &str = "criticality";
const AXIS_SENSITIVITY_KEY: &str = "sensitivity";
const RULE_PREFIX_KEY: &str = "prefix";
const RULE_EXACT_KEY: &str = "exact";
const RULE_AXES_KEY: &str = "axes";
const ACTOR_CLASS_KEY: &str = "actor_class";
const ACTOR_REF_KEY: &str = "actor_ref";
const DREAMER_PROVENANCE_RUN_ID_KEY: &str = "run_id";
const DREAMER_PROVENANCE_RUN_KEY: &str = "run";
const DREAMER_PROVENANCE_RUNNER_KEY: &str = "runner";
const DREAMER_PROVENANCE_SURFACE_KEY: &str = "surface";
const ACTOR_CEILING_KEY: &str = "ceiling";
const SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY: &str = "max_auto_sensitivity";
const SOURCE_TRUST_AUTO_KEY: &str = "auto";
const SOURCE_TRUST_RECEIPTED_KEY: &str = "receipted";
const SOURCE_TRUST_WARNED_KEY: &str = "warned";
const GRANT_EFFECTOR_KEY: &str = "effector";
const GRANT_SCOPE_KEY: &str = "scope";
const GRANT_BUDGET_KEY: &str = "budget";
const GRANT_RECEIPT_REQUIRED_KEY: &str = "receipt_required";
pub(crate) const SCOPED_READ_EFFECTOR_CORE_READ: &str = "core:read";
const SCOPED_READ_EFFECTOR_ONEIRON_READ: &str = "oneiron.read";
const EXTERNAL_EFFECT_EFFECTOR_PREFIX: &str = "external:";
const EXTERNAL_EFFECT_EFFECTOR_LONG_PREFIX: &str = "external_effect:";
const EXTERNAL_EFFECT_SCOPE_VERB_KEY: &str = "verb";
const EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY: &str = "channel";
const EXTERNAL_EFFECT_SCOPE_CHANNEL_REF_KEY: &str = "channel_ref";
const EXTERNAL_EFFECT_SCOPE_CHANNEL_REF_CAMEL_KEY: &str = "channelRef";
const EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY: &str = "policy_risk";
const EXTERNAL_EFFECT_SCOPE_POLICY_RISK_CAMEL_KEY: &str = "policyRisk";
const EXTERNAL_EFFECT_WILDCARD: &str = "*";
const SIGNATURE_ALG_KEY: &str = "alg";
const SIGNATURE_KEY_ID_KEY: &str = "key_id";
const SIGNATURE_SIG_KEY: &str = "sig";
const SIGNATURE_SIGNATURE_KEY: &str = "signature";
pub(crate) const POLICY_ROW_REF_KEY: &str = "row_ref";
pub(crate) const POLICY_ROW_TEXT_KEY: &str = "text";
pub(crate) const POLICY_ROW_ACTIVE_KEY: &str = "active";
pub(crate) const POLICY_ROW_CATEGORY_KEY: &str = "category";
pub(crate) const POLICY_ROW_SUBCATEGORY_KEY: &str = "subcategory";
pub(crate) const POLICY_ROW_ACTION_KEY: &str = "action";
pub(crate) const POLICY_ROW_WORLD_REF_KEY: &str = "world_ref";
pub(crate) const POLICY_ROW_BLOCK_KEY: &str = "block";
// Legacy generic claim puts do not carry an actor-bound handle yet. Treat
// those local storage doors as first-party engine writes until a future
// actor-bound generic claim API can supply per-caller Gate inputs.
const LOCAL_WRITE_ACTOR_CLASS: &str = "first_party";
const LOCAL_WRITE_ACTOR_ENTITY_REF: [u8; ENTITY_ID_LEN] = [0x47; ENTITY_ID_LEN];
pub(crate) const FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID: [u8; ENTITY_ID_LEN] = [0xE1; ENTITY_ID_LEN];
const DEFAULT_POLICY_MANIFEST_ID: [u8; ENTITY_ID_LEN] = [0xD7; ENTITY_ID_LEN];
pub(crate) const DEFAULT_POLICY_MANIFEST_TIMESTAMP: u64 = 0;
const GATE_METRIC_OUTCOME_COUNT: usize = 3;
const GATE_METRIC_REASON_CLASS_COUNT: usize = 11;

static GATE_METRIC_COUNTERS: [[AtomicU64; GATE_METRIC_REASON_CLASS_COUNT];
    GATE_METRIC_OUTCOME_COUNT] = [const { [const { AtomicU64::new(0) }; GATE_METRIC_REASON_CLASS_COUNT] };
    GATE_METRIC_OUTCOME_COUNT];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyApprovalCeiling {
    Auto,
    Proposed,
}

impl PolicyApprovalCeiling {
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "auto" => Some(Self::Auto),
            "proposed" => Some(Self::Proposed),
            _ => None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn restrict(self, other: Self) -> Self {
        if matches!(self, Self::Proposed) || matches!(other, Self::Proposed) {
            Self::Proposed
        } else {
            Self::Auto
        }
    }
}

#[must_use]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn foreign_agent_effective_ceiling(
    confirmed_scope: PolicyApprovalCeiling,
    introducer_ceiling: PolicyApprovalCeiling,
) -> PolicyApprovalCeiling {
    confirmed_scope.restrict(introducer_ceiling)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyCriticality {
    Normal,
    Critical,
}

impl PolicyCriticality {
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "normal" => Some(Self::Normal),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicySensitivity {
    Normal,
    Sensitive,
}

impl PolicySensitivity {
    fn parse(value: &Value) -> Option<Self> {
        match value.as_str()? {
            "normal" => Some(Self::Normal),
            "sensitive" => Some(Self::Sensitive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PolicyAxes {
    criticality: Option<PolicyCriticality>,
    sensitivity: Option<PolicySensitivity>,
    unknown_axis_seen: bool,
}

impl PolicyAxes {
    #[cfg_attr(not(test), allow(dead_code))]
    fn restrict(self, other: Self) -> Self {
        Self {
            criticality: restrict_optional(self.criticality, other.criticality),
            sensitivity: restrict_optional(self.sensitivity, other.sensitivity),
            unknown_axis_seen: self.unknown_axis_seen || other.unknown_axis_seen,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyRule {
    prefix: String,
    exact: bool,
    axes: PolicyAxes,
}

impl PolicyRule {
    fn matches(&self, predicate: &str) -> bool {
        if self.exact {
            predicate == self.prefix
        } else {
            predicate.starts_with(&self.prefix)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyPack {
    _pack_id: String,
    _pack_version: String,
    _min_engine_version: String,
    defaults: PolicyAxes,
    rules: Vec<PolicyRule>,
}

impl PolicyPack {
    #[cfg_attr(not(test), allow(dead_code))]
    fn axes_for_predicate(&self, predicate: &str) -> PolicyAxes {
        let mut best_len = 0usize;
        let mut resolved = self.defaults;

        for rule in &self.rules {
            if rule.matches(predicate) {
                match rule.prefix.len().cmp(&best_len) {
                    Ordering::Greater => {
                        best_len = rule.prefix.len();
                        resolved = rule.axes;
                    }
                    Ordering::Equal => {
                        resolved = resolved.restrict(rule.axes);
                    }
                    Ordering::Less => {}
                }
            }
        }

        resolved
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActorCeiling {
    actor_class: String,
    actor_ref: Option<String>,
    ceiling: PolicyApprovalCeiling,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateActor {
    pub(crate) actor_class: String,
    pub(crate) actor_ref: Option<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateContentKind {
    Claim,
    EdgeProvenanceClaim,
    PolicyManifest,
    ExternalEffect,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateContentKind {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Claim => "claim",
            Self::EdgeProvenanceClaim => "edge_provenance_claim",
            Self::PolicyManifest => "policy_manifest",
            Self::ExternalEffect => "external_effect",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GateProvenanceHandles {
    pub(crate) actor_entity_ref: Option<EntityId>,
    pub(crate) substrate_ref: Option<EntityId>,
    pub(crate) source_revision_ref: Option<[u8; ENTITY_ID_LEN]>,
    pub(crate) body_snapshot_ref: Option<[u8; ENTITY_ID_LEN]>,
    pub(crate) dreamer_run_id: Option<String>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateEvaluatorInput {
    pub(crate) actor: GateActor,
    pub(crate) source: Option<ClaimSource>,
    pub(crate) content_kind: GateContentKind,
    pub(crate) sensitivity_band: Option<u8>,
    pub(crate) criticality: PolicyCriticality,
    pub(crate) policy_manifest_version: String,
    pub(crate) provenance: GateProvenanceHandles,
    pub(crate) external_effect: Option<ExternalEffectGateContext>,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ExternalEffectPolicyRisk {
    #[default]
    Normal,
    HoldToProposal,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ExternalEffectPolicyRisk {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::HoldToProposal => "hold_to_proposal",
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalEffectGateContext {
    pub(crate) verb: String,
    pub(crate) channel: String,
    pub(crate) channel_identity_ref: Option<EntityId>,
    pub(crate) counterparty: Option<String>,
    pub(crate) brief_ref: Option<String>,
    pub(crate) send_ref: Option<String>,
    pub(crate) standing_grant_ref: Option<String>,
    pub(crate) counterparty_first_touch: Option<CounterpartyFirstTouch>,
    pub(crate) counterparty_opted_out: bool,
    pub(crate) counterparty_opt_out_receipt_reason: Option<&'static str>,
    pub(crate) has_opted_in: bool,
    pub(crate) has_permission: bool,
    pub(crate) policy_risk: ExternalEffectPolicyRisk,
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExternalEffectGateInput {
    pub(crate) actor: GateActor,
    pub(crate) provenance: GateProvenanceHandles,
    pub(crate) verb: String,
    pub(crate) channel: String,
    pub(crate) channel_identity_ref: Option<EntityId>,
    pub(crate) counterparty: Option<String>,
    pub(crate) brief_ref: Option<String>,
    pub(crate) send_ref: Option<String>,
    pub(crate) standing_grant_ref: Option<String>,
    pub(crate) counterparty_first_touch: Option<CounterpartyFirstTouch>,
    pub(crate) counterparty_opted_out: bool,
    pub(crate) counterparty_opt_out_receipt_reason: Option<&'static str>,
    pub(crate) has_opted_in: bool,
    pub(crate) has_permission: bool,
    pub(crate) policy_risk: ExternalEffectPolicyRisk,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ExternalEffectGateInput {
    fn gate_input(&self) -> GateEvaluatorInput {
        GateEvaluatorInput {
            actor: self.actor.clone(),
            source: None,
            content_kind: GateContentKind::ExternalEffect,
            sensitivity_band: None,
            criticality: PolicyCriticality::Normal,
            policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
            provenance: self.provenance.clone(),
            external_effect: Some(ExternalEffectGateContext {
                verb: self.verb.clone(),
                channel: self.channel.clone(),
                channel_identity_ref: self.channel_identity_ref,
                counterparty: self.counterparty.clone(),
                brief_ref: self.brief_ref.clone(),
                send_ref: self.send_ref.clone(),
                standing_grant_ref: self.standing_grant_ref.clone(),
                counterparty_first_touch: self.counterparty_first_touch,
                counterparty_opted_out: self.counterparty_opted_out,
                counterparty_opt_out_receipt_reason: self.counterparty_opt_out_receipt_reason,
                has_opted_in: self.has_opted_in,
                has_permission: self.has_permission,
                policy_risk: self.policy_risk,
            }),
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateOutcome {
    Allow,
    Pending,
    Deny,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateOutcome {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Pending => "pending",
            Self::Deny => "deny",
        }
    }

    const fn metric_index(self) -> usize {
        match self {
            Self::Allow => 0,
            Self::Pending => 1,
            Self::Deny => 2,
        }
    }

    const fn metric_values() -> [Self; GATE_METRIC_OUTCOME_COUNT] {
        [Self::Allow, Self::Pending, Self::Deny]
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateMetricReasonClass {
    Allow,
    MissingActorClass,
    MissingActorProvenance,
    MissingPolicyManifestVersion,
    PolicyFailClosed,
    ActorCeiling,
    SourceTrust,
    CriticalityFloor,
    PolicyManifestAuthority,
    ExternalEffectAuthority,
    CounterpartyOptOut,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateMetricReasonClass {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::MissingActorClass => "missing_actor_class",
            Self::MissingActorProvenance => "missing_actor_provenance",
            Self::MissingPolicyManifestVersion => "missing_policy_manifest_version",
            Self::PolicyFailClosed => "policy_fail_closed",
            Self::ActorCeiling => "actor_ceiling",
            Self::SourceTrust => "source_trust",
            Self::CriticalityFloor => "criticality_floor",
            Self::PolicyManifestAuthority => "policy_manifest_authority",
            Self::ExternalEffectAuthority => "external_effect_authority",
            Self::CounterpartyOptOut => "counterparty_opt_out",
        }
    }

    const fn metric_index(self) -> usize {
        match self {
            Self::Allow => 0,
            Self::MissingActorClass => 1,
            Self::MissingActorProvenance => 2,
            Self::MissingPolicyManifestVersion => 3,
            Self::PolicyFailClosed => 4,
            Self::ActorCeiling => 5,
            Self::SourceTrust => 6,
            Self::CriticalityFloor => 7,
            Self::PolicyManifestAuthority => 8,
            Self::ExternalEffectAuthority => 9,
            Self::CounterpartyOptOut => 10,
        }
    }

    const fn metric_values() -> [Self; GATE_METRIC_REASON_CLASS_COUNT] {
        [
            Self::Allow,
            Self::MissingActorClass,
            Self::MissingActorProvenance,
            Self::MissingPolicyManifestVersion,
            Self::PolicyFailClosed,
            Self::ActorCeiling,
            Self::SourceTrust,
            Self::CriticalityFloor,
            Self::PolicyManifestAuthority,
            Self::ExternalEffectAuthority,
            Self::CounterpartyOptOut,
        ]
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GateReasonCode {
    Allow,
    DenyMissingActorClass,
    DenyMissingActorProvenance,
    DenyMissingPolicyManifestVersion,
    DenyPolicyFailClosed,
    PendingActorCeiling,
    PendingSourceTrust,
    PendingCriticalityFloor,
    PendingPolicyManifestAuthority,
    PendingExternalEffectAuthority,
    DenyCounterpartyOptOut,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateReasonCode {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "gate.allow",
            Self::DenyMissingActorClass => "gate.deny.missing_actor_class",
            Self::DenyMissingActorProvenance => "gate.deny.missing_actor_provenance",
            Self::DenyMissingPolicyManifestVersion => "gate.deny.missing_policy_manifest_version",
            Self::DenyPolicyFailClosed => "gate.deny.policy_fail_closed",
            Self::PendingActorCeiling => "gate.pending.actor_ceiling",
            Self::PendingSourceTrust => "gate.pending.source_trust",
            Self::PendingCriticalityFloor => "gate.pending.criticality_floor",
            Self::PendingPolicyManifestAuthority => "gate.pending.policy_manifest_authority",
            Self::PendingExternalEffectAuthority => "gate.pending.external_effect_authority",
            Self::DenyCounterpartyOptOut => "gate.deny.counterparty_opt_out",
        }
    }

    const fn metric_reason_class(self) -> GateMetricReasonClass {
        match self {
            Self::Allow => GateMetricReasonClass::Allow,
            Self::DenyMissingActorClass => GateMetricReasonClass::MissingActorClass,
            Self::DenyMissingActorProvenance => GateMetricReasonClass::MissingActorProvenance,
            Self::DenyMissingPolicyManifestVersion => {
                GateMetricReasonClass::MissingPolicyManifestVersion
            }
            Self::DenyPolicyFailClosed => GateMetricReasonClass::PolicyFailClosed,
            Self::PendingActorCeiling => GateMetricReasonClass::ActorCeiling,
            Self::PendingSourceTrust => GateMetricReasonClass::SourceTrust,
            Self::PendingCriticalityFloor => GateMetricReasonClass::CriticalityFloor,
            Self::PendingPolicyManifestAuthority => GateMetricReasonClass::PolicyManifestAuthority,
            Self::PendingExternalEffectAuthority => GateMetricReasonClass::ExternalEffectAuthority,
            Self::DenyCounterpartyOptOut => GateMetricReasonClass::CounterpartyOptOut,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateDecision {
    outcome: GateOutcome,
    reason_codes: Vec<GateReasonCode>,
    receipt_reasons: Vec<&'static str>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateDecision {
    fn allow() -> Self {
        Self {
            outcome: GateOutcome::Allow,
            reason_codes: vec![GateReasonCode::Allow],
            receipt_reasons: Vec::new(),
        }
    }

    fn deny(reason_code: GateReasonCode) -> Self {
        Self {
            outcome: GateOutcome::Deny,
            reason_codes: vec![reason_code],
            receipt_reasons: Vec::new(),
        }
    }

    fn pending(reason_codes: Vec<GateReasonCode>) -> Self {
        Self {
            outcome: GateOutcome::Pending,
            reason_codes,
            receipt_reasons: Vec::new(),
        }
    }

    fn with_receipt_reasons(mut self, reasons: impl IntoIterator<Item = &'static str>) -> Self {
        for reason in reasons {
            if !self.receipt_reasons.contains(&reason) {
                self.receipt_reasons.push(reason);
            }
        }
        self
    }

    #[must_use]
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.outcome
    }

    #[must_use]
    pub(crate) fn reason_codes(&self) -> &[GateReasonCode] {
        &self.reason_codes
    }

    #[must_use]
    pub(crate) fn receipt_reasons(&self) -> &[&'static str] {
        &self.receipt_reasons
    }
}

fn external_effect_receipt_reasons(
    effect: &ExternalEffectGateContext,
) -> impl Iterator<Item = &'static str> {
    effect
        .counterparty_opt_out_receipt_reason
        .into_iter()
        .chain(
            effect
                .counterparty_first_touch
                .map(CounterpartyFirstTouch::receipt_reason),
        )
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateMetricCounter {
    outcome: GateOutcome,
    reason_class: GateMetricReasonClass,
    count: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateMetricCounter {
    #[must_use]
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.outcome
    }

    #[must_use]
    pub(crate) fn reason_class(&self) -> GateMetricReasonClass {
        self.reason_class
    }

    #[must_use]
    pub(crate) fn count(&self) -> u64 {
        self.count
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GateMetricsSnapshot {
    counters: Vec<GateMetricCounter>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl GateMetricsSnapshot {
    #[must_use]
    pub(crate) fn counters(&self) -> &[GateMetricCounter] {
        &self.counters
    }

    #[must_use]
    pub(crate) fn count(&self, outcome: GateOutcome, reason_class: GateMetricReasonClass) -> u64 {
        self.counters
            .iter()
            .find(|counter| counter.outcome == outcome && counter.reason_class == reason_class)
            .map_or(0, |counter| counter.count)
    }
}

#[must_use]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn foreign_agent_ceiling_after_widen_request(
    current_ceiling: PolicyApprovalCeiling,
    requested_ceiling: PolicyApprovalCeiling,
    normal_gate_decision: &GateDecision,
) -> PolicyApprovalCeiling {
    if normal_gate_decision.outcome() == GateOutcome::Allow {
        requested_ceiling
    } else {
        current_ceiling
    }
}

#[must_use]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn gate_metrics_snapshot() -> GateMetricsSnapshot {
    let mut counters =
        Vec::with_capacity(GATE_METRIC_OUTCOME_COUNT * GATE_METRIC_REASON_CLASS_COUNT);
    for outcome in GateOutcome::metric_values() {
        for reason_class in GateMetricReasonClass::metric_values() {
            counters.push(GateMetricCounter {
                outcome,
                reason_class,
                count: GATE_METRIC_COUNTERS[outcome.metric_index()][reason_class.metric_index()]
                    .load(AtomicOrdering::Relaxed),
            });
        }
    }
    GateMetricsSnapshot { counters }
}

fn record_gate_decision_metrics(decision: &GateDecision) {
    let outcome = decision.outcome();
    // A decision with multiple reason codes records one outcome/reason-class co-occurrence per code.
    for reason_code in decision.reason_codes() {
        let reason_class = reason_code.metric_reason_class();
        GATE_METRIC_COUNTERS[outcome.metric_index()][reason_class.metric_index()]
            .fetch_add(1, AtomicOrdering::Relaxed);
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PolicyScopedGrant {
    pub(crate) actor_class: Option<String>,
    pub(crate) actor_ref: Option<String>,
    pub(crate) effector: String,
    pub(crate) scope: Option<Value>,
    pub(crate) budget: Option<Value>,
    pub(crate) receipt_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyLegalFloorRow {
    pub(crate) row_ref: String,
    pub(crate) category: String,
    pub(crate) subcategory: String,
    pub(crate) action: String,
    pub(crate) text: String,
    pub(crate) active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyOwnerPolicyRow {
    pub(crate) row_ref: String,
    pub(crate) text: String,
    pub(crate) active: bool,
    pub(crate) world_ref: Option<String>,
    pub(crate) block: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicySignature {
    pub(crate) alg: String,
    pub(crate) key_id: Option<String>,
    pub(crate) sig: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SourceTrustRow {
    max_auto_sensitivity: Option<u8>,
    receipted: bool,
    warned: bool,
}

impl SourceTrustRow {
    fn merge(self, other: Self) -> Self {
        let max_auto_sensitivity = match (self.max_auto_sensitivity, other.max_auto_sensitivity) {
            (Some(left), Some(right)) => Some(left.min(right)),
            _ => None,
        };

        Self {
            max_auto_sensitivity,
            receipted: self.receipted && other.receipted,
            warned: self.warned && other.warned,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SourceTrustCeiling {
    user_stated: Option<SourceTrustRow>,
    observed: Option<SourceTrustRow>,
    inferred: Option<SourceTrustRow>,
    imported: Option<SourceTrustRow>,
    tool_output: Option<SourceTrustRow>,
    generated: Option<SourceTrustRow>,
    malformed_manifest_seen: bool,
}

impl SourceTrustCeiling {
    fn malformed() -> Self {
        Self {
            malformed_manifest_seen: true,
            ..Self::default()
        }
    }

    fn row(&self, source: ClaimSource) -> Option<SourceTrustRow> {
        match source {
            ClaimSource::UserStated => self.user_stated,
            ClaimSource::Observed => self.observed,
            ClaimSource::Inferred => self.inferred,
            ClaimSource::Imported => self.imported,
            ClaimSource::ToolOutput => self.tool_output,
            ClaimSource::Generated => self.generated,
        }
    }

    fn set_row(&mut self, source: ClaimSource, row: SourceTrustRow) {
        let slot = match source {
            ClaimSource::UserStated => &mut self.user_stated,
            ClaimSource::Observed => &mut self.observed,
            ClaimSource::Inferred => &mut self.inferred,
            ClaimSource::Imported => &mut self.imported,
            ClaimSource::ToolOutput => &mut self.tool_output,
            ClaimSource::Generated => &mut self.generated,
        };
        *slot = Some(slot.map_or(row, |existing| existing.merge(row)));
    }

    fn merge(&mut self, other: Self) {
        self.malformed_manifest_seen |= other.malformed_manifest_seen;
        for source in [
            ClaimSource::UserStated,
            ClaimSource::Observed,
            ClaimSource::Inferred,
            ClaimSource::Imported,
            ClaimSource::ToolOutput,
            ClaimSource::Generated,
        ] {
            if let Some(row) = other.row(source) {
                self.set_row(source, row);
            }
        }
    }

    fn fail_closed(&mut self) {
        self.malformed_manifest_seen = true;
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PolicyManifestDiagnostics {
    pub(crate) manifest_count: usize,
    pub(crate) malformed_manifest_seen: bool,
    pub(crate) unsupported_schema_seen: bool,
    pub(crate) engine_version_floor_seen: bool,
    pub(crate) unknown_axis_seen: bool,
}

impl PolicyManifestDiagnostics {
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_fail_closed(self) -> bool {
        self.manifest_count == 0
            || self.malformed_manifest_seen
            || self.unsupported_schema_seen
            || self.engine_version_floor_seen
            || self.unknown_axis_seen
    }

    pub(crate) fn loaded_manifest_forces_fail_closed(self) -> bool {
        self.malformed_manifest_seen
            || self.unsupported_schema_seen
            || self.engine_version_floor_seen
            || self.unknown_axis_seen
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PolicyManifestResolution {
    diagnostics: PolicyManifestDiagnostics,
    packs: Vec<PolicyPack>,
    actor_ceilings: Vec<ActorCeiling>,
    source_trust: SourceTrustCeiling,
    scoped_grants: Vec<PolicyScopedGrant>,
    legal_floor_rows: Vec<PolicyLegalFloorRow>,
    owner_policy_rows: Vec<PolicyOwnerPolicyRow>,
    owner_policy_rows_dropped: bool,
    signatures: Vec<PolicySignature>,
    on_budget_exhausted: Option<BudgetExhaustionPolicy>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl PolicyManifestResolution {
    #[must_use]
    pub(crate) fn diagnostics(&self) -> PolicyManifestDiagnostics {
        self.diagnostics
    }

    #[must_use]
    pub(crate) fn is_fail_closed(&self) -> bool {
        self.diagnostics.is_fail_closed()
    }

    #[must_use]
    pub(crate) fn enforces_write_gate(&self) -> bool {
        // A completely absent manifest preserves the existing bootstrap
        // behavior; any loaded malformed/unsupported manifest fails closed.
        self.diagnostics.manifest_count > 0 || self.diagnostics.loaded_manifest_forces_fail_closed()
    }

    #[must_use]
    pub(crate) fn on_budget_exhausted(&self) -> BudgetExhaustionPolicy {
        self.on_budget_exhausted.unwrap_or_default()
    }

    #[must_use]
    pub(crate) fn actor_ceiling(
        &self,
        actor_class: &str,
        actor_ref: Option<&str>,
    ) -> PolicyApprovalCeiling {
        if self.is_fail_closed() {
            return PolicyApprovalCeiling::Proposed;
        }

        let mut ceiling: Option<PolicyApprovalCeiling> = None;
        for row in &self.actor_ceilings {
            if row.actor_class != actor_class {
                continue;
            }
            match (&row.actor_ref, actor_ref) {
                (None, _) => {
                    ceiling = Some(
                        ceiling.map_or(row.ceiling, |existing| existing.restrict(row.ceiling)),
                    );
                }
                (Some(row_ref), Some(request_ref)) if row_ref == request_ref => {
                    ceiling = Some(
                        ceiling.map_or(row.ceiling, |existing| existing.restrict(row.ceiling)),
                    );
                }
                _ => {}
            }
        }
        ceiling.unwrap_or(PolicyApprovalCeiling::Proposed)
    }

    pub(crate) fn has_matching_actor_ceiling(
        &self,
        actor_class: &str,
        actor_ref: Option<&str>,
    ) -> bool {
        self.actor_ceilings.iter().any(|row| {
            row.actor_class == actor_class
                && match (&row.actor_ref, actor_ref) {
                    (None, _) => true,
                    (Some(row_ref), Some(request_ref)) => row_ref == request_ref,
                    _ => false,
                }
        })
    }

    fn actor_ceiling_allows_auto_for_content(&self, input: &GateEvaluatorInput) -> bool {
        let actor_class = input.actor.actor_class.trim();
        if self.actor_ceiling(actor_class, input.actor.actor_ref.as_deref())
            == PolicyApprovalCeiling::Auto
        {
            return true;
        }

        input.content_kind == GateContentKind::EdgeProvenanceClaim
            && matches!(actor_class, "agent" | "system")
            && !self.has_matching_actor_ceiling(actor_class, input.actor.actor_ref.as_deref())
    }

    fn dreamer_auto_grant_requires_manifest_signature(&self, input: &GateEvaluatorInput) -> bool {
        input.content_kind == GateContentKind::Claim
            && input.actor.actor_class.trim() == "agent"
            && input.provenance.dreamer_run_id.is_some()
            && self.actor_ceiling(
                input.actor.actor_class.trim(),
                input.actor.actor_ref.as_deref(),
            ) == PolicyApprovalCeiling::Auto
    }

    #[must_use]
    pub(crate) fn criticality_for_predicate(&self, predicate: &str) -> PolicyCriticality {
        if self.is_fail_closed() {
            return PolicyCriticality::Critical;
        }

        self.axes_for_predicate(predicate)
            .criticality
            .unwrap_or(PolicyCriticality::Critical)
    }

    #[must_use]
    pub(crate) fn sensitivity_for_predicate(&self, predicate: &str) -> PolicySensitivity {
        if self.is_fail_closed() {
            return PolicySensitivity::Sensitive;
        }

        self.axes_for_predicate(predicate)
            .sensitivity
            .unwrap_or(PolicySensitivity::Sensitive)
    }

    #[must_use]
    pub(crate) fn scoped_grants(&self) -> &[PolicyScopedGrant] {
        if self.is_fail_closed() {
            &[]
        } else {
            &self.scoped_grants
        }
    }

    #[must_use]
    pub(crate) fn legal_floor_rows(&self) -> &[PolicyLegalFloorRow] {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            &[]
        } else {
            &self.legal_floor_rows
        }
    }

    #[must_use]
    pub(crate) fn active_owner_policy_rows(
        &self,
        world_ref: Option<&str>,
    ) -> Vec<&PolicyOwnerPolicyRow> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() || self.owner_policy_rows_dropped {
            return Vec::new();
        }

        let scoped_refs: Vec<&str> = match world_ref {
            Some(world_ref) => self
                .owner_policy_rows
                .iter()
                .filter(|row| row.active && row.world_ref.as_deref() == Some(world_ref))
                .map(|row| row.row_ref.as_str())
                .collect(),
            None => Vec::new(),
        };

        self.owner_policy_rows
            .iter()
            .filter(|row| row.active)
            .filter(|row| match (world_ref, row.world_ref.as_deref()) {
                (Some(world_ref), Some(row_world)) => row_world == world_ref,
                (Some(_), None) => !scoped_refs.contains(&row.row_ref.as_str()),
                (None, None) => true,
                (None, Some(_)) => false,
            })
            .collect()
    }

    #[must_use]
    pub(crate) fn has_scoped_read_grants(&self) -> bool {
        self.scoped_grants()
            .iter()
            .any(scoped_read_grant_has_read_effector)
    }

    #[must_use]
    pub(crate) fn signatures(&self) -> &[PolicySignature] {
        &self.signatures
    }

    pub(crate) fn read_frontier_hash(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hash_policy_frontier_v0(&mut hasher, self)?;
        Ok(hasher.finalize().into())
    }

    #[must_use]
    pub(crate) fn evaluate_gate(&self, input: &GateEvaluatorInput) -> GateDecision {
        let actor_class = input.actor.actor_class.trim();
        if actor_class.is_empty() {
            return GateDecision::deny(GateReasonCode::DenyMissingActorClass);
        }
        if input.provenance.actor_entity_ref.is_none() {
            return GateDecision::deny(GateReasonCode::DenyMissingActorProvenance);
        }
        if input.policy_manifest_version.trim().is_empty() {
            return GateDecision::deny(GateReasonCode::DenyMissingPolicyManifestVersion);
        }
        let external_effect = if input.content_kind == GateContentKind::ExternalEffect {
            input.external_effect.as_ref()
        } else {
            None
        };
        if let Some(effect) = external_effect
            && effect.counterparty_opted_out
        {
            return GateDecision::deny(GateReasonCode::DenyCounterpartyOptOut)
                .with_receipt_reasons(external_effect_receipt_reasons(effect));
        }
        if self.is_fail_closed() {
            if input.content_kind == GateContentKind::ExternalEffect {
                let decision =
                    GateDecision::pending(vec![GateReasonCode::PendingExternalEffectAuthority]);
                return if let Some(effect) = external_effect {
                    decision.with_receipt_reasons(external_effect_receipt_reasons(effect))
                } else {
                    decision
                };
            }
            return GateDecision::deny(GateReasonCode::DenyPolicyFailClosed);
        }

        let mut pending = Vec::new();

        let actor_ceiling_allows_auto = self.actor_ceiling_allows_auto_for_content(input);
        if !actor_ceiling_allows_auto {
            pending.push(GateReasonCode::PendingActorCeiling);
        }

        if actor_ceiling_allows_auto
            && self.dreamer_auto_grant_requires_manifest_signature(input)
            && self.signatures.is_empty()
        {
            pending.push(GateReasonCode::PendingPolicyManifestAuthority);
        }

        if !self.source_trust_allows_auto(input.source, input.sensitivity_band) {
            pending.push(GateReasonCode::PendingSourceTrust);
        }

        if input.criticality == PolicyCriticality::Critical {
            pending.push(GateReasonCode::PendingCriticalityFloor);
        }

        match input.content_kind {
            GateContentKind::Claim | GateContentKind::EdgeProvenanceClaim => {}
            GateContentKind::PolicyManifest => {
                pending.push(GateReasonCode::PendingPolicyManifestAuthority);
            }
            GateContentKind::ExternalEffect => {
                if !self.external_effect_allows_auto(input) {
                    pending.push(GateReasonCode::PendingExternalEffectAuthority);
                }
            }
        }

        let decision = if pending.is_empty() {
            GateDecision::allow()
        } else {
            GateDecision::pending(pending)
        };

        if let Some(effect) = external_effect {
            decision.with_receipt_reasons(external_effect_receipt_reasons(effect))
        } else {
            decision
        }
    }

    fn source_trust_allows_auto(
        &self,
        source: Option<ClaimSource>,
        sensitivity: Option<u8>,
    ) -> bool {
        let Some(source) = source else {
            return true;
        };

        if self.source_trust.malformed_manifest_seen {
            return false;
        }

        let Some(sensitivity) = sensitivity else {
            return false;
        };

        let Some(row) = self.source_trust.row(source) else {
            return !source.requires_explicit_auto_permit();
        };

        let Some(max_auto_sensitivity) = row.max_auto_sensitivity else {
            return false;
        };

        sensitivity <= max_auto_sensitivity
            && (!source.requires_explicit_auto_permit() || (row.receipted && row.warned))
    }

    fn external_effect_allows_auto(&self, input: &GateEvaluatorInput) -> bool {
        let Some(effect) = input.external_effect.as_ref() else {
            return false;
        };
        if effect.verb.trim().is_empty()
            || effect.channel.trim().is_empty()
            || !effect.has_permission
        {
            return false;
        }
        if effect.standing_grant_ref.is_some() {
            return true;
        }
        if !effect.has_opted_in {
            return false;
        }

        self.scoped_grants().iter().any(|grant| {
            grant.budget.is_none() && external_effect_grant_matches(grant, &input.actor, effect)
        })
    }

    fn axes_for_predicate(&self, predicate: &str) -> PolicyAxes {
        let mut resolved = PolicyAxes::default();
        for pack in &self.packs {
            resolved = resolved.restrict(pack.axes_for_predicate(predicate));
        }
        resolved
    }
}

pub(crate) fn scoped_read_claim_allowed(
    policy: &PolicyManifestResolution,
    actor_key: &ScopedReadActorKey,
    body: &ClaimBody,
    claim_facets: &[EntityId],
) -> bool {
    let diagnostics = policy.diagnostics();
    if diagnostics.loaded_manifest_forces_fail_closed() {
        return false;
    }
    if diagnostics.manifest_count == 0 {
        return true;
    }
    if policy.is_fail_closed() {
        return false;
    }

    let mut saw_core_read_grant = false;
    for grant in policy
        .scoped_grants()
        .iter()
        .filter(|grant| scoped_read_grant_has_read_effector(grant))
    {
        saw_core_read_grant = true;
        if grant.receipt_required {
            continue;
        }
        if grant.budget.is_some() {
            continue;
        }
        if !scoped_read_actor_matches(grant, actor_key) {
            continue;
        }
        if scoped_read_scope_matches_claim(grant.scope.as_ref(), body, claim_facets) {
            return true;
        }
    }

    !saw_core_read_grant
}

fn scoped_read_grant_has_read_effector(grant: &PolicyScopedGrant) -> bool {
    grant.effector.trim() == SCOPED_READ_EFFECTOR_CORE_READ
        || grant.effector.trim() == SCOPED_READ_EFFECTOR_ONEIRON_READ
}

fn scoped_read_actor_matches(grant: &PolicyScopedGrant, actor_key: &ScopedReadActorKey) -> bool {
    if let Some(actor_ref) = grant.actor_ref.as_deref()
        && actor_ref != actor_key.actor_ref()
    {
        return false;
    }
    if let Some(actor_class) = grant.actor_class.as_deref()
        && Some(actor_class) != actor_key.actor_class()
    {
        return false;
    }
    true
}

fn scoped_read_scope_matches_claim(
    scope: Option<&Value>,
    body: &ClaimBody,
    claim_facets: &[EntityId],
) -> bool {
    let Some(scope) = scope else {
        return true;
    };
    match scope {
        Value::Nil => true,
        Value::Map(entries) if entries.is_empty() => true,
        Value::Map(entries) => {
            for (key, value) in entries {
                let Some(key) = key.as_str() else {
                    return false;
                };
                let matches = match key {
                    "world" | "world_ref" | "worldRef" => {
                        scoped_read_world_matches_claim(value, body.world)
                    }
                    "claim_scope" | "claimScope" | "scope" => {
                        scoped_read_claim_scope_matches(value, body.scope.as_ref())
                    }
                    "facet" | "facet_ref" | "facetRef" => {
                        scoped_read_claim_facet_matches(value, body.scope.as_ref(), claim_facets)
                    }
                    _ => false,
                };
                if !matches {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

fn scoped_read_world_matches_claim(value: &Value, claim_world: Option<EntityId>) -> bool {
    if matches!(value, Value::Nil) {
        return claim_world.is_none();
    }
    if value.as_str().is_some_and(|text| text == "base") {
        return claim_world.is_none();
    }
    let Some(grant_world) = scoped_read_entity_id_from_value(value) else {
        return false;
    };
    match claim_world {
        None => true,
        Some(claim_world) => claim_world == grant_world,
    }
}

fn scoped_read_claim_scope_matches(value: &Value, claim_scope: Option<&Value>) -> bool {
    match (value, claim_scope) {
        (Value::Nil, None) => true,
        (_, Some(claim_scope)) => claim_scope == value,
        _ => false,
    }
}

fn scoped_read_claim_scope_field_matches(
    value: &Value,
    claim_scope: Option<&Value>,
    field_names: &[&str],
) -> bool {
    let Some(Value::Map(entries)) = claim_scope else {
        return false;
    };
    entries.iter().any(|(key, candidate)| {
        key.as_str().is_some_and(|key| field_names.contains(&key)) && candidate == value
    })
}

fn scoped_read_claim_facet_matches(
    value: &Value,
    claim_scope: Option<&Value>,
    claim_facets: &[EntityId],
) -> bool {
    if !claim_facets.is_empty() {
        let Some(grant_facet) = scoped_read_entity_id_from_value(value) else {
            return false;
        };
        return claim_facets.contains(&grant_facet);
    }

    scoped_read_claim_scope_field_matches(value, claim_scope, &["facet", "facet_ref", "facetRef"])
}

fn scoped_read_entity_id_from_value(value: &Value) -> Option<EntityId> {
    match value {
        Value::Binary(bytes) => {
            let bytes: [u8; ENTITY_ID_LEN] = bytes.as_slice().try_into().ok()?;
            EntityId::from_bytes(bytes).ok()
        }
        _ => EntityId::from_hex(value.as_str()?).ok(),
    }
}

fn external_effect_grant_matches(
    grant: &PolicyScopedGrant,
    actor: &GateActor,
    effect: &ExternalEffectGateContext,
) -> bool {
    external_effect_actor_matches(grant, actor)
        && external_effect_effector_matches(grant.effector.trim(), effect.verb.trim())
        && external_effect_scope_matches(grant.scope.as_ref(), effect)
}

fn external_effect_actor_matches(grant: &PolicyScopedGrant, actor: &GateActor) -> bool {
    if let Some(actor_class) = grant.actor_class.as_deref()
        && actor_class != actor.actor_class.trim()
    {
        return false;
    }
    if let Some(actor_ref) = grant.actor_ref.as_deref()
        && Some(actor_ref) != actor.actor_ref.as_deref()
    {
        return false;
    }
    true
}

fn external_effect_effector_matches(effector: &str, verb: &str) -> bool {
    if effector == EXTERNAL_EFFECT_WILDCARD {
        return true;
    }
    if let Some(candidate) = effector.strip_prefix(EXTERNAL_EFFECT_EFFECTOR_PREFIX) {
        return candidate == EXTERNAL_EFFECT_WILDCARD || candidate == verb;
    }
    if let Some(candidate) = effector.strip_prefix(EXTERNAL_EFFECT_EFFECTOR_LONG_PREFIX) {
        return candidate == EXTERNAL_EFFECT_WILDCARD || candidate == verb;
    }
    effector == verb
}

fn external_effect_scope_matches(
    scope: Option<&Value>,
    effect: &ExternalEffectGateContext,
) -> bool {
    let Some(scope) = scope else {
        return true;
    };
    match scope {
        Value::Nil => true,
        Value::Map(entries) if entries.is_empty() => true,
        Value::Map(entries) => entries.iter().all(|(key, value)| {
            let Some(key) = key.as_str() else {
                return false;
            };
            match key {
                EXTERNAL_EFFECT_SCOPE_VERB_KEY => {
                    external_effect_scope_text_matches(value, effect.verb.trim())
                }
                EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY
                | EXTERNAL_EFFECT_SCOPE_CHANNEL_REF_KEY
                | EXTERNAL_EFFECT_SCOPE_CHANNEL_REF_CAMEL_KEY => {
                    external_effect_scope_text_matches(value, effect.channel.trim())
                }
                EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY
                | EXTERNAL_EFFECT_SCOPE_POLICY_RISK_CAMEL_KEY => {
                    external_effect_scope_policy_risk_matches(value, effect.policy_risk)
                }
                _ => false,
            }
        }),
        _ => false,
    }
}

fn external_effect_scope_text_matches(value: &Value, expected: &str) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| external_effect_scope_text_matches(value, expected)),
        _ => value
            .as_str()
            .is_some_and(|value| value == EXTERNAL_EFFECT_WILDCARD || value == expected),
    }
}

fn external_effect_scope_policy_risk_matches(
    value: &Value,
    policy_risk: ExternalEffectPolicyRisk,
) -> bool {
    match value {
        Value::Array(values) => values
            .iter()
            .any(|value| external_effect_scope_policy_risk_matches(value, policy_risk)),
        Value::Boolean(true) => policy_risk == ExternalEffectPolicyRisk::HoldToProposal,
        Value::Boolean(false) => policy_risk == ExternalEffectPolicyRisk::Normal,
        _ => value.as_str().is_some_and(|value| {
            value == EXTERNAL_EFFECT_WILDCARD || value == policy_risk.as_str()
        }),
    }
}

pub(crate) fn companion_profile_access_grant(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    principal_ref: &EntityId,
    person_ref: &EntityId,
    persona_ref: &EntityId,
) -> Result<Option<EntityId>> {
    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_ACCESS_GRANT])?
    {
        let (key, _) = index_entry?;
        let Some(id) = type_index_entity_id(key, ENTITY_TYPE_ACCESS_GRANT) else {
            return Err(Error::CorruptedIndex("access grant type index key"));
        };
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("access grant entity row"));
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(raw) else {
            return Err(Error::CorruptedIndex("access grant entity header"));
        };
        if header.entity_type != ENTITY_TYPE_ACCESS_GRANT {
            return Err(Error::CorruptedIndex("access grant entity type"));
        }

        let grant = match crate::access_grant::decode_access_grant_body(
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
        ) {
            Ok(grant) => grant,
            Err(_) => {
                return Err(Error::CorruptedIndex("access grant body"));
            }
        };
        if grant.allows_companion_profile_read(principal_ref, person_ref, persona_ref) {
            return Ok(Some(id));
        }
    }

    Ok(None)
}

fn hash_policy_frontier_v0(
    hasher: &mut Sha256,
    resolution: &PolicyManifestResolution,
) -> Result<()> {
    hash_bytes(hasher, b"oneiron.gate.policy_frontier.v0");
    hash_diagnostics(hasher, resolution.diagnostics);
    hash_source_trust(hasher, &resolution.source_trust);
    hash_budget_exhaustion_policy(hasher, resolution.on_budget_exhausted());

    hash_len(hasher, resolution.packs.len());
    for pack in &resolution.packs {
        hash_str(hasher, &pack._pack_id);
        hash_str(hasher, &pack._pack_version);
        hash_str(hasher, &pack._min_engine_version);
        hash_axes(hasher, pack.defaults);
        hash_len(hasher, pack.rules.len());
        for rule in &pack.rules {
            hash_str(hasher, &rule.prefix);
            hash_bool(hasher, rule.exact);
            hash_axes(hasher, rule.axes);
        }
    }

    hash_len(hasher, resolution.actor_ceilings.len());
    for ceiling in &resolution.actor_ceilings {
        hash_str(hasher, &ceiling.actor_class);
        hash_opt_str(hasher, ceiling.actor_ref.as_deref());
        hash_approval_ceiling(hasher, ceiling.ceiling);
    }

    hash_len(hasher, resolution.scoped_grants.len());
    for grant in &resolution.scoped_grants {
        hash_opt_str(hasher, grant.actor_class.as_deref());
        hash_opt_str(hasher, grant.actor_ref.as_deref());
        hash_str(hasher, &grant.effector);
        hash_opt_value(hasher, grant.scope.as_ref())?;
        hash_opt_value(hasher, grant.budget.as_ref())?;
        hash_bool(hasher, grant.receipt_required);
    }

    hash_len(hasher, resolution.legal_floor_rows.len());
    for row in &resolution.legal_floor_rows {
        hash_legal_floor_row(hasher, row);
    }

    hash_bool(hasher, resolution.owner_policy_rows_dropped);
    hash_len(hasher, resolution.owner_policy_rows.len());
    for row in &resolution.owner_policy_rows {
        hash_owner_policy_row(hasher, row);
    }

    hash_len(hasher, resolution.signatures.len());
    for signature in &resolution.signatures {
        hash_str(hasher, &signature.alg);
        hash_opt_str(hasher, signature.key_id.as_deref());
        hash_str(hasher, &signature.sig);
    }

    Ok(())
}

fn hash_diagnostics(hasher: &mut Sha256, diagnostics: PolicyManifestDiagnostics) {
    hash_len(hasher, diagnostics.manifest_count);
    hash_bool(hasher, diagnostics.malformed_manifest_seen);
    hash_bool(hasher, diagnostics.unsupported_schema_seen);
    hash_bool(hasher, diagnostics.engine_version_floor_seen);
    hash_bool(hasher, diagnostics.unknown_axis_seen);
}

fn hash_source_trust(hasher: &mut Sha256, source_trust: &SourceTrustCeiling) {
    hash_bool(hasher, source_trust.malformed_manifest_seen);
    for source in [
        ClaimSource::UserStated,
        ClaimSource::Observed,
        ClaimSource::Inferred,
        ClaimSource::Imported,
        ClaimSource::ToolOutput,
        ClaimSource::Generated,
    ] {
        hash_str(hasher, source.as_str());
        hash_source_trust_row(hasher, source_trust.row(source));
    }
}

fn hash_source_trust_row(hasher: &mut Sha256, row: Option<SourceTrustRow>) {
    let Some(row) = row else {
        hash_bool(hasher, false);
        return;
    };
    hash_bool(hasher, true);
    hash_opt_u8(hasher, row.max_auto_sensitivity);
    hash_bool(hasher, row.receipted);
    hash_bool(hasher, row.warned);
}

fn hash_legal_floor_row(hasher: &mut Sha256, row: &PolicyLegalFloorRow) {
    hash_str(hasher, &row.row_ref);
    hash_str(hasher, &row.category);
    hash_str(hasher, &row.subcategory);
    hash_str(hasher, &row.action);
    hash_str(hasher, &row.text);
    hash_bool(hasher, row.active);
}

fn hash_owner_policy_row(hasher: &mut Sha256, row: &PolicyOwnerPolicyRow) {
    hash_str(hasher, &row.row_ref);
    hash_str(hasher, &row.text);
    hash_bool(hasher, row.active);
    hash_opt_str(hasher, row.world_ref.as_deref());
    hash_bool(hasher, row.block);
}

fn hash_axes(hasher: &mut Sha256, axes: PolicyAxes) {
    hash_opt_criticality(hasher, axes.criticality);
    hash_opt_sensitivity(hasher, axes.sensitivity);
    hash_bool(hasher, axes.unknown_axis_seen);
}

fn hash_approval_ceiling(hasher: &mut Sha256, ceiling: PolicyApprovalCeiling) {
    hash_str(
        hasher,
        match ceiling {
            PolicyApprovalCeiling::Auto => "auto",
            PolicyApprovalCeiling::Proposed => "proposed",
        },
    );
}

fn hash_opt_criticality(hasher: &mut Sha256, criticality: Option<PolicyCriticality>) {
    let Some(criticality) = criticality else {
        hash_bool(hasher, false);
        return;
    };
    hash_bool(hasher, true);
    hash_str(
        hasher,
        match criticality {
            PolicyCriticality::Normal => "normal",
            PolicyCriticality::Critical => "critical",
        },
    );
}

fn hash_opt_sensitivity(hasher: &mut Sha256, sensitivity: Option<PolicySensitivity>) {
    let Some(sensitivity) = sensitivity else {
        hash_bool(hasher, false);
        return;
    };
    hash_bool(hasher, true);
    hash_str(
        hasher,
        match sensitivity {
            PolicySensitivity::Normal => "normal",
            PolicySensitivity::Sensitive => "sensitive",
        },
    );
}

fn hash_opt_value(hasher: &mut Sha256, value: Option<&Value>) -> Result<()> {
    let Some(value) = value else {
        hash_bool(hasher, false);
        return Ok(());
    };
    hash_bool(hasher, true);
    let mut encoded = Vec::new();
    rmpv::encode::write_value(&mut encoded, value)
        .map_err(|_| Error::InvariantViolation("policy frontier value encode failed"))?;
    hash_bytes(hasher, &encoded);
    Ok(())
}

fn hash_opt_str(hasher: &mut Sha256, value: Option<&str>) {
    let Some(value) = value else {
        hash_bool(hasher, false);
        return;
    };
    hash_bool(hasher, true);
    hash_str(hasher, value);
}

fn hash_opt_u8(hasher: &mut Sha256, value: Option<u8>) {
    let Some(value) = value else {
        hash_bool(hasher, false);
        return;
    };
    hash_bool(hasher, true);
    hasher.update([value]);
}

fn hash_str(hasher: &mut Sha256, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hash_len(hasher, bytes.len());
    hasher.update(bytes);
}

fn hash_bool(hasher: &mut Sha256, value: bool) {
    hasher.update([u8::from(value)]);
}

fn hash_len(hasher: &mut Sha256, value: usize) {
    hasher.update((value as u64).to_le_bytes());
}

fn hash_u64(hasher: &mut Sha256, value: u64) {
    hasher.update(value.to_le_bytes());
}

fn hash_budget_exhaustion_policy(hasher: &mut Sha256, policy: BudgetExhaustionPolicy) {
    match policy {
        BudgetExhaustionPolicy::Suspend => hash_str(hasher, "suspend"),
        BudgetExhaustionPolicy::ContinueOnLocal => hash_str(hasher, "continue_on_local"),
        BudgetExhaustionPolicy::Overdraft { cap } => {
            hash_str(hasher, "overdraft");
            hash_u64(hasher, cap);
        }
    }
}

struct DecodedPolicyManifest {
    pack: PolicyPack,
    actor_ceilings: Vec<ActorCeiling>,
    source_trust: SourceTrustCeiling,
    scoped_grants: Vec<PolicyScopedGrant>,
    legal_floor_rows: Vec<PolicyLegalFloorRow>,
    owner_policy_rows: Vec<PolicyOwnerPolicyRow>,
    owner_policy_rows_dropped: bool,
    signatures: Vec<PolicySignature>,
    on_budget_exhausted: Option<BudgetExhaustionPolicy>,
    unsupported_schema: bool,
    engine_version_floor: bool,
    unknown_axis_seen: bool,
}

pub(crate) fn first_party_eiri_connector_actor_ref() -> String {
    bytes_to_hex_lower(&FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
}

pub(crate) fn default_policy_manifest_id() -> Result<EntityId> {
    EntityId::from_bytes(DEFAULT_POLICY_MANIFEST_ID)
        .map_err(|_| Error::InvariantViolation("invalid default policy manifest id"))
}

pub(crate) fn default_policy_manifest() -> Vec<u8> {
    let first_party_eiri_actor_ref = first_party_eiri_connector_actor_ref();
    let manifest = Value::Map(vec![
        (
            Value::from(POLICY_SCHEMA_VERSION_KEY),
            Value::from(POLICY_SCHEMA_VERSION),
        ),
        (
            Value::from(POLICY_PACK_ID_KEY),
            Value::from("oneiron-default-policy"),
        ),
        (Value::from(POLICY_PACK_VERSION_KEY), Value::from("v1")),
        (
            Value::from(POLICY_MIN_ENGINE_VERSION_KEY),
            Value::from(env!("CARGO_PKG_VERSION")),
        ),
        (
            Value::from(POLICY_DEFAULTS_KEY),
            Value::Map(vec![
                (Value::from(AXIS_CRITICALITY_KEY), Value::from("critical")),
                (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
            ]),
        ),
        (
            Value::from(POLICY_RULES_KEY),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("profile.")),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("affect.vad")),
                    (Value::from(RULE_EXACT_KEY), Value::Boolean(true)),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (
                        Value::from(RULE_PREFIX_KEY),
                        Value::from(PREDICATE_EDGE_PROVENANCE),
                    ),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
            ]),
        ),
        (
            Value::from(POLICY_ACTOR_CEILINGS_KEY),
            Value::Array(vec![
                Value::Map(vec![
                    (
                        Value::from(ACTOR_CLASS_KEY),
                        Value::from(LOCAL_WRITE_ACTOR_CLASS),
                    ),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
                Value::Map(vec![
                    (Value::from(ACTOR_CLASS_KEY), Value::from("human")),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
                Value::Map(vec![
                    (Value::from(ACTOR_CLASS_KEY), Value::from("agent")),
                    (
                        Value::from(ACTOR_REF_KEY),
                        Value::from(first_party_eiri_actor_ref),
                    ),
                    (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                ]),
            ]),
        ),
        (
            Value::from(POLICY_SOURCE_TRUST_KEY),
            Value::Map(vec![(
                Value::from(ClaimSource::ToolOutput.as_str()),
                Value::Map(vec![
                    (
                        Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
                        Value::from(0_u64),
                    ),
                    (
                        Value::from(SOURCE_TRUST_RECEIPTED_KEY),
                        Value::Boolean(true),
                    ),
                    (Value::from(SOURCE_TRUST_WARNED_KEY), Value::Boolean(true)),
                ]),
            )]),
        ),
        (
            Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
            Value::from("suspend"),
        ),
        (
            Value::from(POLICY_LEGAL_FLOOR_ROWS_KEY),
            Value::Array(vec![
                Value::Map(vec![
                    (
                        Value::from(POLICY_ROW_REF_KEY),
                        Value::from("universal:minor-sexualization"),
                    ),
                    (
                        Value::from(POLICY_ROW_CATEGORY_KEY),
                        Value::from("legal_floor"),
                    ),
                    (
                        Value::from(POLICY_ROW_SUBCATEGORY_KEY),
                        Value::from("minor_sexualization"),
                    ),
                    (Value::from(POLICY_ROW_ACTION_KEY), Value::from("block")),
                    (
                        Value::from(POLICY_ROW_TEXT_KEY),
                        Value::from(
                            "Block sexual content involving minors or realistic depictions of real minors.",
                        ),
                    ),
                    (Value::from(POLICY_ROW_ACTIVE_KEY), Value::Boolean(true)),
                ]),
                Value::Map(vec![
                    (
                        Value::from(POLICY_ROW_REF_KEY),
                        Value::from("universal:ncii"),
                    ),
                    (
                        Value::from(POLICY_ROW_CATEGORY_KEY),
                        Value::from("legal_floor"),
                    ),
                    (Value::from(POLICY_ROW_SUBCATEGORY_KEY), Value::from("ncii")),
                    (Value::from(POLICY_ROW_ACTION_KEY), Value::from("block")),
                    (
                        Value::from(POLICY_ROW_TEXT_KEY),
                        Value::from(
                            "Block non-consensual intimate imagery or deepfakes of a real person.",
                        ),
                    ),
                    (Value::from(POLICY_ROW_ACTIVE_KEY), Value::Boolean(true)),
                ]),
                Value::Map(vec![
                    (
                        Value::from(POLICY_ROW_REF_KEY),
                        Value::from("universal:serious-crime"),
                    ),
                    (
                        Value::from(POLICY_ROW_CATEGORY_KEY),
                        Value::from("legal_floor"),
                    ),
                    (
                        Value::from(POLICY_ROW_SUBCATEGORY_KEY),
                        Value::from("serious_crime"),
                    ),
                    (Value::from(POLICY_ROW_ACTION_KEY), Value::from("block")),
                    (
                        Value::from(POLICY_ROW_TEXT_KEY),
                        Value::from(
                            "Block credible facilitation of serious violence, weapons, explosives, or mass harm.",
                        ),
                    ),
                    (Value::from(POLICY_ROW_ACTIVE_KEY), Value::Boolean(true)),
                ]),
                Value::Map(vec![
                    (
                        Value::from(POLICY_ROW_REF_KEY),
                        Value::from("universal:self-harm"),
                    ),
                    (Value::from(POLICY_ROW_CATEGORY_KEY), Value::from("crisis")),
                    (
                        Value::from(POLICY_ROW_SUBCATEGORY_KEY),
                        Value::from("self_harm"),
                    ),
                    (
                        Value::from(POLICY_ROW_ACTION_KEY),
                        Value::from("route_to_help"),
                    ),
                    (
                        Value::from(POLICY_ROW_TEXT_KEY),
                        Value::from("Route credible imminent self-harm or suicide risk to help."),
                    ),
                    (Value::from(POLICY_ROW_ACTIVE_KEY), Value::Boolean(true)),
                ]),
                Value::Map(vec![
                    (
                        Value::from(POLICY_ROW_REF_KEY),
                        Value::from("universal:adult-content-age-gate"),
                    ),
                    (
                        Value::from(POLICY_ROW_CATEGORY_KEY),
                        Value::from("age_gate"),
                    ),
                    (
                        Value::from(POLICY_ROW_SUBCATEGORY_KEY),
                        Value::from("adult_content"),
                    ),
                    (
                        Value::from(POLICY_ROW_ACTION_KEY),
                        Value::from("reword_retry"),
                    ),
                    (
                        Value::from(POLICY_ROW_TEXT_KEY),
                        Value::from(
                            "Reword adult or NSFW output when the account age tier does not permit it.",
                        ),
                    ),
                    (Value::from(POLICY_ROW_ACTIVE_KEY), Value::Boolean(true)),
                ]),
            ]),
        ),
        (
            Value::from(POLICY_SIGNATURES_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(SIGNATURE_ALG_KEY), Value::from("ed25519")),
                (Value::from(SIGNATURE_KEY_ID_KEY), Value::from("owner")),
                (
                    Value::from(SIGNATURE_SIG_KEY),
                    Value::from("first-party-eiri-auto"),
                ),
            ])]),
        ),
    ]);
    let mut data = Vec::new();
    rmpv::encode::write_value(&mut data, &manifest).expect("encode default policy manifest");
    data
}

pub(crate) fn resolve_policy_manifest(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> Result<PolicyManifestResolution> {
    let mut resolution = PolicyManifestResolution::default();

    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
    {
        let (key, _) = index_entry?;
        let Some(id) = type_index_entity_id(key, ENTITY_TYPE_POLICY_MANIFEST) else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(raw) else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        if header.entity_type != ENTITY_TYPE_POLICY_MANIFEST {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        }

        match decode_policy_manifest(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..]) {
            Some(decoded) => {
                resolution.diagnostics.manifest_count += 1;
                resolution.diagnostics.malformed_manifest_seen |=
                    decoded.source_trust.malformed_manifest_seen;
                resolution.diagnostics.unsupported_schema_seen |= decoded.unsupported_schema;
                resolution.diagnostics.engine_version_floor_seen |= decoded.engine_version_floor;
                resolution.diagnostics.unknown_axis_seen |= decoded.unknown_axis_seen;
                resolution.source_trust.merge(decoded.source_trust);
                resolution.actor_ceilings.extend(decoded.actor_ceilings);
                resolution.scoped_grants.extend(decoded.scoped_grants);
                resolution.legal_floor_rows.extend(decoded.legal_floor_rows);
                resolution
                    .owner_policy_rows
                    .extend(decoded.owner_policy_rows);
                resolution.owner_policy_rows_dropped |= decoded.owner_policy_rows_dropped;
                resolution.signatures.extend(decoded.signatures);
                if let Some(on_budget_exhausted) = decoded.on_budget_exhausted {
                    match resolution.on_budget_exhausted {
                        None => resolution.on_budget_exhausted = Some(on_budget_exhausted),
                        Some(existing) if existing == on_budget_exhausted => {}
                        Some(_) => resolution.diagnostics.malformed_manifest_seen = true,
                    }
                }
                resolution.packs.push(decoded.pack);
            }
            None => {
                resolution.diagnostics.malformed_manifest_seen = true;
            }
        }
    }

    if resolution.diagnostics.loaded_manifest_forces_fail_closed() {
        resolution.source_trust.fail_closed();
    }

    Ok(resolution)
}

pub(crate) fn check_claim_policy_for_write(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    envelope: Option<&WriteEnvelope>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
) -> Result<()> {
    if let Some(envelope) = envelope {
        validate_write_envelope(envelope)?;
    }

    if policy.enforces_write_gate() {
        let (actor, provenance) = if let Some(envelope) = envelope {
            let actor = envelope.actor();
            let dreamer_run_id = dreamer_run_id_from_write_envelope(envelope);
            (
                GateActor {
                    actor_class: edge_actor_class_str(actor.actor_class()).to_owned(),
                    actor_ref: Some(actor.entity_ref().to_hex()),
                },
                GateProvenanceHandles {
                    actor_entity_ref: Some(actor.entity_ref()),
                    dreamer_run_id,
                    ..GateProvenanceHandles::default()
                },
            )
        } else {
            (
                GateActor {
                    actor_class: LOCAL_WRITE_ACTOR_CLASS.to_owned(),
                    actor_ref: None,
                },
                GateProvenanceHandles {
                    actor_entity_ref: Some(local_write_actor_entity_ref()),
                    ..GateProvenanceHandles::default()
                },
            )
        };
        let input = claim_gate_input(
            body,
            policy,
            actor,
            GateContentKind::Claim,
            provenance,
            mode.include_source_in_gate_input,
        );
        let decision = policy.evaluate_gate(&input);
        let binding = GateConsentBinding::for_claim(body, policy)?;
        let decision_id = GateDecisionId::now();
        let created_at = crate::unix_seconds_now();
        let decision_record = GateDecisionRecord {
            version: 0,
            decision_id,
            created_at,
            outcome: decision.outcome().as_str().to_owned(),
            reason_codes: decision
                .reason_codes()
                .iter()
                .map(|code| code.as_str().to_owned())
                .collect(),
            receipt_reasons: decision
                .receipt_reasons()
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect(),
            actor_class: input.actor.actor_class.clone(),
            actor_ref: input.actor.actor_ref.clone(),
            content_kind: input.content_kind.as_str().to_owned(),
            policy_manifest_version: input.policy_manifest_version,
            claim_id: Some(*id.as_bytes()),
            grant_ref: None,
            diff_handle: binding.diff_handle.clone(),
            read_frontier_hash: binding.read_frontier_hash,
        };

        if mode.record_decision {
            store.append_gate_decision_in_txn(wtxn, &decision_record)?;
            record_gate_decision_metrics(&decision);
        }

        if mode.persist_pending_consent
            && decision.outcome() == GateOutcome::Pending
            && body.approval == ClaimApprovalStatus::Proposed
        {
            let pending_decision = if mode.record_decision {
                decision_record.clone()
            } else if let Some(record) =
                store.matching_gate_decision_in_txn(wtxn, &decision_record)?
            {
                record
            } else {
                store.append_gate_decision_in_txn(wtxn, &decision_record)?;
                record_gate_decision_metrics(&decision);
                decision_record.clone()
            };
            store.put_pending_gate_consent_in_txn(
                wtxn,
                &PendingGateConsentRecord {
                    version: 0,
                    claim_id: *id.as_bytes(),
                    decision_id: pending_decision.decision_id,
                    created_at: pending_decision.created_at,
                    diff_handle: pending_decision.diff_handle,
                    read_frontier_hash: pending_decision.read_frontier_hash,
                    reason_codes: pending_decision.reason_codes,
                    dreamer_run_id: pending_consent_dreamer_run_id(envelope, body),
                },
            )?;
        }

        enforce_claim_gate_decision_with_consent(
            store,
            wtxn,
            id,
            &decision,
            body.approval,
            &binding,
            mode,
        )?;
    }

    check_claim_source_trust(body, policy)
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn check_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
) -> Result<(GateDecisionId, GateDecision)> {
    let mut hydrated_effect = hydrate_external_effect_contact(store, wtxn, effect)?;
    hydrated_effect.standing_grant_ref = None;
    let matched_grant = standing_outbound_grant_for_effect(store, wtxn, &hydrated_effect, policy)?;
    if let Some((grant_id, _grant)) = matched_grant.as_ref() {
        hydrated_effect.standing_grant_ref = Some(format!("grant:{}", grant_id.to_hex()));
    }
    let input = hydrated_effect.gate_input();
    let decision = policy.evaluate_gate(&input);
    let binding = GateConsentBinding::for_external_effect(&input, policy)?;
    let decision_id = GateDecisionId::now();
    let created_at = crate::unix_seconds_now();
    let grant_ref = input
        .external_effect
        .as_ref()
        .and_then(|effect| effect.standing_grant_ref.clone());

    store.append_gate_decision_in_txn(
        wtxn,
        &GateDecisionRecord {
            version: 0,
            decision_id,
            created_at,
            outcome: decision.outcome().as_str().to_owned(),
            reason_codes: decision
                .reason_codes()
                .iter()
                .map(|code| code.as_str().to_owned())
                .collect(),
            receipt_reasons: decision
                .receipt_reasons()
                .iter()
                .map(|reason| (*reason).to_owned())
                .collect(),
            actor_class: input.actor.actor_class.clone(),
            actor_ref: input.actor.actor_ref.clone(),
            content_kind: input.content_kind.as_str().to_owned(),
            policy_manifest_version: input.policy_manifest_version,
            claim_id: None,
            grant_ref,
            diff_handle: binding.diff_handle,
            read_frontier_hash: binding.read_frontier_hash,
        },
    )?;
    if decision.outcome() == GateOutcome::Allow
        && let Some((grant_id, grant)) = matched_grant
    {
        touch_standing_outbound_grant_in_txn(store, wtxn, &grant_id, grant, created_at)?;
    }
    record_gate_decision_metrics(&decision);

    Ok((decision_id, decision))
}

fn standing_outbound_grant_for_effect(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
) -> Result<Option<(EntityId, StandingOutboundGrant)>> {
    let current_policy_floor = policy.read_frontier_hash()?;
    let mut candidate_ids = Vec::new();
    for principal_ref in standing_outbound_grant_candidate_principals(effect) {
        let prefix = standing_outbound_grant_principal_index_prefix(&principal_ref)?;
        for entry in store.vault_meta.prefix_iter(txn, &prefix)? {
            let (key, _) = entry?;
            let id = standing_outbound_grant_principal_index_entity_id(key, &principal_ref)?;
            if !candidate_ids.contains(&id) {
                candidate_ids.push(id);
            }
        }
    }
    for id in candidate_ids {
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("outbound grant entity row"));
        };
        let Some(header) = EntityMetadataHeader::parse(raw) else {
            return Err(Error::CorruptedIndex("outbound grant entity header"));
        };
        if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            return Err(Error::CorruptedIndex("outbound grant entity type"));
        }
        let grant = decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if !grant.is_active_under_policy(&current_policy_floor) {
            continue;
        }
        if !standing_outbound_grant_actor_matches(&grant, effect) {
            continue;
        }
        if grant.scope.matches_effect(
            &effect.verb,
            &effect.channel,
            effect.counterparty.as_deref(),
            effect.brief_ref.as_deref(),
        ) {
            return Ok(Some((id, grant)));
        }
    }
    Ok(None)
}

fn standing_outbound_grant_candidate_principals(effect: &ExternalEffectGateInput) -> Vec<String> {
    let mut principals = Vec::with_capacity(2);
    if let Some(actor_ref) = effect.actor.actor_ref.as_deref()
        && !actor_ref.trim().is_empty()
    {
        principals.push(actor_ref.trim().to_owned());
    }
    if let Some(actor_entity_ref) = effect.provenance.actor_entity_ref {
        let actor_entity_ref = actor_entity_ref.to_hex();
        if !principals
            .iter()
            .any(|principal| principal == &actor_entity_ref)
        {
            principals.push(actor_entity_ref);
        }
    }
    principals
}

fn standing_outbound_grant_actor_matches(
    grant: &StandingOutboundGrant,
    effect: &ExternalEffectGateInput,
) -> bool {
    effect
        .actor
        .actor_ref
        .as_deref()
        .is_some_and(|actor_ref| actor_ref == grant.principal_ref)
        || effect
            .provenance
            .actor_entity_ref
            .is_some_and(|actor_entity_ref| actor_entity_ref.to_hex() == grant.principal_ref)
}

fn touch_standing_outbound_grant_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    grant: StandingOutboundGrant,
    used_at: u64,
) -> Result<()> {
    let Some(raw) = store.entities.get(wtxn, id.as_bytes())? else {
        return Err(Error::EntityNotFound);
    };
    let Some(header) = EntityMetadataHeader::parse(raw) else {
        return Err(Error::CorruptedIndex("outbound grant entity header"));
    };
    if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
        return Err(Error::CorruptedIndex("outbound grant entity type"));
    }
    let touched = grant.touched(used_at)?;
    let body = encode_standing_outbound_grant_body(&touched)?;
    let mut payload = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + body.len());
    payload.push(ENTITY_TYPE_OUTBOUND_GRANT);
    payload.extend_from_slice(&header.occurred_start.to_be_bytes());
    payload.extend_from_slice(&header.occurred_end.to_be_bytes());
    payload.extend_from_slice(&header.learned_at.to_be_bytes());
    payload.extend_from_slice(&body);
    store.entities.put(wtxn, id.as_bytes(), &payload)?;
    Ok(())
}

fn hydrate_external_effect_contact(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<ExternalEffectGateInput> {
    let mut hydrated = effect.clone();
    let (Some(identity_ref), Some(counterparty)) =
        (effect.channel_identity_ref, effect.counterparty.as_deref())
    else {
        return Ok(hydrated);
    };
    if let Some(record) = counterparty_contact_for_send(store, txn, &identity_ref, counterparty)? {
        hydrated.counterparty_first_touch = Some(record.first_touch);
        if record.first_touch == CounterpartyFirstTouch::Public
            && hydrated.policy_risk == ExternalEffectPolicyRisk::Normal
        {
            hydrated.policy_risk = ExternalEffectPolicyRisk::HoldToProposal;
        }
        hydrated.counterparty_opted_out = record.is_opted_out();
        hydrated.counterparty_opt_out_receipt_reason =
            record.opt_out.map(|opt_out| opt_out.receipt_reason());
    }
    Ok(hydrated)
}

fn counterparty_contact_for_send(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    identity_ref: &EntityId,
    counterparty: &str,
) -> Result<Option<CounterpartyContactRecord>> {
    if let Some(record) =
        counterparty_contact_for_send_by_index(store, txn, identity_ref, counterparty)?
    {
        return Ok(Some(record));
    }

    for entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_COUNTERPARTY_CONTACT])?
    {
        let (key, _) = entry?;
        let Some(id) = type_index_entity_id(key, ENTITY_TYPE_COUNTERPARTY_CONTACT) else {
            return Err(Error::CorruptedIndex("counterparty contact type index key"));
        };
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("counterparty contact entity row"));
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(raw) else {
            return Err(Error::CorruptedIndex("counterparty contact entity header"));
        };
        if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
            return Err(Error::CorruptedIndex("counterparty contact entity type"));
        }
        let record =
            decode_counterparty_contact_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
        if record.matches_counterparty(identity_ref, counterparty) {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

fn counterparty_contact_for_send_by_index(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    identity_ref: &EntityId,
    counterparty: &str,
) -> Result<Option<CounterpartyContactRecord>> {
    let key = counterparty_contact_index_key(identity_ref, counterparty)?;
    let Some(raw_id) = store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    let id = decode_counterparty_contact_index_value(raw_id)?;
    let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index entity row",
        ));
    };
    let Some(header) = crate::batch::EntityMetadataHeader::parse(raw) else {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index entity header",
        ));
    };
    if header.entity_type != ENTITY_TYPE_COUNTERPARTY_CONTACT {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index entity type",
        ));
    }
    let record =
        decode_counterparty_contact_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])?;
    if !record.matches_counterparty(identity_ref, counterparty) {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index assignment",
        ));
    }
    Ok(Some(record))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateWriteMode {
    pub(crate) record_decision: bool,
    pub(crate) persist_pending_consent: bool,
    pub(crate) resolve_pending: bool,
    pub(crate) can_resolve_pending_consent: bool,
    pub(crate) include_source_in_gate_input: bool,
}

pub(crate) fn check_reserved_claim_policy(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    check_claim_source_trust(body, policy)
}

#[cfg(feature = "sync")]
pub(crate) fn check_federated_claim_admission(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    let decision = federated_claim_admission_decision(body, policy);
    record_gate_decision_metrics(&decision);
    enforce_gate_decision(decision)
}

#[cfg(feature = "sync")]
fn federated_claim_admission_decision(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> GateDecision {
    if policy.enforces_write_gate() && policy.is_fail_closed() {
        return GateDecision::deny(GateReasonCode::DenyPolicyFailClosed);
    }

    if !policy.source_trust_allows_auto(body.source, claim_sensitivity_band(body)) {
        return GateDecision::pending(vec![GateReasonCode::PendingSourceTrust]);
    }

    GateDecision::allow()
}

pub(crate) fn validate_write_envelope(envelope: &WriteEnvelope) -> Result<()> {
    if matches!(envelope.provenance().value(), &Value::Nil) {
        return Err(Error::InvalidClaimBody("write envelope missing provenance"));
    }

    Ok(())
}

fn pending_consent_dreamer_run_id(
    envelope: Option<&WriteEnvelope>,
    body: &ClaimBody,
) -> Option<String> {
    if body.approval != ClaimApprovalStatus::Proposed || body.source != Some(ClaimSource::Generated)
    {
        return None;
    }

    let envelope = envelope?;
    dreamer_run_id_from_write_envelope(envelope)
}

fn dreamer_run_id_from_write_envelope(envelope: &WriteEnvelope) -> Option<String> {
    if envelope.source() != ClaimSource::Generated
        || envelope.actor().actor_class() != EdgeActorClass::Agent
    {
        return None;
    }
    dreamer_run_id_from_provenance(envelope.provenance().value())
}

fn dreamer_run_id_from_provenance(value: &Value) -> Option<String> {
    let Value::Map(entries) = value else {
        return None;
    };
    if !entries.iter().any(|(key, value)| {
        key.as_str().is_some_and(|key| {
            key == DREAMER_PROVENANCE_RUNNER_KEY || key == DREAMER_PROVENANCE_SURFACE_KEY
        }) && value.as_str() == Some(DREAMER_RUNNER_JOB_KIND)
    }) {
        return None;
    }

    [DREAMER_PROVENANCE_RUN_ID_KEY, DREAMER_PROVENANCE_RUN_KEY]
        .into_iter()
        .find_map(|run_key| {
            entries.iter().find_map(|(key, value)| {
                if key.as_str() != Some(run_key) {
                    return None;
                }
                let run_id = value.as_str()?.trim();
                (!run_id.is_empty()).then(|| run_id.to_owned())
            })
        })
}

pub(crate) fn check_edge_provenance_claim_policy(
    body: &ClaimBody,
    record: &crate::provenance::EdgeProvenanceClaimBody,
    actor_class: EdgeActorClass,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    if policy.enforces_write_gate() {
        let input = claim_gate_input(
            body,
            policy,
            GateActor {
                actor_class: edge_actor_class_str(actor_class).to_owned(),
                actor_ref: Some(record.actor_entity_ref.to_hex()),
            },
            GateContentKind::EdgeProvenanceClaim,
            GateProvenanceHandles {
                actor_entity_ref: Some(record.actor_entity_ref),
                substrate_ref: record.substrate_ref,
                source_revision_ref: record.source_revision_ref,
                body_snapshot_ref: record.body_snapshot_ref,
                ..GateProvenanceHandles::default()
            },
            false,
        );
        let decision = policy.evaluate_gate(&input);
        record_gate_decision_metrics(&decision);
        enforce_gate_decision(decision)?;
    }

    check_claim_source_trust(body, policy)
}

fn check_claim_source_trust(body: &ClaimBody, policy: &PolicyManifestResolution) -> Result<()> {
    check_source_trust(
        body.source,
        body.approval,
        claim_sensitivity_band(body),
        &policy.source_trust,
    )
}

fn claim_gate_input(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
    actor: GateActor,
    content_kind: GateContentKind,
    provenance: GateProvenanceHandles,
    include_source: bool,
) -> GateEvaluatorInput {
    let (source, sensitivity_band) = if include_source || body.approval == ClaimApprovalStatus::Auto
    {
        (body.source, claim_sensitivity_band(body))
    } else {
        (None, None)
    };

    GateEvaluatorInput {
        actor,
        source,
        content_kind,
        sensitivity_band,
        criticality: policy.criticality_for_predicate(&body.predicate),
        policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
        provenance,
        external_effect: None,
    }
}

fn enforce_gate_decision(decision: GateDecision) -> Result<()> {
    if decision.outcome() == GateOutcome::Allow {
        return Ok(());
    }

    reject_gate_decision(decision)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GateConsentBinding {
    diff_handle: Vec<u8>,
    read_frontier_hash: [u8; 32],
}

impl GateConsentBinding {
    fn for_claim(body: &ClaimBody, policy: &PolicyManifestResolution) -> Result<Self> {
        let mut normalized = body.clone();
        normalized.approval = ClaimApprovalStatus::Proposed;
        let encoded = crate::claim::encode_claim_body(&normalized)?;
        let mut hasher = Sha256::new();
        hasher.update(b"oneiron.gate.claim_diff.v0");
        hasher.update(&encoded);
        Ok(Self {
            diff_handle: hasher.finalize().to_vec(),
            read_frontier_hash: policy.read_frontier_hash()?,
        })
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn for_external_effect(
        input: &GateEvaluatorInput,
        policy: &PolicyManifestResolution,
    ) -> Result<Self> {
        let mut hasher = Sha256::new();
        hash_bytes(&mut hasher, b"oneiron.gate.external_effect.v0");
        hash_str(&mut hasher, &input.actor.actor_class);
        hash_opt_str(&mut hasher, input.actor.actor_ref.as_deref());
        match input.provenance.actor_entity_ref {
            Some(actor_entity_ref) => {
                hash_bool(&mut hasher, true);
                hash_bytes(&mut hasher, actor_entity_ref.as_bytes());
            }
            None => hash_bool(&mut hasher, false),
        }
        match input.external_effect.as_ref() {
            Some(effect) => {
                hash_bool(&mut hasher, true);
                hash_str(&mut hasher, effect.verb.trim());
                hash_str(&mut hasher, effect.channel.trim());
                hash_opt_str(&mut hasher, effect.brief_ref.as_deref());
                hash_opt_str(&mut hasher, effect.send_ref.as_deref());
                hash_bool(&mut hasher, effect.has_opted_in);
                hash_bool(&mut hasher, effect.has_permission);
                hash_str(&mut hasher, effect.policy_risk.as_str());
            }
            None => hash_bool(&mut hasher, false),
        }
        Ok(Self {
            diff_handle: hasher.finalize().to_vec(),
            read_frontier_hash: policy.read_frontier_hash()?,
        })
    }
}

pub(crate) fn standing_outbound_grant_binding_parts(
    intent: &GrantMintIntent,
    policy: &PolicyManifestResolution,
) -> Result<(Vec<u8>, [u8; 32])> {
    let mut hasher = Sha256::new();
    hash_bytes(&mut hasher, b"oneiron.gate.standing_outbound_grant.v0");
    hash_str(&mut hasher, intent.principal_ref.trim());
    hash_str(&mut hasher, intent.origin_component_id.trim());
    hash_str(&mut hasher, intent.origin_action_id.trim());
    hash_opt_str(&mut hasher, intent.origin_receipt_ref.as_deref());
    match &intent.scope {
        GrantMintIntentScope::JustOnce { .. } => {
            return Err(Error::InvalidOutboundGrantBody(
                "non-standing grant scope is not supported",
            ));
        }
        GrantMintIntentScope::Contact { contact_ref } => {
            hash_str(&mut hasher, "contact");
            hash_str(&mut hasher, contact_ref.trim());
        }
        GrantMintIntentScope::VerbClass { verb_class } => {
            hash_str(&mut hasher, "verb_class");
            hash_str(&mut hasher, verb_class.trim());
        }
        GrantMintIntentScope::Channel { channel } => {
            hash_str(&mut hasher, "channel");
            hash_str(&mut hasher, channel.trim());
        }
        GrantMintIntentScope::BundleExactSends { .. } => {
            return Err(Error::InvalidOutboundGrantBody(
                "non-standing grant scope is not supported",
            ));
        }
        GrantMintIntentScope::BriefVerbClass {
            brief_ref,
            verb_class,
        } => {
            hash_str(&mut hasher, "brief_verb_class");
            hash_str(&mut hasher, brief_ref.trim());
            hash_str(&mut hasher, verb_class.trim());
        }
    }
    Ok((hasher.finalize().to_vec(), policy.read_frontier_hash()?))
}

fn enforce_claim_gate_decision_with_consent(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    decision: &GateDecision,
    approval: ClaimApprovalStatus,
    binding: &GateConsentBinding,
    mode: GateWriteMode,
) -> Result<()> {
    match (decision.outcome(), approval) {
        (GateOutcome::Allow, _) => {
            if mode.resolve_pending {
                resolve_pending_gate_consent_if_bound(store, wtxn, id, binding)?;
            }
            Ok(())
        }
        (GateOutcome::Pending, ClaimApprovalStatus::Proposed) => Ok(()),
        (GateOutcome::Pending, ClaimApprovalStatus::Approved) => {
            if !mode.can_resolve_pending_consent {
                return reject_gate_decision(decision.clone());
            }
            let Some(pending) = store.pending_gate_consent_in_txn(wtxn, id)? else {
                return reject_gate_decision(decision.clone());
            };
            require_pending_gate_consent_binding(id, &pending, binding)?;
            if mode.resolve_pending {
                store.delete_pending_gate_consent_in_txn(wtxn, id)?;
            }
            Ok(())
        }
        _ => reject_gate_decision(decision.clone()),
    }
}

fn resolve_pending_gate_consent_if_bound(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    binding: &GateConsentBinding,
) -> Result<()> {
    let Some(pending) = store.pending_gate_consent_in_txn(wtxn, id)? else {
        return Ok(());
    };
    require_pending_gate_consent_binding(id, &pending, binding)?;
    store.delete_pending_gate_consent_in_txn(wtxn, id)
}

fn require_pending_gate_consent_binding(
    id: &EntityId,
    pending: &PendingGateConsentRecord,
    binding: &GateConsentBinding,
) -> Result<()> {
    if pending.diff_handle != binding.diff_handle
        || pending.read_frontier_hash != binding.read_frontier_hash
    {
        return Err(Error::GateConsentStale { claim_id: *id });
    }
    Ok(())
}

fn reject_gate_decision(decision: GateDecision) -> Result<()> {
    Err(Error::GateWriteRejected {
        outcome: decision.outcome().as_str(),
        reason_codes: decision
            .reason_codes()
            .iter()
            .map(|code| code.as_str())
            .collect(),
    })
}

fn local_write_actor_entity_ref() -> EntityId {
    EntityId::from_bytes(LOCAL_WRITE_ACTOR_ENTITY_REF)
        .expect("local Gate actor entity ref is non-reserved")
}

const fn edge_actor_class_str(actor_class: EdgeActorClass) -> &'static str {
    actor_class.gate_actor_class()
}

fn check_source_trust(
    source: Option<ClaimSource>,
    approval: ClaimApprovalStatus,
    sensitivity: Option<u8>,
    ceiling: &SourceTrustCeiling,
) -> Result<()> {
    if approval != ClaimApprovalStatus::Auto {
        return Ok(());
    }

    let Some(source) = source else {
        return Ok(());
    };

    if ceiling.malformed_manifest_seen {
        return Err(Error::SourceNotTrustedForAuto {
            claim_source: source.as_str(),
        });
    }

    let Some(sensitivity) = sensitivity else {
        return Err(Error::SourceNotTrustedForAuto {
            claim_source: source.as_str(),
        });
    };

    let Some(row) = ceiling.row(source) else {
        if source.requires_explicit_auto_permit() {
            return Err(Error::SourceNotTrustedForAuto {
                claim_source: source.as_str(),
            });
        }
        return Ok(());
    };

    let Some(max_auto_sensitivity) = row.max_auto_sensitivity else {
        return Err(Error::SourceNotTrustedForAuto {
            claim_source: source.as_str(),
        });
    };

    if sensitivity > max_auto_sensitivity {
        return Err(Error::SourceNotTrustedForAuto {
            claim_source: source.as_str(),
        });
    }

    if source.requires_explicit_auto_permit() && (!row.receipted || !row.warned) {
        return Err(Error::SourceNotTrustedForAuto {
            claim_source: source.as_str(),
        });
    }

    Ok(())
}

fn type_index_entity_id(key: &[u8], entity_type: u8) -> Option<EntityId> {
    if key.len() != ENTITY_ID_LEN + 1 || key[0] != entity_type {
        return None;
    }
    EntityId::from_bytes(key[1..].try_into().ok()?).ok()
}

fn decode_policy_manifest(data: &[u8]) -> Option<DecodedPolicyManifest> {
    let mut cursor = Cursor::new(data);
    let value = rmpv::decode::read_value(&mut cursor).ok()?;
    if cursor.position() != data.len() as u64 {
        return None;
    }
    let Value::Map(entries) = value else {
        return None;
    };

    let unsupported_schema = match single_map_value(&entries, POLICY_SCHEMA_VERSION_KEY) {
        MapValue::Missing => true,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => value.as_str()? != POLICY_SCHEMA_VERSION,
    };
    let pack_id = required_string(&entries, POLICY_PACK_ID_KEY)?;
    let pack_version = required_string(&entries, POLICY_PACK_VERSION_KEY)?;
    let min_engine_version = required_string(&entries, POLICY_MIN_ENGINE_VERSION_KEY)?;
    let engine_version_floor = version_gt(&min_engine_version, env!("CARGO_PKG_VERSION"))?;
    let defaults = parse_axes(required_value(&entries, POLICY_DEFAULTS_KEY)?)?;
    let rules = parse_rules(required_value(&entries, POLICY_RULES_KEY)?)?;
    let actor_ceilings =
        parse_actor_ceilings(required_value(&entries, POLICY_ACTOR_CEILINGS_KEY)?)?;

    let source_trust = match single_map_value(&entries, POLICY_SOURCE_TRUST_KEY) {
        MapValue::Missing => SourceTrustCeiling::default(),
        MapValue::Duplicate => SourceTrustCeiling::malformed(),
        MapValue::Present(value) => {
            parse_source_trust(value).unwrap_or_else(SourceTrustCeiling::malformed)
        }
    };
    let scoped_grants = match single_map_value(&entries, POLICY_SCOPED_GRANTS_KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_scoped_grants(value)?,
    };
    let legal_floor_rows = match single_map_value(&entries, POLICY_LEGAL_FLOOR_ROWS_KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_legal_floor_rows(value)?,
    };
    let (owner_policy_rows, owner_policy_rows_dropped) =
        match single_map_value(&entries, POLICY_OWNER_POLICY_ROWS_KEY) {
            MapValue::Missing => (Vec::new(), false),
            MapValue::Duplicate => (Vec::new(), true),
            MapValue::Present(value) => match parse_owner_policy_rows(value) {
                Some(rows) => (rows, false),
                None => (Vec::new(), true),
            },
        };
    let mut signatures = match single_map_value(&entries, POLICY_SIGNATURE_KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => vec![parse_signature_value(value)?],
    };
    match single_map_value(&entries, POLICY_SIGNATURES_KEY) {
        MapValue::Missing => {}
        MapValue::Duplicate => return None,
        MapValue::Present(value) => signatures.extend(parse_signatures(value)?),
    }
    let on_budget_exhausted = match single_map_value(&entries, POLICY_ON_BUDGET_EXHAUSTED_KEY) {
        MapValue::Missing => None,
        MapValue::Duplicate => return None,
        MapValue::Present(value) => Some(parse_budget_exhaustion_policy(value)?),
    };

    let unknown_axis_seen =
        defaults.unknown_axis_seen || rules.iter().any(|rule| rule.axes.unknown_axis_seen);

    Some(DecodedPolicyManifest {
        pack: PolicyPack {
            _pack_id: pack_id,
            _pack_version: pack_version,
            _min_engine_version: min_engine_version,
            defaults,
            rules,
        },
        actor_ceilings,
        source_trust,
        scoped_grants,
        legal_floor_rows,
        owner_policy_rows,
        owner_policy_rows_dropped,
        signatures,
        on_budget_exhausted,
        unsupported_schema,
        engine_version_floor,
        unknown_axis_seen,
    })
}

fn parse_rules(value: &Value) -> Option<Vec<PolicyRule>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut rules = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let prefix = required_string(entries, RULE_PREFIX_KEY)?;
        if prefix.is_empty() {
            return None;
        }
        let exact = optional_bool(entries, RULE_EXACT_KEY)?;
        let axes = parse_axes(required_value(entries, RULE_AXES_KEY)?)?;
        rules.push(PolicyRule {
            prefix,
            exact,
            axes,
        });
    }
    Some(rules)
}

fn parse_axes(value: &Value) -> Option<PolicyAxes> {
    let Value::Map(entries) = value else {
        return None;
    };
    let mut axes = PolicyAxes::default();
    let mut criticality_seen = false;
    let mut sensitivity_seen = false;

    for (key, value) in entries {
        match key.as_str()? {
            AXIS_CRITICALITY_KEY => {
                if criticality_seen {
                    return None;
                }
                criticality_seen = true;
                axes.criticality = Some(PolicyCriticality::parse(value)?);
            }
            AXIS_SENSITIVITY_KEY => {
                if sensitivity_seen {
                    return None;
                }
                sensitivity_seen = true;
                axes.sensitivity = Some(PolicySensitivity::parse(value)?);
            }
            _ => axes.unknown_axis_seen = true,
        }
    }

    Some(axes)
}

fn parse_actor_ceilings(value: &Value) -> Option<Vec<ActorCeiling>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut actor_ceilings = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let actor_class = required_string(entries, ACTOR_CLASS_KEY)?;
        if actor_class.is_empty() {
            return None;
        }
        let actor_ref = optional_string(entries, ACTOR_REF_KEY)?;
        let ceiling = PolicyApprovalCeiling::parse(required_value(entries, ACTOR_CEILING_KEY)?)?;
        actor_ceilings.push(ActorCeiling {
            actor_class,
            actor_ref,
            ceiling,
        });
    }
    Some(actor_ceilings)
}

fn parse_source_trust(value: &Value) -> Option<SourceTrustCeiling> {
    let Value::Map(source_rows) = value else {
        return None;
    };
    let mut ceiling = SourceTrustCeiling::default();
    for (source_key, row_value) in source_rows {
        let source = source_key.as_str().and_then(ClaimSource::parse)?;
        let row = parse_source_trust_row(row_value)?;
        ceiling.set_row(source, row);
    }
    Some(ceiling)
}

fn parse_source_trust_row(value: &Value) -> Option<SourceTrustRow> {
    match value {
        Value::Boolean(false) => Some(SourceTrustRow {
            max_auto_sensitivity: None,
            receipted: false,
            warned: false,
        }),
        Value::Integer(_) | Value::String(_) => Some(SourceTrustRow {
            max_auto_sensitivity: sensitivity_band_from_value(value),
            receipted: false,
            warned: false,
        }),
        Value::Map(entries) => {
            let mut max_auto_sensitivity = None;
            let mut auto_disabled = false;
            let mut receipted = false;
            let mut warned = false;

            for (key, value) in entries {
                match key.as_str()? {
                    SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY => {
                        max_auto_sensitivity = Some(sensitivity_band_from_value(value)?);
                    }
                    SOURCE_TRUST_AUTO_KEY => match value {
                        Value::Boolean(false) => auto_disabled = true,
                        Value::Boolean(true) => {}
                        _ => return None,
                    },
                    SOURCE_TRUST_RECEIPTED_KEY => {
                        receipted = value.as_bool()?;
                    }
                    SOURCE_TRUST_WARNED_KEY => {
                        warned = value.as_bool()?;
                    }
                    _ => {}
                }
            }

            Some(SourceTrustRow {
                max_auto_sensitivity: if auto_disabled {
                    None
                } else {
                    Some(max_auto_sensitivity?)
                },
                receipted,
                warned,
            })
        }
        _ => None,
    }
}

fn parse_budget_exhaustion_policy(value: &Value) -> Option<BudgetExhaustionPolicy> {
    if let Some(policy) = value.as_str().and_then(parse_budget_exhaustion_policy_kind) {
        return Some(policy);
    }

    let Value::Map(entries) = value else {
        return None;
    };

    match single_map_value(entries, "kind") {
        MapValue::Present(kind) => match kind.as_str()? {
            "suspend" => Some(BudgetExhaustionPolicy::Suspend),
            "continue_on_local" => Some(BudgetExhaustionPolicy::ContinueOnLocal),
            "overdraft" => {
                let cap = required_value(entries, "cap")?.as_u64()?;
                Some(BudgetExhaustionPolicy::Overdraft { cap })
            }
            _ => None,
        },
        MapValue::Missing => match single_map_value(entries, "overdraft") {
            MapValue::Missing | MapValue::Duplicate => None,
            MapValue::Present(overdraft) => {
                let Value::Map(overdraft_entries) = overdraft else {
                    return None;
                };
                let cap = required_value(overdraft_entries, "cap")?.as_u64()?;
                Some(BudgetExhaustionPolicy::Overdraft { cap })
            }
        },
        MapValue::Duplicate => None,
    }
}

fn parse_budget_exhaustion_policy_kind(kind: &str) -> Option<BudgetExhaustionPolicy> {
    match kind {
        "suspend" => Some(BudgetExhaustionPolicy::Suspend),
        "continue_on_local" => Some(BudgetExhaustionPolicy::ContinueOnLocal),
        _ => None,
    }
}

fn parse_scoped_grants(value: &Value) -> Option<Vec<PolicyScopedGrant>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut grants = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let actor_class = optional_string(entries, ACTOR_CLASS_KEY)?;
        let actor_ref = optional_string(entries, ACTOR_REF_KEY)?;
        let effector = required_string(entries, GRANT_EFFECTOR_KEY)?;
        if effector.is_empty() {
            return None;
        }
        let scope = optional_value(entries, GRANT_SCOPE_KEY)?;
        let budget = optional_value(entries, GRANT_BUDGET_KEY)?;
        let receipt_required = match single_map_value(entries, GRANT_RECEIPT_REQUIRED_KEY) {
            MapValue::Missing => true,
            MapValue::Duplicate => return None,
            MapValue::Present(value) => value.as_bool()?,
        };
        grants.push(PolicyScopedGrant {
            actor_class,
            actor_ref,
            effector,
            scope,
            budget,
            receipt_required,
        });
    }
    Some(grants)
}

fn parse_legal_floor_rows(value: &Value) -> Option<Vec<PolicyLegalFloorRow>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let row_ref = required_nonempty_string(entries, POLICY_ROW_REF_KEY)?;
        let category = required_nonempty_string(entries, POLICY_ROW_CATEGORY_KEY)?;
        let subcategory = required_nonempty_string(entries, POLICY_ROW_SUBCATEGORY_KEY)?;
        let action = required_nonempty_string(entries, POLICY_ROW_ACTION_KEY)?;
        let text = required_nonempty_string(entries, POLICY_ROW_TEXT_KEY)?;
        let active = optional_bool_default(entries, POLICY_ROW_ACTIVE_KEY, true)?;
        parsed.push(PolicyLegalFloorRow {
            row_ref,
            category,
            subcategory,
            action,
            text,
            active,
        });
    }
    Some(parsed)
}

fn parse_owner_policy_rows(value: &Value) -> Option<Vec<PolicyOwnerPolicyRow>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let row_ref = required_nonempty_string(entries, POLICY_ROW_REF_KEY)?;
        let text = required_nonempty_string(entries, POLICY_ROW_TEXT_KEY)?;
        let active = optional_bool_default(entries, POLICY_ROW_ACTIVE_KEY, true)?;
        let world_ref = optional_string(entries, POLICY_ROW_WORLD_REF_KEY)?;
        let action = optional_string(entries, POLICY_ROW_ACTION_KEY)?;
        let block = match single_map_value(entries, POLICY_ROW_BLOCK_KEY) {
            MapValue::Missing => action.as_deref() == Some("block"),
            MapValue::Duplicate => return None,
            MapValue::Present(Value::Boolean(value)) => *value,
            MapValue::Present(_) => return None,
        };
        parsed.push(PolicyOwnerPolicyRow {
            row_ref,
            text,
            active,
            world_ref,
            block,
        });
    }
    Some(parsed)
}

fn required_nonempty_string(entries: &[(Value, Value)], key: &str) -> Option<String> {
    let value = required_string(entries, key)?;
    if value.is_empty() { None } else { Some(value) }
}

fn optional_bool_default(entries: &[(Value, Value)], key: &str, default: bool) -> Option<bool> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(default),
        MapValue::Duplicate => None,
        MapValue::Present(Value::Boolean(value)) => Some(*value),
        MapValue::Present(_) => None,
    }
}

fn parse_signatures(value: &Value) -> Option<Vec<PolicySignature>> {
    let Value::Array(rows) = value else {
        return None;
    };
    rows.iter().map(parse_signature_value).collect()
}

fn parse_signature_value(value: &Value) -> Option<PolicySignature> {
    match value {
        Value::String(sig) => Some(PolicySignature {
            alg: "unknown".to_owned(),
            key_id: None,
            sig: sig.as_str()?.to_owned(),
        }),
        Value::Map(entries) => {
            let alg = required_string(entries, SIGNATURE_ALG_KEY)?;
            let key_id = optional_string(entries, SIGNATURE_KEY_ID_KEY)?;
            let sig = match single_map_value(entries, SIGNATURE_SIG_KEY) {
                MapValue::Present(value) => value.as_str()?.to_owned(),
                MapValue::Missing => required_string(entries, SIGNATURE_SIGNATURE_KEY)?,
                MapValue::Duplicate => return None,
            };
            if alg.is_empty() || sig.is_empty() {
                return None;
            }
            Some(PolicySignature { alg, key_id, sig })
        }
        _ => None,
    }
}

enum MapValue<'a> {
    Missing,
    Present(&'a Value),
    Duplicate,
}

fn single_map_value<'a>(entries: &'a [(Value, Value)], needle: &str) -> MapValue<'a> {
    let mut found = None;
    for (key, value) in entries {
        if key.as_str() == Some(needle) {
            if found.is_some() {
                return MapValue::Duplicate;
            }
            found = Some(value);
        }
    }
    found.map_or(MapValue::Missing, MapValue::Present)
}

fn required_value<'a>(entries: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    match single_map_value(entries, key) {
        MapValue::Present(value) => Some(value),
        MapValue::Missing | MapValue::Duplicate => None,
    }
}

fn optional_value(entries: &[(Value, Value)], key: &str) -> Option<Option<Value>> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(None),
        MapValue::Duplicate => None,
        MapValue::Present(value) => Some(Some(value.clone())),
    }
}

fn required_string(entries: &[(Value, Value)], key: &str) -> Option<String> {
    required_value(entries, key)?.as_str().map(str::to_owned)
}

fn optional_string(entries: &[(Value, Value)], key: &str) -> Option<Option<String>> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(None),
        MapValue::Duplicate => None,
        MapValue::Present(value) => {
            let value = value.as_str()?;
            if value.is_empty() {
                None
            } else {
                Some(Some(value.to_owned()))
            }
        }
    }
}

fn optional_bool(entries: &[(Value, Value)], key: &str) -> Option<bool> {
    match single_map_value(entries, key) {
        MapValue::Missing => Some(false),
        MapValue::Duplicate => None,
        MapValue::Present(Value::Boolean(value)) => Some(*value),
        MapValue::Present(_) => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn restrict_optional<T>(left: Option<T>, right: Option<T>) -> Option<T>
where
    T: Copy + Restrict,
{
    match (left, right) {
        (Some(left), Some(right)) => Some(left.restrict(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

#[cfg_attr(not(test), allow(dead_code))]
trait Restrict {
    fn restrict(self, other: Self) -> Self;
}

impl Restrict for PolicyCriticality {
    fn restrict(self, other: Self) -> Self {
        if matches!(self, Self::Critical) || matches!(other, Self::Critical) {
            Self::Critical
        } else {
            Self::Normal
        }
    }
}

impl Restrict for PolicySensitivity {
    fn restrict(self, other: Self) -> Self {
        if matches!(self, Self::Sensitive) || matches!(other, Self::Sensitive) {
            Self::Sensitive
        } else {
            Self::Normal
        }
    }
}

fn version_gt(left: &str, right: &str) -> Option<bool> {
    let left = parse_version(left)?;
    let right = parse_version(right)?;
    Some(left > right)
}

fn parse_version(value: &str) -> Option<[u64; 3]> {
    let trimmed = value.strip_prefix('v').unwrap_or(value);
    let mut out = [0_u64; 3];
    let mut count = 0usize;
    for (index, part) in trimmed.split('.').enumerate() {
        if index >= out.len() || part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        out[index] = part.parse().ok()?;
        count += 1;
    }
    if count == 0 { None } else { Some(out) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim::{
        ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, ScopedReadActorKey,
        claim_body_decode_count, decode_claim_body, reset_claim_body_decode_count,
    };
    use crate::counterparty_contact::{
        CounterpartyContactRecord, CounterpartyContactStatus, CounterpartyFirstTouch,
        CounterpartyOptOutReason,
    };
    use crate::error::{ErrorKind, GateDenialOutcome, GateDenialReason};
    use crate::provenance::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
    use crate::receipt::{ReceiptKind, ReceiptQuery, StandingOutboundGrantsLensQuery};
    use crate::types::{
        ClaimCandidate, ContextEntity, ContextPack, ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_MACHINE,
        ENTITY_TYPE_PERSON, EdgeActorClass, EdgeConfirmationStatus, EdgeKind, EdgeProvenanceFlags,
        PackItemAccounting, PackStats, PackTokenStats, ScoredEntity, TimeRange, WriteActor,
        WriteProvenance,
    };
    use std::time::Duration;

    fn test_id(seed: u8) -> EntityId {
        EntityId::from_bytes([seed; 16]).expect("valid test id")
    }

    fn test_time(ts: u64) -> TimeRange {
        TimeRange { start: ts, end: ts }
    }

    fn temp_vault() -> (tempfile::TempDir, crate::Vault) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let vault = crate::Vault::open(tmp.path(), crate::types::VaultConfig::default())
            .expect("open vault");
        clear_policy_manifests_for_test(&vault);
        (tmp, vault)
    }

    fn clear_policy_manifests_for_test(vault: &crate::Vault) {
        vault
            .with_write_txn(|wtxn| {
                let mut ids = Vec::new();
                for row in vault
                    .store
                    .type_index
                    .prefix_iter(wtxn, &[ENTITY_TYPE_POLICY_MANIFEST])?
                {
                    let (key, _) = row?;
                    let id = EntityId::from_bytes(
                        key[1..]
                            .try_into()
                            .map_err(|_| Error::CorruptedIndex("type index key"))?,
                    )
                    .map_err(|_| Error::CorruptedIndex("type index key"))?;
                    ids.push(id);
                }
                for id in ids {
                    crate::batch::deindex_entity_for_test(&vault.store, wtxn, &id)?;
                }
                Ok(())
            })
            .expect("clear default policy manifest");
    }

    #[test]
    fn companion_profile_access_grants_allow_deny_and_revoke() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let grant_id = test_id(0xA1);
        let principal = test_id(0xB1);
        let other_principal = test_id(0xB3);
        let person = test_id(0xC1);
        let persona = test_id(0xD1);
        let other_persona = test_id(0xD2);

        assert_eq!(
            vault.companion_profile_access_grant(&principal, &person, &persona)?,
            None,
            "missing grant must fail closed"
        );

        let grant = crate::AccessGrant::companion_profile_read(principal, person, persona, 10);
        vault.create_access_grant(&grant_id, &grant)?;

        assert_eq!(
            vault.companion_profile_access_grant(&principal, &person, &persona)?,
            Some(grant_id),
            "exact active grant should authorize"
        );
        assert_eq!(
            vault.companion_profile_access_grant(&other_principal, &person, &persona)?,
            None,
            "principal mismatch must deny"
        );
        assert_eq!(
            vault.companion_profile_access_grant(&principal, &person, &other_persona)?,
            None,
            "scope mismatch must deny"
        );

        let revoked = vault.revoke_access_grant(&grant_id, 20)?;
        assert_eq!(revoked.status, crate::AccessGrantStatus::Revoked);
        assert_eq!(
            vault.companion_profile_access_grant(&principal, &person, &persona)?,
            None,
            "revoked grant must fail closed"
        );
        Ok(())
    }

    #[test]
    fn companion_profile_access_grant_fails_closed_on_malformed_record() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let malformed_id = test_id(0x01);
        let valid_id = test_id(0xA2);
        let principal = test_id(0xB2);
        let person = test_id(0xC2);
        let persona = test_id(0xD3);

        put_malformed_access_grant_bytes(&vault, &malformed_id, b"not-msgpack")?;
        let grant = crate::AccessGrant::companion_profile_read(principal, person, persona, 10);
        vault.create_access_grant(&valid_id, &grant)?;

        let err = vault
            .companion_profile_access_grant(&principal, &person, &persona)
            .expect_err("malformed AccessGrant row must fail closed before any later allow");
        assert!(
            matches!(err, Error::CorruptedIndex("access grant body")),
            "expected CorruptedIndex for malformed AccessGrant row, got {err:?}"
        );
        Ok(())
    }

    fn encode_policy_manifest(extra_entries: Vec<(Value, Value)>) -> Vec<u8> {
        let mut entries = vec![
            (
                Value::from(POLICY_SCHEMA_VERSION_KEY),
                Value::from(POLICY_SCHEMA_VERSION),
            ),
            (Value::from(POLICY_PACK_ID_KEY), Value::from("gate-test")),
            (Value::from(POLICY_PACK_VERSION_KEY), Value::from("v1")),
            (
                Value::from(POLICY_MIN_ENGINE_VERSION_KEY),
                Value::from(env!("CARGO_PKG_VERSION")),
            ),
            (
                Value::from(POLICY_DEFAULTS_KEY),
                Value::Map(vec![
                    (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                    (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                ]),
            ),
            (
                Value::from(POLICY_RULES_KEY),
                Value::Array(vec![Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("health.")),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("critical")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("sensitive")),
                        ]),
                    ),
                ])]),
            ),
            (
                Value::from(POLICY_ACTOR_CEILINGS_KEY),
                Value::Array(vec![
                    Value::Map(vec![
                        (Value::from(ACTOR_CLASS_KEY), Value::from("first_party")),
                        (Value::from(ACTOR_CEILING_KEY), Value::from("auto")),
                    ]),
                    Value::Map(vec![
                        (Value::from(ACTOR_CLASS_KEY), Value::from("first_party")),
                        (Value::from(ACTOR_REF_KEY), Value::from("probation")),
                        (Value::from(ACTOR_CEILING_KEY), Value::from("proposed")),
                    ]),
                ]),
            ),
        ];
        entries.extend(extra_entries);
        let mut out = Vec::new();
        rmpv::encode::write_value(&mut out, &Value::Map(entries)).expect("manifest encode");
        out
    }

    fn encode_first_party_eiri_default_policy_manifest() -> Vec<u8> {
        default_policy_manifest()
    }

    fn rewrite_policy_manifest_entries(
        data: &mut Vec<u8>,
        rewrite: impl FnOnce(&mut Vec<(Value, Value)>),
    ) {
        let mut cursor = Cursor::new(data.as_slice());
        let Value::Map(mut entries) = rmpv::decode::read_value(&mut cursor).expect("decode") else {
            unreachable!("test manifest is a map");
        };
        rewrite(&mut entries);
        data.clear();
        rmpv::encode::write_value(data, &Value::Map(entries)).expect("re-encode");
    }

    fn source_trust_entry(source: ClaimSource, max_auto_sensitivity: u8) -> (Value, Value) {
        let row = Value::Map(vec![
            (
                Value::from(SOURCE_TRUST_MAX_AUTO_SENSITIVITY_KEY),
                Value::from(u64::from(max_auto_sensitivity)),
            ),
            (
                Value::from(SOURCE_TRUST_RECEIPTED_KEY),
                Value::Boolean(true),
            ),
            (Value::from(SOURCE_TRUST_WARNED_KEY), Value::Boolean(true)),
        ]);
        (
            Value::from(POLICY_SOURCE_TRUST_KEY),
            Value::Map(vec![(Value::from(source.as_str()), row)]),
        )
    }

    fn source_trust_entry_without_auto_permit(
        source: ClaimSource,
        max_auto_sensitivity: u8,
    ) -> (Value, Value) {
        (
            Value::from(POLICY_SOURCE_TRUST_KEY),
            Value::Map(vec![(
                Value::from(source.as_str()),
                Value::from(u64::from(max_auto_sensitivity)),
            )]),
        )
    }

    fn actor_ceiling_row(actor_class: &str, ceiling: &str) -> Value {
        Value::Map(vec![
            (Value::from(ACTOR_CLASS_KEY), Value::from(actor_class)),
            (Value::from(ACTOR_CEILING_KEY), Value::from(ceiling)),
        ])
    }

    fn actor_ceiling_row_for_ref(actor_class: &str, actor_ref: &str, ceiling: &str) -> Value {
        Value::Map(vec![
            (Value::from(ACTOR_CLASS_KEY), Value::from(actor_class)),
            (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
            (Value::from(ACTOR_CEILING_KEY), Value::from(ceiling)),
        ])
    }

    fn replace_actor_ceilings(data: &mut Vec<u8>, rows: Vec<Value>) {
        rewrite_policy_manifest_entries(data, |entries| {
            for (key, value) in entries {
                if key.as_str() == Some(POLICY_ACTOR_CEILINGS_KEY) {
                    *value = Value::Array(rows);
                    return;
                }
            }
        });
    }

    fn append_actor_ceiling(data: &mut Vec<u8>, row: Value) {
        rewrite_policy_manifest_entries(data, |entries| {
            for (key, value) in entries {
                if key.as_str() == Some(POLICY_ACTOR_CEILINGS_KEY) {
                    let Value::Array(rows) = value else {
                        unreachable!("actor ceilings are an array");
                    };
                    rows.push(row);
                    return;
                }
            }
        });
    }

    fn trust_human_candidate_actor(data: &mut Vec<u8>) {
        append_actor_ceiling(data, actor_ceiling_row("human", "auto"));
    }

    fn scoped_grants_entry() -> (Value, Value) {
        (
            Value::from(POLICY_SCOPED_GRANTS_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(ACTOR_REF_KEY), Value::from("dreamer")),
                (Value::from(GRANT_EFFECTOR_KEY), Value::from("channel_send")),
                (
                    Value::from(GRANT_SCOPE_KEY),
                    Value::Map(vec![(Value::from("audience"), Value::from("cold"))]),
                ),
                (
                    Value::from(GRANT_RECEIPT_REQUIRED_KEY),
                    Value::Boolean(true),
                ),
            ])]),
        )
    }

    fn external_effect_scoped_grant_entry(
        actor_ref: &str,
        effector: &str,
        scope: Value,
        budget: Option<Value>,
    ) -> (Value, Value) {
        let mut row = vec![
            (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
            (Value::from(GRANT_EFFECTOR_KEY), Value::from(effector)),
            (Value::from(GRANT_SCOPE_KEY), scope),
        ];
        if let Some(budget) = budget {
            row.push((Value::from(GRANT_BUDGET_KEY), budget));
        }
        (
            Value::from(POLICY_SCOPED_GRANTS_KEY),
            Value::Array(vec![Value::Map(row)]),
        )
    }

    fn signatures_entry() -> (Value, Value) {
        (
            Value::from(POLICY_SIGNATURES_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(SIGNATURE_ALG_KEY), Value::from("ed25519")),
                (Value::from(SIGNATURE_KEY_ID_KEY), Value::from("owner")),
                (
                    Value::from(SIGNATURE_SIG_KEY),
                    Value::from("first-party-eiri-auto"),
                ),
            ])]),
        )
    }

    fn policy_manifest_blob(data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(ENTITY_TYPE_POLICY_MANIFEST);
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(data);
        payload
    }

    fn access_grant_blob(data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(ENTITY_TYPE_ACCESS_GRANT);
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(data);
        payload
    }

    #[cfg(feature = "sync")]
    fn authority_log_blob(data: &[u8]) -> Vec<u8> {
        let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(crate::types::ENTITY_TYPE_AUTHORITY_LOG);
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(data);
        payload
    }

    fn put_malformed_access_grant_bytes(
        vault: &crate::Vault,
        id: &EntityId,
        data: &[u8],
    ) -> Result<()> {
        let payload = access_grant_blob(data);

        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_ACCESS_GRANT, id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
    }

    fn put_policy_manifest_bytes(vault: &crate::Vault, seed: u8, data: &[u8]) -> Result<()> {
        let id = test_id(seed);
        let payload = policy_manifest_blob(data);

        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(ENTITY_TYPE_POLICY_MANIFEST, &id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
    }

    fn resolve(vault: &crate::Vault) -> Result<PolicyManifestResolution> {
        let rtxn = vault.store.env.read_txn()?;
        resolve_policy_manifest(&vault.store, &rtxn)
    }

    #[test]
    fn policy_manifest_budget_exhaustion_defaults_to_suspend() -> Result<()> {
        assert_eq!(
            PolicyManifestResolution::default().on_budget_exhausted(),
            BudgetExhaustionPolicy::Suspend
        );

        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x81, &encode_policy_manifest(vec![]))?;

        let policy = resolve(&vault)?;
        assert_eq!(
            policy.on_budget_exhausted(),
            BudgetExhaustionPolicy::Suspend
        );
        Ok(())
    }

    #[test]
    fn policy_manifest_budget_exhaustion_parses_continue_and_overdraft() -> Result<()> {
        let (_tmp, continue_vault) = temp_vault();
        let continue_manifest = encode_policy_manifest(vec![(
            Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
            Value::from("continue_on_local"),
        )]);
        put_policy_manifest_bytes(&continue_vault, 0x82, &continue_manifest)?;
        assert_eq!(
            resolve(&continue_vault)?.on_budget_exhausted(),
            BudgetExhaustionPolicy::ContinueOnLocal
        );

        let (_tmp, overdraft_vault) = temp_vault();
        let overdraft_manifest = encode_policy_manifest(vec![(
            Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
            Value::Map(vec![
                (Value::from("kind"), Value::from("overdraft")),
                (Value::from("cap"), Value::from(25_u64)),
            ]),
        )]);
        put_policy_manifest_bytes(&overdraft_vault, 0x83, &overdraft_manifest)?;
        assert_eq!(
            resolve(&overdraft_vault)?.on_budget_exhausted(),
            BudgetExhaustionPolicy::Overdraft { cap: 25 }
        );
        Ok(())
    }

    #[test]
    fn conflicting_budget_exhaustion_policies_fail_closed() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(
            &vault,
            0x84,
            &encode_policy_manifest(vec![(
                Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
                Value::from("continue_on_local"),
            )]),
        )?;
        put_policy_manifest_bytes(
            &vault,
            0x85,
            &encode_policy_manifest(vec![(
                Value::from(POLICY_ON_BUDGET_EXHAUSTED_KEY),
                Value::from("suspend"),
            )]),
        )?;

        let policy = resolve(&vault)?;
        assert!(policy.diagnostics().malformed_manifest_seen);
        assert!(policy.is_fail_closed());
        Ok(())
    }

    fn first_party_eiri_connector_actor_id() -> EntityId {
        EntityId::from_bytes(FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
            .expect("first-party Eiri actor fixture id")
    }

    fn first_party_eiri_connector_actor_ref() -> String {
        super::first_party_eiri_connector_actor_ref()
    }

    fn has_pending_gate_consent(vault: &crate::Vault, id: &EntityId) -> Result<bool> {
        let rtxn = vault.store.env.read_txn()?;
        Ok(vault
            .store
            .pending_gate_consent_in_txn(&rtxn, id)?
            .is_some())
    }

    fn source_trust_claim(source: ClaimSource) -> ClaimBody {
        let mut body = ClaimBody::new(
            "profile.name",
            ClaimSubject::Entity(test_id(0x21)),
            Value::from("Ada"),
            1.0,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        );
        body.source = Some(source);
        body
    }

    fn core_read_scoped_grant_entry(actor_ref: &str, scope: Value) -> (Value, Value) {
        (
            Value::from(POLICY_SCOPED_GRANTS_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
                (
                    Value::from(GRANT_EFFECTOR_KEY),
                    Value::from(SCOPED_READ_EFFECTOR_CORE_READ),
                ),
                (Value::from(GRANT_SCOPE_KEY), scope),
                (
                    Value::from(GRANT_RECEIPT_REQUIRED_KEY),
                    Value::Boolean(false),
                ),
            ])]),
        )
    }

    fn receipt_required_core_read_scoped_grant_entry(
        actor_ref: &str,
        scope: Value,
    ) -> (Value, Value) {
        (
            Value::from(POLICY_SCOPED_GRANTS_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
                (
                    Value::from(GRANT_EFFECTOR_KEY),
                    Value::from(SCOPED_READ_EFFECTOR_CORE_READ),
                ),
                (Value::from(GRANT_SCOPE_KEY), scope),
            ])]),
        )
    }

    fn budgeted_core_read_scoped_grant_entry(actor_ref: &str, scope: Value) -> (Value, Value) {
        (
            Value::from(POLICY_SCOPED_GRANTS_KEY),
            Value::Array(vec![Value::Map(vec![
                (Value::from(ACTOR_REF_KEY), Value::from(actor_ref)),
                (
                    Value::from(GRANT_EFFECTOR_KEY),
                    Value::from(SCOPED_READ_EFFECTOR_CORE_READ),
                ),
                (Value::from(GRANT_SCOPE_KEY), scope),
                (
                    Value::from(GRANT_RECEIPT_REQUIRED_KEY),
                    Value::Boolean(false),
                ),
                (
                    Value::from(GRANT_BUDGET_KEY),
                    Value::Map(vec![(Value::from("limit"), Value::from(1_u64))]),
                ),
            ])]),
        )
    }

    fn core_read_world_grant_manifest(actor_ref: &str, world: EntityId) -> Vec<u8> {
        encode_policy_manifest(vec![core_read_scoped_grant_entry(
            actor_ref,
            Value::Map(vec![(
                Value::from("world_ref"),
                Value::from(world.to_hex()),
            )]),
        )])
    }

    fn put_claim_body(vault: &crate::Vault, id: &EntityId, body: &ClaimBody) -> Result<()> {
        let data = crate::claim::encode_claim_body(body)?;
        let mut payload = Vec::with_capacity(crate::batch::ENTITY_METADATA_HEADER_LEN + data.len());
        payload.push(crate::types::ENTITY_TYPE_CLAIM);
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&1_u64.to_be_bytes());
        payload.extend_from_slice(&data);

        vault.with_write_txn(|wtxn| {
            vault.store.entities.put(wtxn, id.as_bytes(), &payload)?;
            let type_key = Store::encode_type_key(crate::types::ENTITY_TYPE_CLAIM, id);
            vault.store.type_index.put(wtxn, &type_key, &[])?;
            Ok(())
        })
    }

    fn put_claim_text_body(
        vault: &crate::Vault,
        id: &EntityId,
        text: &str,
        body: &ClaimBody,
    ) -> Result<()> {
        put_claim_body(vault, id, body)?;
        vault.batch().text(id, &[("body", text)]).commit()
    }

    fn put_text_entity(
        vault: &crate::Vault,
        id: &EntityId,
        entity_type: u8,
        text: &str,
        fields: serde_json::Value,
    ) -> Result<()> {
        let payload = rmp_serde::to_vec_named(&fields).expect("msgpack encode");
        vault
            .batch()
            .put(id, entity_type, test_time(1), 1, &payload)
            .text(id, &[("body", text)])
            .commit()
    }

    fn put_vector_entity(vault: &crate::Vault, id: &EntityId, vector: &[f32]) -> Result<()> {
        vault.put_entity(
            id,
            crate::types::ENTITY_TYPE_PERSON,
            test_time(1),
            1,
            b"vector entity",
        )?;
        vault.put_vector(id, vector)
    }

    fn put_dangling_short_id(
        vault: &crate::Vault,
        short_id: &str,
        content_hash: u8,
        id: &EntityId,
    ) -> Result<()> {
        let key = crate::batch::encode_short_id_forward_key(short_id, content_hash);
        vault.with_write_txn(|wtxn| {
            vault.store.short_ids.put(wtxn, &key, id.as_bytes())?;
            Ok(())
        })
    }

    #[cfg(feature = "sync")]
    fn source_trust_claim_data(source: ClaimSource) -> Vec<u8> {
        crate::claim::encode_claim_body(&source_trust_claim(source)).expect("claim encode")
    }

    #[cfg(feature = "sync")]
    fn federated_claim_update(id: &EntityId, body: &ClaimBody) -> Result<Vec<u8>> {
        use crate::batch::ENTITY_METADATA_HEADER_LEN;
        use crate::sync::loro_support::{export_all_updates, map_insert_bytes};
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;

        let data = crate::claim::encode_claim_body(body)?;
        let mut blob = Vec::with_capacity(ENTITY_METADATA_HEADER_LEN + data.len());
        blob.push(crate::types::ENTITY_TYPE_CLAIM);
        blob.extend_from_slice(&5_u64.to_be_bytes());
        blob.extend_from_slice(&5_u64.to_be_bytes());
        blob.extend_from_slice(&5_u64.to_be_bytes());
        blob.extend_from_slice(&data);

        let key = WindowKey::new("2026-03");
        let doc = create_window_doc("federation-remote", &key);
        map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)?;
        doc.commit();
        export_all_updates(&doc)
    }

    fn claim_candidate_from_body(body: &ClaimBody) -> ClaimCandidate {
        let mut candidate = ClaimCandidate::new(
            body.predicate.clone(),
            body.subject,
            body.value.clone(),
            body.confidence,
        )
        .with_validity(body.valid_from, body.valid_to)
        .with_stale(body.stale);
        if let Some(salience) = body.salience {
            candidate = candidate.with_salience(salience);
        }
        if let Some(evidence) = body.evidence.clone() {
            candidate = candidate.with_evidence(evidence);
        }
        if let Some(world) = body.world {
            candidate = candidate.with_world(world);
        }
        if let Some(scope) = body.scope.clone() {
            candidate = candidate.with_scope(scope);
        }
        candidate
    }

    #[test]
    fn scoped_read_actor_key_rejects_unkeyed_bulk_bypass() {
        assert!(ScopedReadActorKey::new("").is_none());
        assert!(ScopedReadActorKey::new("   ").is_none());
        assert_eq!(
            ScopedReadActorKey::new(" reader ")
                .expect("trimmed actor key")
                .actor_ref(),
            "reader"
        );
    }

    #[test]
    fn scoped_read_core_read_world_scope_contains_actor_readable_claims() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let world = test_id(0x31);
        let other_world = test_id(0x32);
        let data = encode_policy_manifest(vec![core_read_scoped_grant_entry(
            "reader",
            Value::Map(vec![(
                Value::from("world_ref"),
                Value::from(world.to_hex()),
            )]),
        )]);
        put_policy_manifest_bytes(&vault, 0x61, &data)?;
        let policy = resolve(&vault)?;
        let actor_key = ScopedReadActorKey::new("reader").expect("actor key");
        assert_eq!(policy.scoped_grants().len(), 1);
        assert_eq!(
            policy.scoped_grants()[0].actor_ref.as_deref(),
            Some("reader")
        );
        assert_eq!(
            policy.scoped_grants()[0].effector,
            SCOPED_READ_EFFECTOR_CORE_READ
        );
        assert!(scoped_read_entity_id_from_value(&Value::from(world.to_hex())).is_some());

        let base_id = test_id(0xA0);
        let allowed_id = test_id(0xA1);
        let denied_id = test_id(0xA2);

        let base = source_trust_claim(ClaimSource::UserStated);
        let mut allowed = source_trust_claim(ClaimSource::UserStated);
        allowed.world = Some(world);
        let mut denied = source_trust_claim(ClaimSource::UserStated);
        denied.world = Some(other_world);
        put_claim_body(&vault, &base_id, &base)?;
        put_claim_body(&vault, &allowed_id, &allowed)?;
        put_claim_body(&vault, &denied_id, &denied)?;

        assert!(scoped_read_claim_allowed(&policy, &actor_key, &base, &[]));
        assert!(scoped_read_claim_allowed(
            &policy,
            &actor_key,
            &allowed,
            &[]
        ));
        assert!(!scoped_read_claim_allowed(
            &policy,
            &actor_key,
            &denied,
            &[]
        ));

        let scoped_read = vault.scoped_read(actor_key);
        let ids: Vec<_> = scoped_read
            .filter_scored_entities(vec![
                ScoredEntity {
                    id: base_id,
                    score: 1.0,
                },
                ScoredEntity {
                    id: allowed_id,
                    score: 0.9,
                },
                ScoredEntity {
                    id: denied_id,
                    score: 0.8,
                },
            ])?
            .into_iter()
            .map(|result| result.id)
            .collect();
        assert_eq!(ids, vec![base_id, allowed_id]);

        let other_actor =
            vault.scoped_read(ScopedReadActorKey::new("other-reader").expect("actor key"));
        assert!(
            other_actor
                .filter_scored_entities(vec![ScoredEntity {
                    id: allowed_id,
                    score: 1.0,
                }])?
                .is_empty(),
            "a core:read grant for one actor must not create a vault-wide read lane"
        );

        Ok(())
    }

    #[test]
    fn scoped_read_receipt_required_core_grants_fail_closed_without_receipt() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let world = test_id(0x33);
        let data = encode_policy_manifest(vec![receipt_required_core_read_scoped_grant_entry(
            "reader",
            Value::Map(vec![(
                Value::from("world_ref"),
                Value::from(world.to_hex()),
            )]),
        )]);
        put_policy_manifest_bytes(&vault, 0x6C, &data)?;

        let id = test_id(0x34);
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.world = Some(world);
        put_claim_body(&vault, &id, &body)?;

        let policy = resolve(&vault)?;
        assert_eq!(policy.scoped_grants().len(), 1);
        assert!(policy.scoped_grants()[0].receipt_required);
        let actor_key = ScopedReadActorKey::new("reader").expect("actor key");
        assert!(
            !scoped_read_claim_allowed(&policy, &actor_key, &body, &[]),
            "ScopedReadActorKey does not carry a consent receipt, so receipt-required grants must fail closed"
        );

        let scoped_read = vault.scoped_read(actor_key);
        assert!(scoped_read.get(&id)?.is_none());
        Ok(())
    }

    #[test]
    fn scoped_read_budgeted_core_grants_fail_closed_without_budget_enforcer() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let world = test_id(0x3A);
        let data = encode_policy_manifest(vec![budgeted_core_read_scoped_grant_entry(
            "reader",
            Value::Map(vec![(
                Value::from("world_ref"),
                Value::from(world.to_hex()),
            )]),
        )]);
        put_policy_manifest_bytes(&vault, 0x3B, &data)?;

        let id = test_id(0x3C);
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.world = Some(world);
        put_claim_body(&vault, &id, &body)?;

        let policy = resolve(&vault)?;
        assert_eq!(policy.scoped_grants().len(), 1);
        assert!(policy.scoped_grants()[0].budget.is_some());
        let actor_key = ScopedReadActorKey::new("reader").expect("actor key");
        assert!(
            !scoped_read_claim_allowed(&policy, &actor_key, &body, &[]),
            "ScopedRead has no read-budget counter or receipt state, so budgeted grants must fail closed"
        );

        let scoped_read = vault.scoped_read(actor_key);
        assert!(scoped_read.get(&id)?.is_none());
        Ok(())
    }

    #[test]
    fn scoped_read_without_core_grants_preserves_claim_surfaceable_gate() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x62, &encode_policy_manifest(vec![]))?;

        let live_id = test_id(0xB0);
        let proposed_id = test_id(0xB1);
        let stale_id = test_id(0xB2);

        let live = source_trust_claim(ClaimSource::UserStated);
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let mut stale = source_trust_claim(ClaimSource::UserStated);
        stale.stale = true;

        assert!(crate::claim::claim_surfaceable(&live));
        assert!(!crate::claim::claim_surfaceable(&proposed));
        assert!(!crate::claim::claim_surfaceable(&stale));

        put_claim_body(&vault, &live_id, &live)?;
        put_claim_body(&vault, &proposed_id, &proposed)?;
        put_claim_body(&vault, &stale_id, &stale)?;

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        assert!(scoped_read.get(&live_id)?.is_some());
        assert!(scoped_read.get(&proposed_id)?.is_none());
        assert!(scoped_read.get(&stale_id)?.is_none());

        let visible: Vec<_> = scoped_read
            .filter_scored_entities(vec![
                ScoredEntity {
                    id: live_id,
                    score: 1.0,
                },
                ScoredEntity {
                    id: proposed_id,
                    score: 0.9,
                },
                ScoredEntity {
                    id: stale_id,
                    score: 0.8,
                },
            ])?
            .into_iter()
            .map(|result| result.id)
            .collect();
        assert_eq!(visible, vec![live_id]);
        Ok(())
    }

    #[test]
    fn scoped_read_search_candidate_limit_is_not_widened_without_core_read_grants() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x6D, &encode_policy_manifest(vec![]))?;
        for seed in 0x35..=0x38 {
            put_text_entity(
                &vault,
                &test_id(seed),
                crate::types::ENTITY_TYPE_PERSON,
                "nowiden",
                serde_json::json!({"name": format!("person-{seed}")}),
            )?;
        }

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        assert_eq!(scoped_read.search_candidate_limit(1, true, false)?, 1);
        Ok(())
    }

    #[test]
    fn scoped_read_hybrid_candidate_limit_uses_text_vector_union() -> Result<()> {
        let _tmp = tempfile::tempdir().expect("temp dir");
        let mut config = crate::types::VaultConfig::device();
        config.dimensions = 4;
        config.embedding_model = Some("scoped-read-test-model".to_owned());
        let vault = crate::Vault::open(_tmp.path(), config)?;
        let world = test_id(0x39);
        put_policy_manifest_bytes(
            &vault,
            0x3D,
            &core_read_world_grant_manifest("reader", world),
        )?;
        for seed in [0x3E, 0x3F] {
            put_text_entity(
                &vault,
                &test_id(seed),
                crate::types::ENTITY_TYPE_PERSON,
                "hybrid-union",
                serde_json::json!({"name": format!("text-{seed}")}),
            )?;
        }
        for (seed, vector) in [
            (0x40, [1.0_f32, 0.0, 0.0, 0.0]),
            (0x41, [0.0_f32, 1.0, 0.0, 0.0]),
            (0x42, [0.0_f32, 0.0, 1.0, 0.0]),
        ] {
            put_vector_entity(&vault, &test_id(seed), &vector)?;
        }

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        assert_eq!(scoped_read.search_candidate_limit(1, true, false)?, 2);
        assert_eq!(scoped_read.search_candidate_limit(1, false, true)?, 3);
        assert_eq!(
            scoped_read.search_candidate_limit(1, true, true)?,
            5,
            "hybrid scoped search must fetch the possible text/vector union before actor filtering"
        );
        Ok(())
    }

    #[test]
    fn scoped_read_core_grant_preserves_claim_surfaceable_gate() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let world = test_id(0xC0);
        put_policy_manifest_bytes(
            &vault,
            0x63,
            &core_read_world_grant_manifest("reader", world),
        )?;

        let live_id = test_id(0xC1);
        let proposed_id = test_id(0xC2);
        let mut live = source_trust_claim(ClaimSource::UserStated);
        live.world = Some(world);
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.world = Some(world);
        proposed.approval = ClaimApprovalStatus::Proposed;
        put_claim_body(&vault, &live_id, &live)?;
        put_claim_body(&vault, &proposed_id, &proposed)?;

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        assert!(scoped_read.get(&live_id)?.is_some());
        assert!(
            scoped_read.get(&proposed_id)?.is_none(),
            "matching scoped grant must still preserve claim_surfaceable"
        );
        let visible: Vec<_> = scoped_read
            .filter_scored_entities(vec![
                ScoredEntity {
                    id: proposed_id,
                    score: 1.0,
                },
                ScoredEntity {
                    id: live_id,
                    score: 0.9,
                },
            ])?
            .into_iter()
            .map(|result| result.id)
            .collect();
        assert_eq!(visible, vec![live_id]);
        Ok(())
    }

    #[test]
    fn scoped_read_search_filters_before_limit_truncation() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let allowed_world = test_id(0xC3);
        let denied_world = test_id(0xC4);
        put_policy_manifest_bytes(
            &vault,
            0x64,
            &core_read_world_grant_manifest("reader", allowed_world),
        )?;

        let denied_ids = [
            test_id(0xC5),
            test_id(0xC6),
            test_id(0xC7),
            test_id(0xC8),
            test_id(0xC9),
        ];
        for (index, id) in denied_ids.iter().enumerate() {
            let mut body = source_trust_claim(ClaimSource::UserStated);
            body.world = Some(denied_world);
            let text = std::iter::repeat_n("scopedslots", 10 - index)
                .collect::<Vec<_>>()
                .join(" ");
            put_claim_text_body(&vault, id, &text, &body)?;
        }

        let allowed_id = test_id(0xCA);
        let mut allowed = source_trust_claim(ClaimSource::UserStated);
        allowed.world = Some(allowed_world);
        put_claim_text_body(&vault, &allowed_id, "scopedslots", &allowed)?;

        let unscoped_top = vault.search_text("scopedslots", denied_ids.len())?;
        assert!(
            !unscoped_top.iter().any(|hit| hit.id == allowed_id),
            "test setup must place denied hits ahead of the allowed claim"
        );

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        let visible: Vec<_> = scoped_read
            .search_text("scopedslots", 1)?
            .into_iter()
            .map(|hit| hit.id)
            .collect();
        assert_eq!(visible, vec![allowed_id]);
        Ok(())
    }

    #[test]
    fn scoped_read_hydrate_preserves_dangling_short_id_result() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x65, &encode_policy_manifest(vec![]))?;

        let missing_id = test_id(0xCB);
        put_dangling_short_id(&vault, "cldangling", 0x5A, &missing_id)?;

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        let hydrated = scoped_read
            .hydrate_short_id("cldangling", 0x5A)?
            .expect("dangling short id should surface deletion metadata");
        assert_eq!(hydrated.id, missing_id);
        assert!(hydrated.body.is_none());
        assert_eq!(
            hydrated
                .deletion
                .expect("dangling short id deletion")
                .source,
            crate::types::HydratedShortIdDeletionSource::DanglingShortId
        );
        Ok(())
    }

    #[test]
    fn scoped_read_hydrate_preserves_deleted_claim_short_id_metadata() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x6F, &encode_policy_manifest(vec![]))?;

        let claim_id = test_id(0xD0);
        put_claim_body(
            &vault,
            &claim_id,
            &source_trust_claim(ClaimSource::UserStated),
        )?;
        let short_id = "cldeleted";
        let content_hash = 0x5B;
        put_dangling_short_id(&vault, short_id, content_hash, &claim_id)?;

        let outcome = vault
            .delete_entity_with_reason(&claim_id, crate::deletion::DeleteReason::UserDelete)?;
        assert!(outcome.existed);

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        let hydrated = scoped_read
            .hydrate_short_id(short_id, content_hash)?
            .expect("deleted claim short id should preserve deletion metadata");
        assert_eq!(hydrated.id, claim_id);
        assert_eq!(hydrated.entity_type, crate::types::ENTITY_TYPE_CLAIM);
        assert!(hydrated.body.is_none());
        let deletion = hydrated.deletion.expect("deleted claim metadata");
        assert!(matches!(
            deletion.source,
            crate::types::HydratedShortIdDeletionSource::Tombstone
                | crate::types::HydratedShortIdDeletionSource::PendingTombstone
        ));
        assert_eq!(
            deletion.reason,
            Some(crate::types::HydratedShortIdDeletionReason::UserDelete)
        );
        assert!(!deletion.hard);
        Ok(())
    }

    #[test]
    fn scoped_read_context_pack_scrubs_edges_to_denied_claims() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let allowed_world = test_id(0xCC);
        let denied_world = test_id(0xCD);
        put_policy_manifest_bytes(
            &vault,
            0x66,
            &core_read_world_grant_manifest("reader", allowed_world),
        )?;

        let source = test_id(0xCE);
        let denied_claim = test_id(0xCF);
        let claim_subject = test_id(0x21);
        put_text_entity(
            &vault,
            &source,
            crate::types::ENTITY_TYPE_TURN,
            "edgevisible",
            serde_json::json!({"text": "edgevisible"}),
        )?;
        put_text_entity(
            &vault,
            &claim_subject,
            crate::types::ENTITY_TYPE_PERSON,
            "claim subject",
            serde_json::json!({"name": "subject"}),
        )?;
        let mut denied = source_trust_claim(ClaimSource::UserStated);
        denied.world = Some(denied_world);
        put_claim_body(&vault, &denied_claim, &denied)?;
        vault.put_edge(&source, EdgeKind::Supports, &denied_claim, 0.7)?;

        let mut pack = vault
            .context_pack()
            .search_text("edgevisible", 10)
            .include_edges(true)
            .run()?;
        assert!(
            pack.results
                .iter()
                .flat_map(|entity| entity.edges.iter().flatten())
                .any(|edge| edge.target == denied_claim),
            "test setup should hydrate the denied target edge before scoped filtering"
        );

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        scoped_read.filter_context_pack(&mut pack)?;
        let leaked = pack
            .results
            .iter()
            .chain(pack.neighbors.iter())
            .flat_map(|entity| entity.edges.iter().flatten())
            .any(|edge| edge.target == denied_claim);
        assert!(
            !leaked,
            "scoped context-pack edges must not reveal denied claims"
        );
        Ok(())
    }

    #[test]
    fn scoped_read_context_pack_drops_neighbors_reached_only_from_filtered_results() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let facet = test_id(0x6E);
        put_policy_manifest_bytes(
            &vault,
            0x70,
            &encode_policy_manifest(vec![core_read_scoped_grant_entry(
                "reader",
                Value::Map(vec![(Value::from("facet"), Value::from(facet.to_hex()))]),
            )]),
        )?;

        let denied_seed = test_id(0x71);
        let readable_neighbor = test_id(0x72);
        put_text_entity(
            &vault,
            &facet,
            crate::types::ENTITY_TYPE_FACET,
            "facet",
            serde_json::json!({"name": "facet"}),
        )?;
        put_text_entity(
            &vault,
            &test_id(0x21),
            crate::types::ENTITY_TYPE_PERSON,
            "claim subject",
            serde_json::json!({"name": "subject"}),
        )?;
        let denied = source_trust_claim(ClaimSource::UserStated);
        put_claim_text_body(&vault, &denied_seed, "neighborleak", &denied)?;
        put_text_entity(
            &vault,
            &readable_neighbor,
            crate::types::ENTITY_TYPE_PERSON,
            "neighbor target",
            serde_json::json!({"name": "neighbor"}),
        )?;
        vault.put_edge(&denied_seed, EdgeKind::Mentions, &readable_neighbor, 0.9)?;

        let mut pack = vault
            .context_pack()
            .search_text("neighborleak", 10)
            .edge_hop(1)
            .max_neighbors(10)
            .run()?;
        assert!(
            pack.results.iter().any(|entity| entity.id == denied_seed),
            "test setup should surface the denied primary result before scoped filtering"
        );
        assert!(
            pack.neighbors
                .iter()
                .any(|entity| entity.id == readable_neighbor),
            "test setup should expand to the readable neighbor before scoped filtering"
        );

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        scoped_read.filter_context_pack(&mut pack)?;
        assert!(
            pack.results.is_empty(),
            "the denied primary seed should be removed"
        );
        assert!(
            pack.neighbors.is_empty(),
            "neighbors reached only through a denied primary seed must not remain visible"
        );
        Ok(())
    }

    #[test]
    fn scoped_read_context_pack_retains_neighbors_reached_from_kept_results_without_edges()
    -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let allowed_world = test_id(0x73);
        let denied_world = test_id(0x74);
        put_policy_manifest_bytes(
            &vault,
            0x75,
            &core_read_world_grant_manifest("reader", allowed_world),
        )?;

        let kept_seed = test_id(0x76);
        let denied_seed = test_id(0x77);
        let readable_neighbor = test_id(0x78);
        put_text_entity(
            &vault,
            &kept_seed,
            crate::types::ENTITY_TYPE_TURN,
            "kept seed",
            serde_json::json!({"text": "kept seed"}),
        )?;
        put_text_entity(
            &vault,
            &readable_neighbor,
            crate::types::ENTITY_TYPE_PERSON,
            "readable neighbor",
            serde_json::json!({"name": "readable neighbor"}),
        )?;
        let mut denied = source_trust_claim(ClaimSource::UserStated);
        denied.world = Some(denied_world);
        put_claim_body(&vault, &denied_seed, &denied)?;
        vault.put_edge(&kept_seed, EdgeKind::Mentions, &readable_neighbor, 0.9)?;

        let entity = |id: EntityId, entity_type: u8, score: f32| ContextEntity {
            id,
            short_id: id.to_hex(),
            content_hash: 0,
            entity_type,
            score,
            fields: None,
            edges: None,
            vector: None,
        };
        let mut pack = ContextPack {
            results: vec![
                entity(kept_seed, crate::types::ENTITY_TYPE_TURN, 1.0),
                entity(denied_seed, crate::types::ENTITY_TYPE_CLAIM, 0.9),
            ],
            neighbors: vec![entity(
                readable_neighbor,
                crate::types::ENTITY_TYPE_PERSON,
                0.0,
            )],
            stats: PackStats {
                candidates_considered: 2,
                signals_used: Vec::new(),
                query_time_us: 0,
                entities_hydrated: 2,
                neighbors_hydrated: 1,
                cosine_ghosts_dampened: 0,
                claims_suppressed: 0,
                tokens: PackTokenStats::default(),
                items_truncated: PackItemAccounting::item_budget(),
                items_dropped: PackItemAccounting::token_budget(),
            },
            empty: None,
        };

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        scoped_read.filter_context_pack(&mut pack)?;
        assert_eq!(
            pack.results
                .iter()
                .map(|entity| entity.id)
                .collect::<Vec<_>>(),
            vec![kept_seed]
        );
        assert_eq!(
            pack.neighbors
                .iter()
                .map(|entity| entity.id)
                .collect::<Vec<_>>(),
            vec![readable_neighbor],
            "omitted serialized edges must not cause readable neighbors from kept seeds to be pruned"
        );
        Ok(())
    }

    #[test]
    fn scoped_read_context_pack_filters_before_response_limit() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let facet = test_id(0xE1);
        put_policy_manifest_bytes(
            &vault,
            0x6B,
            &encode_policy_manifest(vec![core_read_scoped_grant_entry(
                "reader",
                Value::Map(vec![(Value::from("facet"), Value::from(facet.to_hex()))]),
            )]),
        )?;
        put_text_entity(
            &vault,
            &test_id(0x21),
            crate::types::ENTITY_TYPE_PERSON,
            "claim subject",
            serde_json::json!({"name": "subject"}),
        )?;
        put_text_entity(
            &vault,
            &facet,
            crate::types::ENTITY_TYPE_FACET,
            "facet",
            serde_json::json!({"name": "facet"}),
        )?;

        let denied_ids = [test_id(0xE3), test_id(0xE4), test_id(0xE5), test_id(0xE6)];
        for (index, id) in denied_ids.iter().enumerate() {
            let body = source_trust_claim(ClaimSource::UserStated);
            let text = std::iter::repeat_n("packslots", 8 - index)
                .collect::<Vec<_>>()
                .join(" ");
            put_claim_text_body(&vault, id, &text, &body)?;
        }

        let allowed_id = test_id(0xE7);
        let allowed = source_trust_claim(ClaimSource::UserStated);
        put_claim_text_body(&vault, &allowed_id, "packslots", &allowed)?;
        vault.put_edge(&allowed_id, EdgeKind::FacetOf, &facet, 0.7)?;

        let unscoped_top = vault
            .context_pack()
            .limit(denied_ids.len())
            .search_text("packslots", denied_ids.len())
            .run()?;
        assert!(
            !unscoped_top
                .results
                .iter()
                .any(|entity| entity.id == allowed_id),
            "test setup must place denied pack results ahead of the allowed claim"
        );

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        let candidate_limit = scoped_read.search_candidate_limit(1, true, false)?;
        let mut pack = vault
            .context_pack()
            .limit(candidate_limit)
            .retrieval_budget(crate::types::ContextPackRetrievalBudget::new(
                candidate_limit,
                candidate_limit,
                candidate_limit,
                candidate_limit,
                candidate_limit,
                crate::context_pack::DEFAULT_MAX_NEIGHBORS,
            ))
            .search_text("packslots", candidate_limit)
            .run()?;
        scoped_read.filter_context_pack(&mut pack)?;
        pack.results.truncate(1);
        assert_eq!(pack.results.len(), 1);
        assert_eq!(pack.results[0].id, allowed_id);
        Ok(())
    }

    #[test]
    fn scoped_read_memory_timeline_prunes_links_to_filtered_records() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let allowed_world = test_id(0xD0);
        let denied_world = test_id(0xD1);
        put_policy_manifest_bytes(
            &vault,
            0x67,
            &core_read_world_grant_manifest("reader", allowed_world),
        )?;

        let old = test_id(0xD2);
        let new = test_id(0xD3);
        let mut denied = source_trust_claim(ClaimSource::UserStated);
        denied.world = Some(denied_world);
        let mut allowed = source_trust_claim(ClaimSource::UserStated);
        allowed.world = Some(allowed_world);
        put_claim_body(&vault, &old, &denied)?;
        put_claim_body(&vault, &new, &allowed)?;
        vault.put_edge(&new, EdgeKind::Supersedes, &old, 0.3)?;

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        let timeline = scoped_read.memory_timeline(&new)?;
        assert_eq!(timeline.records.len(), 1);
        let record = &timeline.records[0];
        assert_eq!(record.id, new);
        assert!(record.supersedes.is_empty());
        assert!(record.superseded_by.is_empty());
        Ok(())
    }

    #[test]
    fn scoped_read_memory_timeline_rejects_unreadable_anchor() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let allowed_world = test_id(0xD7);
        let denied_world = test_id(0xD8);
        put_policy_manifest_bytes(
            &vault,
            0x69,
            &core_read_world_grant_manifest("reader", allowed_world),
        )?;

        let old = test_id(0xD9);
        let denied_anchor = test_id(0xDA);
        let mut allowed = source_trust_claim(ClaimSource::UserStated);
        allowed.world = Some(allowed_world);
        let mut denied = source_trust_claim(ClaimSource::UserStated);
        denied.world = Some(denied_world);
        put_claim_body(&vault, &old, &allowed)?;
        put_claim_body(&vault, &denied_anchor, &denied)?;
        vault.put_edge(&denied_anchor, EdgeKind::Supersedes, &old, 0.3)?;

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        let timeline = scoped_read.memory_timeline(&denied_anchor)?;
        assert!(
            timeline.records.is_empty(),
            "unreadable anchors must not reveal readable chain neighbors"
        );
        Ok(())
    }

    #[test]
    fn scoped_read_edges_out_scrubs_denied_sources_and_targets() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let allowed_world = test_id(0xDB);
        let denied_world = test_id(0xDC);
        put_policy_manifest_bytes(
            &vault,
            0x6A,
            &core_read_world_grant_manifest("reader", allowed_world),
        )?;

        let source = test_id(0xDD);
        let allowed_claim = test_id(0xDE);
        let denied_claim = test_id(0xDF);
        put_text_entity(
            &vault,
            &source,
            crate::types::ENTITY_TYPE_TURN,
            "source",
            serde_json::json!({"text": "source"}),
        )?;
        let mut allowed = source_trust_claim(ClaimSource::UserStated);
        allowed.world = Some(allowed_world);
        let mut denied = source_trust_claim(ClaimSource::UserStated);
        denied.world = Some(denied_world);
        put_claim_body(&vault, &allowed_claim, &allowed)?;
        put_claim_body(&vault, &denied_claim, &denied)?;
        vault.put_edge(&source, EdgeKind::Supports, &allowed_claim, 0.7)?;
        vault.put_edge(&source, EdgeKind::Opposes, &denied_claim, 0.7)?;

        let denied_source = test_id(0xE0);
        put_claim_body(&vault, &denied_source, &denied)?;
        vault.put_edge(&denied_source, EdgeKind::Supports, &allowed_claim, 0.7)?;

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        let edges = scoped_read
            .edges_out(&source)?
            .expect("readable source should return scoped edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].target, allowed_claim);
        assert!(
            scoped_read.edges_out(&denied_source)?.is_none(),
            "denied edge sources must not reveal outgoing relationships"
        );
        Ok(())
    }

    #[test]
    fn scoped_read_facet_grants_match_facet_of_edges() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let facet = test_id(0xD4);
        put_policy_manifest_bytes(
            &vault,
            0x68,
            &encode_policy_manifest(vec![core_read_scoped_grant_entry(
                "reader",
                Value::Map(vec![(Value::from("facet"), Value::from(facet.to_hex()))]),
            )]),
        )?;
        put_text_entity(
            &vault,
            &facet,
            crate::types::ENTITY_TYPE_FACET,
            "facet",
            serde_json::json!({"name": "facet"}),
        )?;

        let faceted_claim = test_id(0xD5);
        let unfaceted_claim = test_id(0xD6);
        let body = source_trust_claim(ClaimSource::UserStated);
        put_claim_body(&vault, &faceted_claim, &body)?;
        put_claim_body(&vault, &unfaceted_claim, &body)?;
        vault.put_edge(&faceted_claim, EdgeKind::FacetOf, &facet, 0.7)?;

        let scoped_read = vault.scoped_read(ScopedReadActorKey::new("reader").expect("actor key"));
        assert!(
            scoped_read.get(&faceted_claim)?.is_some(),
            "facet grant must match the claim's outgoing FacetOf edge"
        );
        assert!(
            scoped_read.get(&unfaceted_claim)?.is_none(),
            "facet grant must not fall through to unfaceted claims"
        );
        Ok(())
    }

    fn claim_candidate_write_parts(
        vault: &crate::Vault,
        body: &ClaimBody,
    ) -> Result<(ClaimCandidate, WriteEnvelope)> {
        let actor = test_id(0x20);
        claim_candidate_write_parts_for_actor(vault, body, actor, EdgeActorClass::Human)
    }

    fn claim_candidate_write_parts_for_actor(
        vault: &crate::Vault,
        body: &ClaimBody,
        actor: EntityId,
        actor_class: EdgeActorClass,
    ) -> Result<(ClaimCandidate, WriteEnvelope)> {
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, test_time(1), 1, b"gate actor")?;
        if let ClaimSubject::Entity(subject) = body.subject {
            vault.put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                test_time(1),
                1,
                b"gate subject",
            )?;
        }
        let source = body.source.unwrap_or(ClaimSource::UserStated);
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, actor_class),
            source,
            WriteProvenance::new(Value::from("gate-test"))?,
            body.approval,
        );
        Ok((claim_candidate_from_body(body), envelope))
    }

    fn dreamer_claim_candidate_write_parts(
        vault: &crate::Vault,
        body: &ClaimBody,
        actor: EntityId,
        run_id: &str,
    ) -> Result<(ClaimCandidate, WriteEnvelope)> {
        vault.put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            test_time(1),
            1,
            b"dreamer actor",
        )?;
        if let ClaimSubject::Entity(subject) = body.subject {
            vault.put_entity(
                &subject,
                ENTITY_TYPE_PERSON,
                test_time(1),
                1,
                b"dreamer subject",
            )?;
        }
        let envelope = WriteEnvelope::new(
            WriteActor::new(actor, EdgeActorClass::Agent),
            ClaimSource::Generated,
            WriteProvenance::new(Value::Map(vec![
                (
                    Value::from(DREAMER_PROVENANCE_RUNNER_KEY),
                    Value::from(DREAMER_RUNNER_JOB_KIND),
                ),
                (
                    Value::from(DREAMER_PROVENANCE_RUN_ID_KEY),
                    Value::from(run_id),
                ),
            ]))?,
            body.approval,
        );
        Ok((claim_candidate_from_body(body), envelope))
    }

    fn gate_evaluator_input(
        actor_class: &str,
        actor_ref: Option<&str>,
        source: ClaimSource,
        criticality: PolicyCriticality,
    ) -> GateEvaluatorInput {
        GateEvaluatorInput {
            actor: GateActor {
                actor_class: actor_class.to_owned(),
                actor_ref: actor_ref.map(str::to_owned),
            },
            source: Some(source),
            content_kind: GateContentKind::Claim,
            sensitivity_band: Some(0),
            criticality,
            policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
            provenance: GateProvenanceHandles {
                actor_entity_ref: Some(test_id(0xA0)),
                substrate_ref: Some(test_id(0xA1)),
                source_revision_ref: Some([0xA2; ENTITY_ID_LEN]),
                body_snapshot_ref: Some([0xA3; ENTITY_ID_LEN]),
                ..GateProvenanceHandles::default()
            },
            external_effect: None,
        }
    }

    fn external_effect_gate_input(
        actor_ref: &str,
        verb: &str,
        channel: &str,
    ) -> ExternalEffectGateInput {
        ExternalEffectGateInput {
            actor: GateActor {
                actor_class: "first_party".to_owned(),
                actor_ref: Some(actor_ref.to_owned()),
            },
            provenance: GateProvenanceHandles {
                actor_entity_ref: Some(test_id(0xE0)),
                ..GateProvenanceHandles::default()
            },
            verb: verb.to_owned(),
            channel: channel.to_owned(),
            channel_identity_ref: None,
            counterparty: None,
            brief_ref: None,
            send_ref: None,
            standing_grant_ref: None,
            counterparty_first_touch: None,
            counterparty_opted_out: false,
            counterparty_opt_out_receipt_reason: None,
            has_opted_in: true,
            has_permission: true,
            policy_risk: ExternalEffectPolicyRisk::Normal,
        }
    }

    fn gate_reason_strs(decision: &GateDecision) -> Vec<&'static str> {
        decision
            .reason_codes()
            .iter()
            .map(|code| code.as_str())
            .collect()
    }

    fn assert_auto_source_rejected(
        vault: &crate::Vault,
        seed: u8,
        source: ClaimSource,
    ) -> Result<()> {
        let id = test_id(seed);
        let body = source_trust_claim(source);
        let (candidate, envelope) = claim_candidate_write_parts(vault, &body)?;
        let err = vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(6), 6)
            .commit()
            .expect_err("manifest must reject risky auto source");
        assert!(
            matches!(err, Error::SourceNotTrustedForAuto { claim_source: got } if got == source.as_str()),
            "expected source trust error for {}, got {err:?}",
            source.as_str()
        );
        assert!(vault.get_raw(&id)?.is_none());
        Ok(())
    }

    fn assert_auto_source_gate_rejected(
        vault: &crate::Vault,
        seed: u8,
        source: ClaimSource,
        outcome: &'static str,
        reason_codes: &[&'static str],
    ) -> Result<()> {
        let id = test_id(seed);
        let body = source_trust_claim(source);
        let (candidate, envelope) = claim_candidate_write_parts(vault, &body)?;
        let err = vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(6), 6)
            .commit()
            .expect_err("active policy write gate must reject risky auto source");
        assert_gate_rejected(err, outcome, reason_codes);
        assert!(vault.get_raw(&id)?.is_none());
        Ok(())
    }

    fn assert_gate_rejected(err: Error, outcome: &'static str, reason_codes: &[&'static str]) {
        let typed = err
            .gate_denial()
            .expect("GateWriteRejected must expose typed denial taxonomy");
        assert_eq!(typed.outcome().as_str(), outcome);
        let typed_reason_codes = typed
            .reason_codes()
            .iter()
            .map(|reason| reason.as_str())
            .collect::<Vec<_>>();
        assert_eq!(typed_reason_codes, reason_codes);

        match err {
            Error::GateWriteRejected {
                outcome: got_outcome,
                reason_codes: got_reasons,
            } => {
                assert_eq!(got_outcome, outcome);
                assert_eq!(got_reasons, reason_codes);
            }
            other => panic!("expected GateWriteRejected, got {other:?}"),
        }
    }

    fn assert_metric_counter_advanced(
        before: &GateMetricsSnapshot,
        after: &GateMetricsSnapshot,
        outcome: GateOutcome,
        reason_class: GateMetricReasonClass,
        delta: u64,
    ) {
        let before_count = before.count(outcome, reason_class);
        let after_count = after.count(outcome, reason_class);
        assert!(
            after_count >= before_count + delta,
            "expected metric {}/{} to advance by at least {delta}; before={before_count}, after={after_count}",
            outcome.as_str(),
            reason_class.as_str()
        );
    }

    #[test]
    fn min_of_two_caps() {
        for (confirmed_scope, introducer_ceiling, expected) in [
            (
                PolicyApprovalCeiling::Auto,
                PolicyApprovalCeiling::Auto,
                PolicyApprovalCeiling::Auto,
            ),
            (
                PolicyApprovalCeiling::Auto,
                PolicyApprovalCeiling::Proposed,
                PolicyApprovalCeiling::Proposed,
            ),
            (
                PolicyApprovalCeiling::Proposed,
                PolicyApprovalCeiling::Auto,
                PolicyApprovalCeiling::Proposed,
            ),
            (
                PolicyApprovalCeiling::Proposed,
                PolicyApprovalCeiling::Proposed,
                PolicyApprovalCeiling::Proposed,
            ),
        ] {
            assert_eq!(
                foreign_agent_effective_ceiling(confirmed_scope, introducer_ceiling),
                expected
            );
        }
    }

    #[test]
    fn introducer_lower_wins() {
        assert_eq!(
            foreign_agent_effective_ceiling(
                PolicyApprovalCeiling::Auto,
                PolicyApprovalCeiling::Proposed,
            ),
            PolicyApprovalCeiling::Proposed
        );
    }

    #[test]
    fn widen_on_request_path() {
        let capped = foreign_agent_effective_ceiling(
            PolicyApprovalCeiling::Auto,
            PolicyApprovalCeiling::Proposed,
        );

        assert_eq!(
            foreign_agent_ceiling_after_widen_request(
                capped,
                PolicyApprovalCeiling::Auto,
                &GateDecision::pending(vec![GateReasonCode::PendingActorCeiling]),
            ),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(
            foreign_agent_ceiling_after_widen_request(
                capped,
                PolicyApprovalCeiling::Auto,
                &GateDecision::allow(),
            ),
            PolicyApprovalCeiling::Auto
        );
    }

    fn stored_claim_body(vault: &crate::Vault, id: &EntityId) -> Result<ClaimBody> {
        let raw = vault.get_raw(id)?.ok_or(Error::EntityNotFound)?;
        decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], true)
    }

    fn edge_provenance_flags(
        vault: &crate::Vault,
        source: &EntityId,
        kind: EdgeKind,
        target: &EntityId,
    ) -> Result<EdgeProvenanceFlags> {
        let edge = vault
            .edges_out(source)?
            .into_iter()
            .find(|edge| edge.kind == kind && edge.target == *target)
            .ok_or(Error::EdgeNotFound)?;
        edge.provenance.ok_or(Error::InvariantViolation(
            "test edge should carry provenance flags",
        ))
    }

    #[test]
    fn gate_metrics_snapshot_has_stable_privacy_preserving_labels() {
        let snapshot = gate_metrics_snapshot();
        assert_eq!(
            snapshot.counters().len(),
            GATE_METRIC_OUTCOME_COUNT * GATE_METRIC_REASON_CLASS_COUNT
        );

        let labels = snapshot
            .counters()
            .iter()
            .map(|counter| (counter.outcome().as_str(), counter.reason_class().as_str()))
            .collect::<Vec<_>>();
        for counter in snapshot.counters() {
            assert_eq!(
                counter.count(),
                snapshot.count(counter.outcome(), counter.reason_class())
            );
        }
        assert!(labels.contains(&("allow", "allow")));
        assert!(labels.contains(&("pending", "actor_ceiling")));
        assert!(labels.contains(&("pending", "source_trust")));
        assert!(labels.contains(&("deny", "policy_fail_closed")));
    }

    #[test]
    fn gate_metrics_counters_advance_for_representative_decisions() {
        let before = gate_metrics_snapshot();
        record_gate_decision_metrics(&GateDecision::allow());
        record_gate_decision_metrics(&GateDecision::deny(GateReasonCode::DenyPolicyFailClosed));
        record_gate_decision_metrics(&GateDecision::pending(vec![
            GateReasonCode::PendingSourceTrust,
            GateReasonCode::PendingCriticalityFloor,
        ]));
        let after = gate_metrics_snapshot();

        assert_metric_counter_advanced(
            &before,
            &after,
            GateOutcome::Allow,
            GateMetricReasonClass::Allow,
            1,
        );
        assert_metric_counter_advanced(
            &before,
            &after,
            GateOutcome::Deny,
            GateMetricReasonClass::PolicyFailClosed,
            1,
        );
        assert_metric_counter_advanced(
            &before,
            &after,
            GateOutcome::Pending,
            GateMetricReasonClass::SourceTrust,
            1,
        );
        assert_metric_counter_advanced(
            &before,
            &after,
            GateOutcome::Pending,
            GateMetricReasonClass::CriticalityFloor,
            1,
        );
    }

    #[test]
    fn gate_metrics_advance_at_claim_write_chokepoint_without_double_counting() -> Result<()> {
        let before = gate_metrics_snapshot();

        let (_allow_tmp, allow_vault) = temp_vault();
        let mut allow_policy = encode_policy_manifest(vec![]);
        trust_human_candidate_actor(&mut allow_policy);
        put_policy_manifest_bytes(&allow_vault, 0x40, &allow_policy)?;
        let allow_body = source_trust_claim(ClaimSource::UserStated);
        let (allow_candidate, allow_envelope) =
            claim_candidate_write_parts(&allow_vault, &allow_body)?;
        allow_vault
            .batch()
            .claim_candidate(
                &test_id(0x41),
                allow_candidate,
                &allow_envelope,
                test_time(3),
                3,
            )
            .commit()?;

        let (_pending_tmp, pending_vault) = temp_vault();
        put_policy_manifest_bytes(&pending_vault, 0x42, &encode_policy_manifest(vec![]))?;
        let pending_body = source_trust_claim(ClaimSource::UserStated);
        let (pending_candidate, pending_envelope) =
            claim_candidate_write_parts(&pending_vault, &pending_body)?;
        let pending_err = pending_vault
            .batch()
            .claim_candidate(
                &test_id(0x43),
                pending_candidate,
                &pending_envelope,
                test_time(3),
                3,
            )
            .commit()
            .expect_err("untrusted actor class must remain pending");
        assert_gate_rejected(pending_err, "pending", &["gate.pending.actor_ceiling"]);

        let (_deny_tmp, deny_vault) = temp_vault();
        put_policy_manifest_bytes(&deny_vault, 0x45, b"not-msgpack")?;
        let deny_body = source_trust_claim(ClaimSource::UserStated);
        let (deny_candidate, deny_envelope) = claim_candidate_write_parts(&deny_vault, &deny_body)?;
        let deny_err = deny_vault
            .batch()
            .claim_candidate(
                &test_id(0x44),
                deny_candidate,
                &deny_envelope,
                test_time(3),
                3,
            )
            .commit()
            .expect_err("missing policy manifest must fail closed");
        assert_gate_rejected(deny_err, "deny", &["gate.deny.policy_fail_closed"]);

        let after = gate_metrics_snapshot();
        assert_metric_counter_advanced(
            &before,
            &after,
            GateOutcome::Allow,
            GateMetricReasonClass::Allow,
            1,
        );
        assert_metric_counter_advanced(
            &before,
            &after,
            GateOutcome::Pending,
            GateMetricReasonClass::ActorCeiling,
            1,
        );
        assert_metric_counter_advanced(
            &before,
            &after,
            GateOutcome::Deny,
            GateMetricReasonClass::PolicyFailClosed,
            1,
        );
        Ok(())
    }

    #[test]
    fn gate_evaluator_default_policy_fails_closed_with_typed_denial() {
        let policy = PolicyManifestResolution::default();
        let input = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );

        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        assert_eq!(
            decision.reason_codes(),
            &[GateReasonCode::DenyPolicyFailClosed]
        );
        let err = Error::GateWriteRejected {
            outcome: decision.outcome().as_str(),
            reason_codes: decision
                .reason_codes()
                .iter()
                .map(|reason| reason.as_str())
                .collect(),
        };
        let typed = err
            .gate_denial()
            .expect("default fail-closed denial must be typed");
        assert_eq!(typed.outcome(), GateDenialOutcome::Deny);
        assert_eq!(
            typed.reason_codes(),
            &[GateDenialReason::DenyPolicyFailClosed]
        );
    }

    #[test]
    fn gate_evaluator_actor_source_criticality_matrix() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![]);
        put_policy_manifest_bytes(&vault, 0x71, &data)?;
        let policy = resolve(&vault)?;

        let cases = [
            (
                "auto actor trusted source normal criticality",
                None,
                ClaimSource::UserStated,
                PolicyCriticality::Normal,
                GateOutcome::Allow,
                vec![GateReasonCode::Allow],
            ),
            (
                "auto actor trusted source critical floor",
                None,
                ClaimSource::UserStated,
                PolicyCriticality::Critical,
                GateOutcome::Pending,
                vec![GateReasonCode::PendingCriticalityFloor],
            ),
            (
                "auto actor low source trust normal criticality",
                None,
                ClaimSource::ToolOutput,
                PolicyCriticality::Normal,
                GateOutcome::Pending,
                vec![GateReasonCode::PendingSourceTrust],
            ),
            (
                "auto actor low source trust critical floor",
                None,
                ClaimSource::ToolOutput,
                PolicyCriticality::Critical,
                GateOutcome::Pending,
                vec![
                    GateReasonCode::PendingSourceTrust,
                    GateReasonCode::PendingCriticalityFloor,
                ],
            ),
            (
                "proposed actor trusted source normal criticality",
                Some("probation"),
                ClaimSource::UserStated,
                PolicyCriticality::Normal,
                GateOutcome::Pending,
                vec![GateReasonCode::PendingActorCeiling],
            ),
            (
                "proposed actor trusted source critical floor",
                Some("probation"),
                ClaimSource::UserStated,
                PolicyCriticality::Critical,
                GateOutcome::Pending,
                vec![
                    GateReasonCode::PendingActorCeiling,
                    GateReasonCode::PendingCriticalityFloor,
                ],
            ),
            (
                "proposed actor low source trust normal criticality",
                Some("probation"),
                ClaimSource::ToolOutput,
                PolicyCriticality::Normal,
                GateOutcome::Pending,
                vec![
                    GateReasonCode::PendingActorCeiling,
                    GateReasonCode::PendingSourceTrust,
                ],
            ),
            (
                "proposed actor low source trust critical floor",
                Some("probation"),
                ClaimSource::ToolOutput,
                PolicyCriticality::Critical,
                GateOutcome::Pending,
                vec![
                    GateReasonCode::PendingActorCeiling,
                    GateReasonCode::PendingSourceTrust,
                    GateReasonCode::PendingCriticalityFloor,
                ],
            ),
        ];

        for (name, actor_ref, source, criticality, outcome, reasons) in cases {
            let input = gate_evaluator_input("first_party", actor_ref, source, criticality);
            let decision = policy.evaluate_gate(&input);
            assert_eq!(decision.outcome(), outcome, "{name}");
            assert_eq!(decision.reason_codes(), reasons.as_slice(), "{name}");
            assert!(
                decision
                    .reason_codes()
                    .iter()
                    .all(|code| code.as_str().starts_with("gate.")),
                "{name}: reason codes must be stable gate.* strings"
            );
        }

        Ok(())
    }

    #[test]
    fn gate_evaluator_denial_reason_codes_are_stable() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![]);
        put_policy_manifest_bytes(&vault, 0x72, &data)?;
        let policy = resolve(&vault)?;

        let mut missing_actor_class = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        missing_actor_class.actor.actor_class = " \t ".to_owned();
        let decision = policy.evaluate_gate(&missing_actor_class);
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.missing_actor_class"]
        );

        let mut missing_actor_provenance = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        missing_actor_provenance.provenance.actor_entity_ref = None;
        let decision = policy.evaluate_gate(&missing_actor_provenance);
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.missing_actor_provenance"]
        );

        let mut missing_policy_version = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        missing_policy_version.policy_manifest_version.clear();
        let decision = policy.evaluate_gate(&missing_policy_version);
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.missing_policy_manifest_version"]
        );

        let fail_closed_policy = PolicyManifestResolution::default();
        let input = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        let decision = fail_closed_policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Deny);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.policy_fail_closed"]
        );

        Ok(())
    }

    #[test]
    fn gate_evaluator_missing_source_preserves_write_gate_semantics() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![]);
        put_policy_manifest_bytes(&vault, 0x74, &data)?;
        let policy = resolve(&vault)?;

        let mut input = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::ToolOutput,
            PolicyCriticality::Normal,
        );
        input.source = None;
        input.sensitivity_band = None;

        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Allow);
        assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

        Ok(())
    }

    #[test]
    fn gate_evaluator_source_trust_respects_sensitivity_ceiling() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
        put_policy_manifest_bytes(&vault, 0x75, &data)?;
        let policy = resolve(&vault)?;

        let mut input = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::ToolOutput,
            PolicyCriticality::Normal,
        );

        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Allow);
        assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

        input.sensitivity_band = Some(1);
        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.source_trust"]
        );

        input.sensitivity_band = None;
        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.source_trust"]
        );

        Ok(())
    }

    #[test]
    fn gate_evaluator_generated_source_requires_explicit_auto_permit() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![source_trust_entry_without_auto_permit(
            ClaimSource::Generated,
            0,
        )]);
        put_policy_manifest_bytes(&vault, 0x76, &data)?;
        let policy = resolve(&vault)?;

        let input = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::Generated,
            PolicyCriticality::Normal,
        );
        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.source_trust"]
        );

        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Generated, 0)]);
        put_policy_manifest_bytes(&vault, 0x77, &data)?;
        let policy = resolve(&vault)?;
        let decision = policy.evaluate_gate(&input);
        assert_eq!(decision.outcome(), GateOutcome::Allow);
        assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

        Ok(())
    }

    #[test]
    fn gate_evaluator_content_kind_reasons_are_stable() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![]);
        put_policy_manifest_bytes(&vault, 0x73, &data)?;
        let policy = resolve(&vault)?;

        let mut edge_provenance = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        edge_provenance.content_kind = GateContentKind::EdgeProvenanceClaim;
        assert_eq!(
            edge_provenance.content_kind.as_str(),
            "edge_provenance_claim"
        );
        let decision = policy.evaluate_gate(&edge_provenance);
        assert_eq!(decision.outcome(), GateOutcome::Allow);
        assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

        let mut policy_manifest = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        policy_manifest.content_kind = GateContentKind::PolicyManifest;
        assert_eq!(policy_manifest.content_kind.as_str(), "policy_manifest");
        let decision = policy.evaluate_gate(&policy_manifest);
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.policy_manifest_authority"]
        );

        let mut external_effect = gate_evaluator_input(
            "first_party",
            None,
            ClaimSource::UserStated,
            PolicyCriticality::Normal,
        );
        external_effect.content_kind = GateContentKind::ExternalEffect;
        assert_eq!(external_effect.content_kind.as_str(), "external_effect");
        let decision = policy.evaluate_gate(&external_effect);
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );
        assert_eq!(decision.outcome().as_str(), "pending");

        Ok(())
    }

    #[test]
    fn external_effect_scoped_grant_allows_and_records_receipt() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
            "sender",
            "external:send",
            Value::Map(vec![(
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("line"),
            )]),
            None,
        )]);
        put_policy_manifest_bytes(&vault, 0xD0, &data)?;
        let policy = resolve(&vault)?;
        let effect = external_effect_gate_input("sender", "send", "line");

        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
        })?;

        assert_eq!(decision.outcome(), GateOutcome::Allow);
        assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);

        let decisions = vault.store.gate_decisions(10)?;
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].outcome, "allow");
        assert_eq!(decisions[0].reason_codes, vec!["gate.allow"]);
        assert_eq!(decisions[0].actor_class, "first_party");
        assert_eq!(decisions[0].actor_ref.as_deref(), Some("sender"));
        assert_eq!(decisions[0].content_kind, "external_effect");
        assert_eq!(decisions[0].claim_id, None);
        assert!(!decisions[0].diff_handle.is_empty());
        assert_eq!(
            decisions[0].read_frontier_hash,
            policy.read_frontier_hash()?
        );
        Ok(())
    }

    #[test]
    fn standing_outbound_grant_allows_in_scope_external_effect_and_records_join() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0xD8, &encode_policy_manifest(vec![]))?;

        let grant_id = test_id(0xD9);
        let intent = GrantMintIntent {
            principal_ref: "sender".to_owned(),
            origin_component_id: "ask-1".to_owned(),
            origin_action_id: "escalate_always_this_verb_class".to_owned(),
            origin_receipt_ref: Some("gate:ask-1".to_owned()),
            scope: GrantMintIntentScope::VerbClass {
                verb_class: "send".to_owned(),
            },
        };
        vault.mint_standing_outbound_grant(&grant_id, &intent, 10)?;
        let policy = resolve(&vault)?;

        let mut effect = external_effect_gate_input("sender", "send", "line");
        effect.has_opted_in = false;
        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
        })?;

        assert_eq!(decision.outcome(), GateOutcome::Allow);
        let grant = vault
            .get_standing_outbound_grant(&grant_id)?
            .expect("grant stored");
        assert!(grant.last_used_at.is_some());

        let decisions = vault.store.gate_decisions(10)?;
        let grant_ref = format!("grant:{}", grant_id.to_hex());
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].grant_ref.as_deref(), Some(grant_ref.as_str()));

        let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
        assert_eq!(
            receipts[0].fields.get("grant_ref").map(String::as_str),
            Some(grant_ref.as_str())
        );
        let projection = vault.receipt_projection_by_grant(grant_ref, ReceiptQuery::new(10))?;
        assert_eq!(projection.receipts.len(), 2);
        assert!(
            projection
                .receipts
                .iter()
                .any(|receipt| receipt.receipt_kind == ReceiptKind::Gate)
        );
        Ok(())
    }

    #[test]
    fn standing_outbound_grant_lookup_uses_principal_index_before_type_scan() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0xDD, &encode_policy_manifest(vec![]))?;

        let grant_id = test_id(0xDE);
        let intent = GrantMintIntent {
            principal_ref: "sender".to_owned(),
            origin_component_id: "ask-1".to_owned(),
            origin_action_id: "escalate_always_this_verb_class".to_owned(),
            origin_receipt_ref: Some("gate:ask-1".to_owned()),
            scope: GrantMintIntentScope::VerbClass {
                verb_class: "send".to_owned(),
            },
        };
        vault.mint_standing_outbound_grant(&grant_id, &intent, 10)?;
        let policy = resolve(&vault)?;

        vault.with_write_txn(|wtxn| {
            let mut type_key = Vec::with_capacity(ENTITY_ID_LEN + 1);
            type_key.push(ENTITY_TYPE_OUTBOUND_GRANT);
            type_key.extend_from_slice(grant_id.as_bytes());
            vault.store.type_index.delete(wtxn, &type_key)?;
            Ok(())
        })?;

        let mut effect = external_effect_gate_input("sender", "send", "line");
        effect.has_opted_in = false;
        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
        })?;

        assert_eq!(decision.outcome(), GateOutcome::Allow);
        Ok(())
    }

    #[test]
    fn forged_standing_grant_ref_does_not_authorize_external_effect() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0xD7, &encode_policy_manifest(vec![]))?;
        let policy = resolve(&vault)?;

        let mut effect = external_effect_gate_input("sender", "send", "line");
        effect.has_opted_in = false;
        effect.standing_grant_ref = Some(format!("grant:{}", test_id(0xD7).to_hex()));
        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
        })?;

        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );
        let decisions = vault.store.gate_decisions(10)?;
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].grant_ref, None);
        Ok(())
    }

    #[test]
    fn standing_outbound_grant_reasks_out_of_scope_stale_and_revoked_sends() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0xDA, &encode_policy_manifest(vec![]))?;

        let grant_id = test_id(0xDB);
        let intent = GrantMintIntent {
            principal_ref: "sender".to_owned(),
            origin_component_id: "ask-1".to_owned(),
            origin_action_id: "escalate_always_this_channel".to_owned(),
            origin_receipt_ref: Some("gate:ask-1".to_owned()),
            scope: GrantMintIntentScope::Channel {
                channel: "line".to_owned(),
            },
        };
        vault.mint_standing_outbound_grant(&grant_id, &intent, 10)?;
        let policy = resolve(&vault)?;

        let mut out_of_scope = external_effect_gate_input("sender", "send", "email");
        out_of_scope.has_opted_in = false;
        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &out_of_scope, &policy)
        })?;
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );

        let mut lifecycle_effect = external_effect_gate_input("sender", "provision", "line");
        lifecycle_effect.has_opted_in = false;
        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &lifecycle_effect, &policy)
        })?;
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );

        put_policy_manifest_bytes(&vault, 0xDC, &encode_policy_manifest(vec![]))?;
        let stale_policy = resolve(&vault)?;
        let mut in_scope_stale = external_effect_gate_input("sender", "send", "line");
        in_scope_stale.has_opted_in = false;
        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &in_scope_stale, &stale_policy)
        })?;
        assert_eq!(decision.outcome(), GateOutcome::Pending);

        vault.revoke_standing_outbound_grant(&grant_id, 20)?;
        let mut in_scope_revoked = external_effect_gate_input("sender", "send", "line");
        in_scope_revoked.has_opted_in = false;
        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &in_scope_revoked, &stale_policy)
        })?;
        assert_eq!(decision.outcome(), GateOutcome::Pending);

        let lens =
            vault.standing_outbound_grants_lens(StandingOutboundGrantsLensQuery::new(10, 10))?;
        assert_eq!(lens.grants.len(), 1);
        assert_eq!(lens.grants[0].status, "revoked");
        assert_eq!(lens.grants[0].revoked_at, Some(20));
        assert_eq!(lens.grants[0].scope_dial, "always_this_channel");
        assert_eq!(
            lens.grants[0].origin_receipt_ref.as_deref(),
            Some("gate:ask-1")
        );
        Ok(())
    }

    #[test]
    fn counterparty_contact_records_are_visible_and_revocable_by_identity() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let identity = test_id(0xC7);
        let intro_id = test_id(0xC8);
        let inbound_id = test_id(0xC9);
        let intro =
            CounterpartyContactRecord::user_introduction(identity, " kenji@example.com ", 10)?;
        let inbound = CounterpartyContactRecord::inbound_first(identity, "+15551234567", 11)?;

        vault.create_counterparty_contact(&intro_id, &intro)?;
        vault.create_counterparty_contact(&inbound_id, &inbound)?;

        let found = vault
            .find_counterparty_contact(&identity, "kenji@example.com")?
            .expect("intro contact visible by target");
        assert_eq!(found.0, intro_id);
        assert_eq!(
            found.1.first_touch,
            CounterpartyFirstTouch::UserIntroduction
        );
        assert_eq!(found.1.counterparty, "kenji@example.com");

        let contacts = vault.counterparty_contacts_for_identity(&identity)?;
        assert_eq!(contacts.len(), 2);

        let revoked = vault.revoke_counterparty_contact(&intro_id, 20)?;
        assert_eq!(revoked.status, CounterpartyContactStatus::Revoked);
        assert_eq!(revoked.revoked_at, Some(20));
        assert_eq!(
            vault
                .get_counterparty_contact(&intro_id)?
                .expect("revoked stored"),
            revoked
        );
        Ok(())
    }

    #[test]
    fn counterparty_contact_lookup_uses_dedicated_index_before_scan() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let identity = test_id(0xC7);
        let contact_id = test_id(0xC8);
        let contact =
            CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
        vault.create_counterparty_contact(&contact_id, &contact)?;

        vault.with_write_txn(|wtxn| {
            let type_key = Store::encode_type_key(ENTITY_TYPE_COUNTERPARTY_CONTACT, &contact_id);
            vault.store.type_index.delete(wtxn, &type_key)?;
            Ok(())
        })?;

        let found = vault
            .find_counterparty_contact(&identity, "kenji@example.com")?
            .expect("lookup index finds contact without type-index scan row");
        assert_eq!(found.0, contact_id);
        assert_eq!(found.1.counterparty, "kenji@example.com");

        let duplicate_id = test_id(0xC9);
        let duplicate =
            CounterpartyContactRecord::inbound_first(identity, " kenji@example.com ", 20)?;
        let err = vault
            .create_counterparty_contact(&duplicate_id, &duplicate)
            .expect_err("lookup index rejects duplicate counterparty assignment");
        assert_eq!(err.kind(), ErrorKind::CounterpartyContactAlreadyExists);
        Ok(())
    }

    #[test]
    fn external_effect_denies_opted_out_counterparty_regardless_of_grant() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
            "sender",
            "send",
            Value::Map(vec![(
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("line"),
            )]),
            None,
        )]);
        put_policy_manifest_bytes(&vault, 0xD5, &data)?;
        let policy = resolve(&vault)?;

        let identity = test_id(0xCA);
        let contact_id = test_id(0xCB);
        let contact =
            CounterpartyContactRecord::user_introduction(identity, "kenji@example.com", 10)?;
        vault.create_counterparty_contact(&contact_id, &contact)?;
        let opted_out = vault.opt_out_counterparty_contact(
            &contact_id,
            CounterpartyOptOutReason::Unsubscribe,
            20,
        )?;
        assert!(opted_out.is_opted_out());

        let mut effect = external_effect_gate_input("sender", "send", "line");
        effect.channel_identity_ref = Some(identity);
        effect.counterparty = Some("kenji@example.com".to_owned());

        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
        })?;

        assert_eq!(decision.outcome(), GateOutcome::Deny);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.deny.counterparty_opt_out"]
        );
        assert_eq!(
            decision.receipt_reasons(),
            &[
                "counterparty_opt_out_unsubscribe",
                "counterparty_first_touch_user_introduction"
            ]
        );

        let decisions = vault.store.gate_decisions(10)?;
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].outcome, "deny");
        assert_eq!(
            decisions[0].reason_codes,
            vec!["gate.deny.counterparty_opt_out"]
        );
        assert_eq!(
            decisions[0].receipt_reasons,
            vec![
                "counterparty_opt_out_unsubscribe",
                "counterparty_first_touch_user_introduction"
            ]
        );

        let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
        assert_eq!(receipts.len(), 1);
        assert_eq!(
            receipts[0].policy_trace,
            vec![
                "gate.deny.counterparty_opt_out",
                "counterparty_opt_out_unsubscribe",
                "counterparty_first_touch_user_introduction"
            ]
        );
        assert_eq!(
            receipts[0].fields.get("receipt_reason").map(String::as_str),
            Some("counterparty_opt_out_unsubscribe")
        );
        assert_eq!(
            receipts[0]
                .fields
                .get("receipt_reasons")
                .map(String::as_str),
            Some("counterparty_opt_out_unsubscribe,counterparty_first_touch_user_introduction")
        );
        Ok(())
    }

    #[test]
    fn external_effect_public_first_touch_applies_hold_floor_and_receipt() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
            "sender",
            "send",
            Value::Map(vec![
                (
                    Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                    Value::from("line"),
                ),
                (
                    Value::from(EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY),
                    Value::from(ExternalEffectPolicyRisk::Normal.as_str()),
                ),
            ]),
            None,
        )]);
        put_policy_manifest_bytes(&vault, 0xD6, &data)?;
        let policy = resolve(&vault)?;
        let identity = test_id(0xCE);

        let mut normal_effect = external_effect_gate_input("sender", "send", "line");
        normal_effect.channel_identity_ref = Some(identity);
        normal_effect.counterparty = Some("unknown@example.com".to_owned());
        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &normal_effect, &policy)
        })?;
        assert_eq!(decision.outcome(), GateOutcome::Allow);
        assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);
        assert!(decision.receipt_reasons().is_empty());

        let contact_id = test_id(0xCF);
        let public_contact = CounterpartyContactRecord::public(identity, "public@example.com", 10)?;
        vault.create_counterparty_contact(&contact_id, &public_contact)?;

        let mut public_effect = external_effect_gate_input("sender", "send", "line");
        public_effect.channel_identity_ref = Some(identity);
        public_effect.counterparty = Some("public@example.com".to_owned());
        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &public_effect, &policy)
        })?;
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );
        assert_eq!(
            decision.receipt_reasons(),
            &["counterparty_first_touch_public"]
        );

        let decisions = vault.store.gate_decisions(10)?;
        let shaped = decisions
            .iter()
            .find(|record| record.receipt_reasons == vec!["counterparty_first_touch_public"])
            .expect("public first-touch gate decision is persisted with receipt reason");
        assert_eq!(shaped.outcome, "pending");
        assert_eq!(
            shaped.reason_codes,
            vec!["gate.pending.external_effect_authority"]
        );

        let receipts = vault.receipts(ReceiptQuery::new(10).with_kind(ReceiptKind::Gate))?;
        let shaped_receipt = receipts
            .iter()
            .find(|receipt| {
                receipt
                    .policy_trace
                    .iter()
                    .any(|reason| reason == "counterparty_first_touch_public")
            })
            .expect("public first-touch gate receipt is projected");
        assert_eq!(
            shaped_receipt.policy_trace,
            vec![
                "gate.pending.external_effect_authority",
                "counterparty_first_touch_public"
            ]
        );
        assert_eq!(
            shaped_receipt
                .fields
                .get("receipt_reason")
                .map(String::as_str),
            Some("counterparty_first_touch_public")
        );
        Ok(())
    }

    #[test]
    fn external_effect_requires_opt_in_and_permission() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
            "sender",
            "send",
            Value::Map(vec![(
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("line"),
            )]),
            None,
        )]);
        put_policy_manifest_bytes(&vault, 0xD1, &data)?;
        let policy = resolve(&vault)?;

        let mut missing_opt_in = external_effect_gate_input("sender", "send", "line");
        missing_opt_in.has_opted_in = false;
        let decision = policy.evaluate_gate(&missing_opt_in.gate_input());
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );

        let mut missing_permission = external_effect_gate_input("sender", "send", "line");
        missing_permission.has_permission = false;
        let decision = policy.evaluate_gate(&missing_permission.gate_input());
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );
        Ok(())
    }

    #[test]
    fn external_effect_policy_risk_holds_but_owner_grant_can_dial_allow_all() -> Result<()> {
        let (_pending_tmp, pending_vault) = temp_vault();
        put_policy_manifest_bytes(&pending_vault, 0xD2, &encode_policy_manifest(vec![]))?;
        let pending_policy = resolve(&pending_vault)?;
        let mut risky = external_effect_gate_input("sender", "send", "line");
        risky.policy_risk = ExternalEffectPolicyRisk::HoldToProposal;

        let decision = pending_policy.evaluate_gate(&risky.gate_input());
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );

        let (_allowed_tmp, allowed_vault) = temp_vault();
        let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
            "sender",
            "external:*",
            Value::Map(vec![
                (
                    Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                    Value::from("line"),
                ),
                (
                    Value::from(EXTERNAL_EFFECT_SCOPE_POLICY_RISK_KEY),
                    Value::from(EXTERNAL_EFFECT_WILDCARD),
                ),
            ]),
            None,
        )]);
        put_policy_manifest_bytes(&allowed_vault, 0xD3, &data)?;
        let allowed_policy = resolve(&allowed_vault)?;
        let decision = allowed_policy.evaluate_gate(&risky.gate_input());
        assert_eq!(decision.outcome(), GateOutcome::Allow);
        assert_eq!(gate_reason_strs(&decision), vec!["gate.allow"]);
        Ok(())
    }

    #[test]
    fn external_effect_budgeted_grants_hold_without_budget_enforcer() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![external_effect_scoped_grant_entry(
            "sender",
            "send",
            Value::Map(vec![(
                Value::from(EXTERNAL_EFFECT_SCOPE_CHANNEL_KEY),
                Value::from("line"),
            )]),
            Some(Value::Map(vec![(Value::from("limit"), Value::from(1_u64))])),
        )]);
        put_policy_manifest_bytes(&vault, 0xD4, &data)?;
        let policy = resolve(&vault)?;
        let effect = external_effect_gate_input("sender", "send", "line");
        let decision = policy.evaluate_gate(&effect.gate_input());
        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );
        Ok(())
    }

    #[test]
    fn external_effect_fail_closed_policy_holds_instead_of_denies() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        let effect = external_effect_gate_input("sender", "send", "line");

        let (_decision_id, decision) = vault.with_write_txn(|wtxn| {
            check_external_effect_policy(&vault.store, wtxn, &effect, &policy)
        })?;

        assert_eq!(decision.outcome(), GateOutcome::Pending);
        assert_eq!(
            gate_reason_strs(&decision),
            vec!["gate.pending.external_effect_authority"]
        );
        let decisions = vault.store.gate_decisions(10)?;
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].outcome, "pending");
        assert_eq!(
            decisions[0].reason_codes,
            vec!["gate.pending.external_effect_authority"]
        );
        assert_eq!(decisions[0].content_kind, "external_effect");
        assert_eq!(decisions[0].claim_id, None);
        Ok(())
    }

    #[test]
    fn policy_manifest_valid_fixture_resolves_gate_inputs() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![
            source_trust_entry(ClaimSource::ToolOutput, 0),
            scoped_grants_entry(),
            signatures_entry(),
        ]);
        replace_actor_ceilings(
            &mut data,
            vec![
                actor_ceiling_row("first_party", "auto"),
                actor_ceiling_row_for_ref("first_party", "probation", "proposed"),
                actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "auto"),
                actor_ceiling_row("human", "auto"),
            ],
        );
        put_policy_manifest_bytes(&vault, 0x51, &data)?;

        let policy = resolve(&vault)?;
        assert!(!policy.is_fail_closed());
        assert_eq!(policy.diagnostics().manifest_count, 1);
        assert_eq!(
            policy.actor_ceiling("first_party", None),
            PolicyApprovalCeiling::Auto
        );
        assert_eq!(
            policy.actor_ceiling("first_party", Some("probation")),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(
            policy.actor_ceiling("agent", Some(&first_party_eiri_connector_actor_ref())),
            PolicyApprovalCeiling::Auto
        );
        assert_eq!(
            policy.criticality_for_predicate("health.allergy"),
            PolicyCriticality::Critical
        );
        assert_eq!(
            policy.sensitivity_for_predicate("health.allergy"),
            PolicySensitivity::Sensitive
        );
        assert_eq!(policy.scoped_grants().len(), 1);
        assert_eq!(policy.signatures().len(), 1);

        let id = test_id(0x63);
        let body = source_trust_claim(ClaimSource::ToolOutput);
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
        reset_claim_body_decode_count();
        vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
            .commit()?;
        assert!(vault.get_raw(&id)?.is_some());
        assert_eq!(
            claim_body_decode_count(),
            1,
            "policy gate must reuse the write-door decode"
        );
        Ok(())
    }

    #[test]
    fn first_party_eiri_tool_output_auto_write_reaches_auto() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_first_party_eiri_default_policy_manifest();
        put_policy_manifest_bytes(&vault, 0xB4, &data)?;

        let claim_id = test_id(0xB5);
        let body = source_trust_claim(ClaimSource::ToolOutput);
        let (candidate, envelope) = claim_candidate_write_parts_for_actor(
            &vault,
            &body,
            first_party_eiri_connector_actor_id(),
            EdgeActorClass::Agent,
        )?;

        vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
            .commit()?;

        let stored = stored_claim_body(&vault, &claim_id)?;
        assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
        assert_eq!(stored.source, Some(ClaimSource::ToolOutput));

        let decisions = vault.store.gate_decisions(10)?;
        let decision = decisions
            .iter()
            .find(|decision| decision.claim_id == Some(*claim_id.as_bytes()))
            .expect("first-party Eiri write must record a gate decision");
        assert_eq!(decision.outcome, "allow");
        assert_eq!(decision.reason_codes, vec!["gate.allow"]);
        assert_eq!(decision.actor_class, "agent");
        assert_eq!(
            decision.actor_ref.as_deref(),
            Some(first_party_eiri_connector_actor_ref().as_str())
        );
        Ok(())
    }

    #[test]
    fn dreamer_generated_auto_write_requires_manifest_signature() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Generated, 0)]);
        append_actor_ceiling(
            &mut data,
            actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "auto"),
        );
        put_policy_manifest_bytes(&vault, 0xC4, &data)?;

        let claim_id = test_id(0xC5);
        let body = source_trust_claim(ClaimSource::Generated);
        let (candidate, envelope) = dreamer_claim_candidate_write_parts(
            &vault,
            &body,
            first_party_eiri_connector_actor_id(),
            "dreamer-run-auth",
        )?;

        let err = vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
            .commit()
            .expect_err("unsigned manifest must not grant Dreamer Auto writes");

        assert_gate_rejected(err, "pending", &["gate.pending.policy_manifest_authority"]);
        assert!(vault.get_raw(&claim_id)?.is_none());
        Ok(())
    }

    #[test]
    fn dreamer_generated_auto_write_with_signed_manifest_reaches_auto() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![
            source_trust_entry(ClaimSource::Generated, 0),
            signatures_entry(),
        ]);
        append_actor_ceiling(
            &mut data,
            actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "auto"),
        );
        put_policy_manifest_bytes(&vault, 0xC6, &data)?;

        let claim_id = test_id(0xC7);
        let body = source_trust_claim(ClaimSource::Generated);
        let (candidate, envelope) = dreamer_claim_candidate_write_parts(
            &vault,
            &body,
            first_party_eiri_connector_actor_id(),
            "dreamer-run-auth",
        )?;

        vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
            .commit()?;

        let stored = stored_claim_body(&vault, &claim_id)?;
        assert_eq!(stored.approval, ClaimApprovalStatus::Auto);
        assert_eq!(stored.source, Some(ClaimSource::Generated));

        let decisions = vault.store.gate_decisions(10)?;
        let decision = decisions
            .iter()
            .find(|decision| decision.claim_id == Some(*claim_id.as_bytes()))
            .expect("signed Dreamer Auto write must record a gate decision");
        assert_eq!(decision.outcome, "allow");
        assert_eq!(decision.reason_codes, vec!["gate.allow"]);
        assert_eq!(decision.actor_class, "agent");
        assert_eq!(
            decision.actor_ref.as_deref(),
            Some(first_party_eiri_connector_actor_ref().as_str())
        );
        Ok(())
    }

    #[test]
    fn foreign_tool_output_connector_stays_pending_actor_ceiling() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_first_party_eiri_default_policy_manifest();
        put_policy_manifest_bytes(&vault, 0xB6, &data)?;

        let claim_id = test_id(0xB7);
        let body = source_trust_claim(ClaimSource::ToolOutput);
        let (candidate, envelope) = claim_candidate_write_parts_for_actor(
            &vault,
            &body,
            test_id(0xB8),
            EdgeActorClass::Agent,
        )?;

        let err = vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
            .commit()
            .expect_err("foreign connector must not inherit first-party Auto");

        assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
        assert!(vault.get_raw(&claim_id)?.is_none());
        Ok(())
    }

    #[test]
    fn default_policy_vad_rule_is_exact() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_first_party_eiri_default_policy_manifest();
        put_policy_manifest_bytes(&vault, 0xC0, &data)?;
        let policy = resolve(&vault)?;

        assert_eq!(
            policy.criticality_for_predicate("affect.vad"),
            PolicyCriticality::Normal
        );
        for predicate in ["affect.vad.extra", "affect.vader.note"] {
            assert_eq!(
                policy.criticality_for_predicate(predicate),
                PolicyCriticality::Critical,
                "{predicate} must not inherit the internal VAD exemption"
            );
        }

        let claim_id = test_id(0xC1);
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.predicate = "affect.vad.extra".to_owned();
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
        let err = vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
            .commit()
            .expect_err("VAD-like predicates must stay subject to the criticality floor");
        assert_gate_rejected(err, "pending", &["gate.pending.criticality_floor"]);
        assert!(vault.get_raw(&claim_id)?.is_none());
        Ok(())
    }

    #[test]
    fn default_policy_preserves_non_eiri_edge_provenance_writers() -> Result<()> {
        for (seed, actor_entity_type, actor_class) in [
            (0xC2, ENTITY_TYPE_PERSON, EdgeActorClass::Agent),
            (0xD2, ENTITY_TYPE_MACHINE, EdgeActorClass::System),
        ] {
            let (_tmp, vault) = temp_vault();
            let data = encode_first_party_eiri_default_policy_manifest();
            put_policy_manifest_bytes(&vault, seed, &data)?;

            let src = test_id(seed + 1);
            let tgt = test_id(seed + 2);
            let actor = test_id(seed + 3);
            let claim_id = test_id(seed + 4);
            let occurred = test_time(8);
            vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
            vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
            vault.put_entity(&actor, actor_entity_type, occurred, 8, b"actor")?;
            vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

            let subject = EdgeRef {
                source: src,
                kind: EdgeKind::Mentions,
                target: tgt,
            };
            let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
            vault.put_edge_provenance(&claim_id, &subject, &body, actor_class, 9)?;

            assert!(
                vault.get_raw(&claim_id)?.is_some(),
                "{actor_class:?} edge provenance write should persist under the default policy"
            );
        }
        Ok(())
    }

    #[test]
    fn unknown_and_revoked_connector_refs_fail_closed_to_pending() -> Result<()> {
        let (_unknown_tmp, unknown_vault) = temp_vault();
        let data = encode_first_party_eiri_default_policy_manifest();
        put_policy_manifest_bytes(&unknown_vault, 0xB9, &data)?;

        let unknown_claim = test_id(0xBA);
        let body = source_trust_claim(ClaimSource::ToolOutput);
        let (candidate, envelope) = claim_candidate_write_parts_for_actor(
            &unknown_vault,
            &body,
            test_id(0xBB),
            EdgeActorClass::Agent,
        )?;
        let err = unknown_vault
            .batch()
            .claim_candidate(&unknown_claim, candidate, &envelope, test_time(3), 3)
            .commit()
            .expect_err("unknown connector key must remain pending");
        assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
        assert!(unknown_vault.get_raw(&unknown_claim)?.is_none());

        let (_revoked_tmp, revoked_vault) = temp_vault();
        let mut revoked_policy = encode_first_party_eiri_default_policy_manifest();
        append_actor_ceiling(
            &mut revoked_policy,
            actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "proposed"),
        );
        put_policy_manifest_bytes(&revoked_vault, 0xBC, &revoked_policy)?;

        let revoked_claim = test_id(0xBD);
        let (candidate, envelope) = claim_candidate_write_parts_for_actor(
            &revoked_vault,
            &body,
            first_party_eiri_connector_actor_id(),
            EdgeActorClass::Agent,
        )?;
        let err = revoked_vault
            .batch()
            .claim_candidate(&revoked_claim, candidate, &envelope, test_time(3), 3)
            .commit()
            .expect_err("revoked connector key must remain pending");
        assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
        assert!(revoked_vault.get_raw(&revoked_claim)?.is_none());
        Ok(())
    }

    #[test]
    fn policy_manifest_signature_frontier_covers_first_party_auto_grant() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_first_party_eiri_default_policy_manifest();
        put_policy_manifest_bytes(&vault, 0xBE, &data)?;
        let policy = resolve(&vault)?;
        let signed_auto_frontier = policy.read_frontier_hash()?;

        assert_eq!(policy.signatures().len(), 1);
        assert_eq!(
            policy.actor_ceiling("agent", Some(&first_party_eiri_connector_actor_ref())),
            PolicyApprovalCeiling::Auto
        );

        let (_revoked_tmp, revoked_vault) = temp_vault();
        let mut revoked_data = encode_first_party_eiri_default_policy_manifest();
        append_actor_ceiling(
            &mut revoked_data,
            actor_ceiling_row_for_ref("agent", &first_party_eiri_connector_actor_ref(), "proposed"),
        );
        put_policy_manifest_bytes(&revoked_vault, 0xBF, &revoked_data)?;
        let revoked_policy = resolve(&revoked_vault)?;

        assert_eq!(revoked_policy.signatures().len(), 1);
        assert_eq!(
            revoked_policy.actor_ceiling("agent", Some(&first_party_eiri_connector_actor_ref())),
            PolicyApprovalCeiling::Proposed
        );
        assert_ne!(signed_auto_frontier, revoked_policy.read_frontier_hash()?);
        Ok(())
    }

    #[test]
    fn gate_chokepoint_active_policy_source_denial_is_typed_gate_rejection() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![]);
        trust_human_candidate_actor(&mut data);
        put_policy_manifest_bytes(&vault, 0x84, &data)?;

        assert_auto_source_gate_rejected(
            &vault,
            0x85,
            ClaimSource::ToolOutput,
            "pending",
            &["gate.pending.source_trust"],
        )
    }

    #[test]
    fn gate_decision_ledger_survives_rejected_standalone_write() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x90, &encode_policy_manifest(vec![]))?;

        let id = test_id(0x91);
        let body = source_trust_claim(ClaimSource::UserStated);
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

        let err = vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
            .commit()
            .expect_err("pending auto write must be rejected");
        assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
        assert!(
            vault.get_raw(&id)?.is_none(),
            "rejected entity write must not stage the claim"
        );

        let decisions = vault.store.gate_decisions(10)?;
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].outcome, "pending");
        assert_eq!(decisions[0].claim_id, Some(*id.as_bytes()));
        assert_eq!(
            decisions[0].reason_codes,
            vec!["gate.pending.actor_ceiling"]
        );
        Ok(())
    }

    #[test]
    fn pending_gate_consent_survives_reopen() -> Result<()> {
        let (tmp, vault) = temp_vault();
        {
            put_policy_manifest_bytes(&vault, 0x92, &encode_policy_manifest(vec![]))?;

            let id = test_id(0x93);
            let mut body = source_trust_claim(ClaimSource::UserStated);
            body.approval = ClaimApprovalStatus::Proposed;
            let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
            vault
                .batch()
                .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
                .commit()?;
        }
        drop(vault);

        let reopened = crate::Vault::open(tmp.path(), crate::types::VaultConfig::default())?;
        let id = test_id(0x93);
        let pending = reopened.with_write_txn(|wtxn| {
            reopened
                .store
                .pending_gate_consent_in_txn(wtxn, &id)?
                .ok_or(Error::CorruptedIndex("pending gate consent"))
        })?;
        assert_eq!(pending.claim_id, *id.as_bytes());
        assert_eq!(pending.reason_codes, vec!["gate.pending.actor_ceiling"]);
        Ok(())
    }

    #[test]
    fn pending_gate_consent_groups_interleaved_dreamer_runs_with_default_lane() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0xA0, &encode_policy_manifest(vec![]))?;

        let run_a = "dreamer-run-a";
        let run_b = "dreamer-run-b";
        let run_a_first = test_id(0xA1);
        let run_b_first = test_id(0xA2);
        let default_id = test_id(0xA3);
        let run_a_second = test_id(0xA4);
        let run_b_second = test_id(0xA5);

        let pending_body = |subject_seed: u8, value: &'static str, source: ClaimSource| {
            let mut body = source_trust_claim(source);
            body.subject = ClaimSubject::Entity(test_id(subject_seed));
            body.value = Value::from(value);
            body.approval = ClaimApprovalStatus::Proposed;
            body
        };

        let body_a_first = pending_body(0xB1, "run-a-1", ClaimSource::Generated);
        let body_b_first = pending_body(0xB2, "run-b-1", ClaimSource::Generated);
        let body_default = pending_body(0xB3, "default", ClaimSource::UserStated);
        let body_a_second = pending_body(0xB4, "run-a-2", ClaimSource::Generated);
        let body_b_second = pending_body(0xB5, "run-b-2", ClaimSource::Generated);

        for (claim_id, actor, run_id, body) in [
            (run_a_first, test_id(0xC1), run_a, &body_a_first),
            (run_b_first, test_id(0xC2), run_b, &body_b_first),
        ] {
            let (candidate, envelope) =
                dreamer_claim_candidate_write_parts(&vault, body, actor, run_id)?;
            vault
                .batch()
                .claim_candidate(&claim_id, candidate, &envelope, test_time(3), 3)
                .commit()?;
            std::thread::sleep(Duration::from_millis(2));
        }

        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body_default)?;
        vault
            .batch()
            .claim_candidate(&default_id, candidate, &envelope, test_time(3), 3)
            .commit()?;
        std::thread::sleep(Duration::from_millis(2));

        for (claim_id, actor, run_id, body) in [
            (run_a_second, test_id(0xC4), run_a, &body_a_second),
            (run_b_second, test_id(0xC5), run_b, &body_b_second),
        ] {
            let (candidate, envelope) =
                dreamer_claim_candidate_write_parts(&vault, body, actor, run_id)?;
            vault
                .batch()
                .claim_candidate(&claim_id, candidate, &envelope, test_time(4), 4)
                .commit()?;
            std::thread::sleep(Duration::from_millis(2));
        }

        let pending = vault.pending_gate_consents(10)?;
        assert_eq!(pending.len(), 5);
        assert_eq!(
            pending
                .iter()
                .find(|record| record.claim_id == *run_a_first.as_bytes())
                .and_then(|record| record.dreamer_run_id.as_deref()),
            Some(run_a)
        );
        assert_eq!(
            pending
                .iter()
                .find(|record| record.claim_id == *run_b_first.as_bytes())
                .and_then(|record| record.dreamer_run_id.as_deref()),
            Some(run_b)
        );
        assert_eq!(
            pending
                .iter()
                .find(|record| record.claim_id == *default_id.as_bytes())
                .and_then(|record| record.dreamer_run_id.as_deref()),
            None
        );

        let groups = vault.pending_gate_consent_groups(10)?;
        assert_eq!(groups.len(), 3);
        let group_ids = |run_id: Option<&str>| -> Vec<[u8; ENTITY_ID_LEN]> {
            groups
                .iter()
                .find(|group| group.dreamer_run_id.as_deref() == run_id)
                .expect("group exists")
                .records
                .iter()
                .map(|record| record.claim_id)
                .collect()
        };
        assert_eq!(
            group_ids(Some(run_a)),
            vec![*run_a_first.as_bytes(), *run_a_second.as_bytes()]
        );
        assert_eq!(
            group_ids(Some(run_b)),
            vec![*run_b_first.as_bytes(), *run_b_second.as_bytes()]
        );
        assert_eq!(group_ids(None), vec![*default_id.as_bytes()]);

        let mut approved_a_first = body_a_first;
        approved_a_first.approval = ClaimApprovalStatus::Approved;
        let (candidate, envelope) =
            dreamer_claim_candidate_write_parts(&vault, &approved_a_first, test_id(0xC1), run_a)?;
        vault
            .batch()
            .claim_candidate(&run_a_first, candidate, &envelope, test_time(5), 5)
            .commit()?;

        assert!(!has_pending_gate_consent(&vault, &run_a_first)?);
        assert!(has_pending_gate_consent(&vault, &run_a_second)?);
        assert_eq!(
            vault
                .get_claim(&run_a_first)?
                .expect("approved claim")
                .approval,
            ClaimApprovalStatus::Approved
        );

        let groups = vault.pending_gate_consent_groups(10)?;
        let run_a_after = groups
            .iter()
            .find(|group| group.dreamer_run_id.as_deref() == Some(run_a))
            .expect("run A group remains");
        assert_eq!(run_a_after.records.len(), 1);
        assert_eq!(run_a_after.records[0].claim_id, *run_a_second.as_bytes());
        Ok(())
    }

    #[test]
    fn approved_gate_consent_rejects_drifted_diff() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x94, &encode_policy_manifest(vec![]))?;

        let id = test_id(0x95);
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
        vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
            .commit()?;

        let mut drifted = proposed;
        drifted.value = Value::from("Grace");
        drifted.approval = ClaimApprovalStatus::Approved;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &drifted)?;
        let err = vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(4), 4)
            .commit()
            .expect_err("approval must bind to original pending diff");
        assert!(matches!(err, Error::GateConsentStale { claim_id } if claim_id == id));

        let pending = vault.with_write_txn(|wtxn| {
            vault
                .store
                .pending_gate_consent_in_txn(wtxn, &id)?
                .ok_or(Error::CorruptedIndex("pending gate consent"))
        })?;
        assert_eq!(pending.claim_id, *id.as_bytes());
        Ok(())
    }

    #[test]
    fn allowed_gate_consent_resolution_rejects_drifted_source_trust_pending() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![signatures_entry()]);
        append_actor_ceiling(&mut data, actor_ceiling_row("agent", "auto"));
        append_actor_ceiling(
            &mut data,
            actor_ceiling_row(LOCAL_WRITE_ACTOR_CLASS, "auto"),
        );
        put_policy_manifest_bytes(&vault, 0xA6, &data)?;

        let id = test_id(0xA7);
        let mut proposed = source_trust_claim(ClaimSource::Generated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) =
            dreamer_claim_candidate_write_parts(&vault, &proposed, test_id(0xA8), "run-a")?;
        vault.put_claim_candidate_without_lexical_query_reconcile(
            &id,
            candidate,
            &envelope,
            test_time(3),
            3,
        )?;

        let pending = vault.with_write_txn(|wtxn| {
            vault
                .store
                .pending_gate_consent_in_txn(wtxn, &id)?
                .ok_or(Error::CorruptedIndex("pending gate consent"))
        })?;
        assert_eq!(pending.reason_codes, vec!["gate.pending.source_trust"]);

        let stored = vault.get_claim(&id)?.expect("pending claim");
        let mut drifted = stored.clone();
        drifted.value = Value::from("Grace");
        drifted.approval = ClaimApprovalStatus::Approved;
        let err = vault
            .put_claim(&id, &drifted, test_time(4), 4)
            .expect_err("allow-path approval must bind to original pending diff");
        assert!(matches!(err, Error::GateConsentStale { claim_id } if claim_id == id));
        assert!(has_pending_gate_consent(&vault, &id)?);

        let mut approved = stored;
        approved.approval = ClaimApprovalStatus::Approved;
        vault.put_claim(&id, &approved, test_time(5), 5)?;

        assert!(!has_pending_gate_consent(&vault, &id)?);
        assert_eq!(
            vault.get_claim(&id)?.expect("approved claim").approval,
            ClaimApprovalStatus::Approved
        );
        Ok(())
    }

    #[test]
    fn approved_gate_consent_followup_succeeds_and_clears_pending() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x96, &encode_policy_manifest(vec![]))?;

        let id = test_id(0x97);
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &proposed)?;
        vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(3), 3)
            .commit()?;
        assert!(has_pending_gate_consent(&vault, &id)?);

        let mut approved = proposed;
        approved.approval = ClaimApprovalStatus::Approved;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &approved)?;
        vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(4), 4)
            .commit()?;

        assert!(!has_pending_gate_consent(&vault, &id)?);
        assert_eq!(
            vault.get_claim(&id)?.expect("approved claim").approval,
            ClaimApprovalStatus::Approved
        );
        Ok(())
    }

    #[test]
    fn same_batch_proposed_then_approved_rejects_without_pending_consent() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x98, &encode_policy_manifest(vec![]))?;

        let id = test_id(0x99);
        let mut proposed = source_trust_claim(ClaimSource::UserStated);
        proposed.approval = ClaimApprovalStatus::Proposed;
        let (proposed_candidate, proposed_envelope) =
            claim_candidate_write_parts(&vault, &proposed)?;
        let mut approved = proposed;
        approved.approval = ClaimApprovalStatus::Approved;
        let (approved_candidate, approved_envelope) =
            claim_candidate_write_parts(&vault, &approved)?;

        let err = vault
            .batch()
            .claim_candidate(&id, proposed_candidate, &proposed_envelope, test_time(3), 3)
            .claim_candidate(&id, approved_candidate, &approved_envelope, test_time(4), 4)
            .commit()
            .expect_err("same batch approval must not consume same batch consent");

        assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
        assert!(vault.get_raw(&id)?.is_none());
        assert!(!has_pending_gate_consent(&vault, &id)?);
        Ok(())
    }

    #[test]
    fn gate_chokepoint_batch_claim_denial_aborts_without_partial_writes() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![]);
        trust_human_candidate_actor(&mut data);
        put_policy_manifest_bytes(&vault, 0x76, &data)?;

        let prior_id = test_id(0x77);
        let claim_id = test_id(0x78);
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.predicate = "health.allergy".to_owned();
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

        let err = vault
            .batch()
            .put(&prior_id, ENTITY_TYPE_PERSON, test_time(7), 7, b"prior")
            .claim_candidate(&claim_id, candidate, &envelope, test_time(7), 7)
            .commit()
            .expect_err("critical local claim must stop at Gate");

        assert_gate_rejected(err, "pending", &["gate.pending.criticality_floor"]);
        assert!(vault.get_raw(&claim_id)?.is_none());
        assert!(vault.get_raw(&prior_id)?.is_none());
        Ok(())
    }

    #[test]
    fn gate_chokepoint_batch_policy_delete_cannot_weaken_later_claim() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![]);
        trust_human_candidate_actor(&mut data);
        let policy_id = test_id(0x95);
        put_policy_manifest_bytes(&vault, 0x95, &data)?;

        let claim_id = test_id(0x96);
        let mut body = source_trust_claim(ClaimSource::UserStated);
        body.predicate = "health.allergy".to_owned();
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

        let err = vault
            .batch()
            .delete(&policy_id)
            .claim_candidate(&claim_id, candidate, &envelope, test_time(7), 7)
            .commit()
            .expect_err("policy delete must not weaken same-batch Gate checks");

        assert_gate_rejected(err, "pending", &["gate.pending.criticality_floor"]);
        assert!(
            vault.get_raw(&policy_id)?.is_some(),
            "failed batch must not delete the active policy manifest"
        );
        assert!(vault.get_raw(&claim_id)?.is_none());
        Ok(())
    }

    #[test]
    fn gate_chokepoint_allows_proposed_claims_for_review_under_pending_policy() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![]);
        trust_human_candidate_actor(&mut data);
        put_policy_manifest_bytes(&vault, 0x97, &data)?;

        let claim_id = test_id(0x98);
        let mut body = source_trust_claim(ClaimSource::ToolOutput);
        body.predicate = "health.allergy".to_owned();
        body.approval = ClaimApprovalStatus::Proposed;
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;

        vault
            .batch()
            .claim_candidate(&claim_id, candidate, &envelope, test_time(7), 7)
            .commit()?;

        let stored = stored_claim_body(&vault, &claim_id)?;
        assert_eq!(stored.approval, ClaimApprovalStatus::Proposed);
        assert_eq!(stored.predicate, "health.allergy");
        Ok(())
    }

    #[test]
    fn gate_chokepoint_edge_provenance_uses_actor_gate_before_persistence() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![]);
        put_policy_manifest_bytes(&vault, 0x79, &data)?;

        let src = test_id(0x7A);
        let tgt = test_id(0x7B);
        let actor = test_id(0x7C);
        let claim_id = test_id(0x7D);
        let occurred = test_time(8);
        vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
        vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 8, b"actor")?;
        vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

        let subject = EdgeRef {
            source: src,
            kind: EdgeKind::Mentions,
            target: tgt,
        };
        let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
        let err = vault
            .put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 9)
            .expect_err("unlisted actor class must stop at Gate");

        assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
        assert!(vault.get_raw(&claim_id)?.is_none());
        Ok(())
    }

    #[test]
    fn gate_chokepoint_edge_provenance_retract_uses_gate_before_reserved_reput() -> Result<()> {
        let (_tmp, vault) = temp_vault();

        let src = test_id(0x90);
        let tgt = test_id(0x91);
        let actor = test_id(0x92);
        let claim_id = test_id(0x93);
        let occurred = test_time(8);
        vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
        vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
        vault.put_entity(&actor, ENTITY_TYPE_PERSON, occurred, 8, b"actor")?;
        vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

        let subject = EdgeRef {
            source: src,
            kind: EdgeKind::Mentions,
            target: tgt,
        };
        let body = EdgeProvenanceClaimBody::new(actor, 0.9, SupersessionStatus::Confirmed);
        vault.put_edge_provenance(&claim_id, &subject, &body, EdgeActorClass::Human, 9)?;

        let before_body = stored_claim_body(&vault, &claim_id)?;
        assert_eq!(before_body.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(before_body.valid_to, None);
        assert_eq!(
            edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
            EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Confirmed,
                actor_class: EdgeActorClass::Human,
            }
        );

        let data = encode_policy_manifest(vec![]);
        put_policy_manifest_bytes(&vault, 0x94, &data)?;

        let err = vault
            .retract_edge_provenance(&claim_id, 10)
            .expect_err("retraction must stop at Gate before reserved re-put");

        assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
        let after_body = stored_claim_body(&vault, &claim_id)?;
        assert_eq!(after_body.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(after_body.valid_to, None);
        assert_eq!(
            edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
            EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Confirmed,
                actor_class: EdgeActorClass::Human,
            }
        );
        Ok(())
    }

    #[test]
    fn gate_chokepoint_edge_provenance_supersede_checks_closed_prior_before_reput() -> Result<()> {
        let (_tmp, vault) = temp_vault();

        let src = test_id(0xA4);
        let tgt = test_id(0xA5);
        let human_actor = test_id(0xA6);
        let agent_actor = test_id(0xA7);
        let prior_claim_id = test_id(0xA8);
        let new_claim_id = test_id(0xA9);
        let occurred = test_time(8);
        vault.put_entity(&src, ENTITY_TYPE_PERSON, occurred, 8, b"src")?;
        vault.put_entity(&tgt, ENTITY_TYPE_PERSON, occurred, 8, b"tgt")?;
        vault.put_entity(&human_actor, ENTITY_TYPE_PERSON, occurred, 8, b"human")?;
        vault.put_entity(&agent_actor, ENTITY_TYPE_PERSON, occurred, 8, b"agent")?;
        vault.put_edge(&src, EdgeKind::Mentions, &tgt, 0.5)?;

        let subject = EdgeRef {
            source: src,
            kind: EdgeKind::Mentions,
            target: tgt,
        };
        let prior_body =
            EdgeProvenanceClaimBody::new(human_actor, 0.9, SupersessionStatus::Confirmed);
        vault.put_edge_provenance(
            &prior_claim_id,
            &subject,
            &prior_body,
            EdgeActorClass::Human,
            9,
        )?;

        let before_body = stored_claim_body(&vault, &prior_claim_id)?;
        assert_eq!(before_body.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(before_body.valid_to, None);
        assert_eq!(
            edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
            EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Confirmed,
                actor_class: EdgeActorClass::Human,
            }
        );

        let mut policy = encode_policy_manifest(vec![]);
        replace_actor_ceilings(
            &mut policy,
            vec![
                actor_ceiling_row("first_party", "auto"),
                actor_ceiling_row("agent", "auto"),
            ],
        );
        put_policy_manifest_bytes(&vault, 0xAA, &policy)?;

        let new_body =
            EdgeProvenanceClaimBody::new(agent_actor, 0.8, SupersessionStatus::Confirmed);
        let err = vault
            .put_edge_provenance(
                &new_claim_id,
                &subject,
                &new_body,
                EdgeActorClass::Agent,
                10,
            )
            .expect_err("superseded prior closure must stop at Gate before reserved re-put");

        assert_gate_rejected(err, "pending", &["gate.pending.actor_ceiling"]);
        assert!(vault.get_raw(&new_claim_id)?.is_none());
        let after_body = stored_claim_body(&vault, &prior_claim_id)?;
        assert_eq!(after_body.lifecycle, ClaimLifecycleStatus::Active);
        assert_eq!(after_body.valid_to, None);
        assert_eq!(
            edge_provenance_flags(&vault, &src, EdgeKind::Mentions, &tgt)?,
            EdgeProvenanceFlags {
                confirmation_status: EdgeConfirmationStatus::Confirmed,
                actor_class: EdgeActorClass::Human,
            }
        );
        Ok(())
    }

    #[test]
    fn policy_manifest_missing_fixture_fails_closed_where_required() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert_eq!(
            policy.actor_ceiling("first_party", None),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(
            policy.criticality_for_predicate("profile.name"),
            PolicyCriticality::Critical
        );

        assert_auto_source_rejected(&vault, 0x64, ClaimSource::ToolOutput)?;
        assert_auto_source_rejected(&vault, 0x65, ClaimSource::Imported)?;
        assert_auto_source_rejected(&vault, 0x66, ClaimSource::Generated)?;

        let id = test_id(0x67);
        let body = source_trust_claim(ClaimSource::Observed);
        let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
        vault
            .batch()
            .claim_candidate(&id, candidate, &envelope, test_time(4), 4)
            .commit()?;
        assert!(vault.get_raw(&id)?.is_some());
        Ok(())
    }

    #[test]
    fn policy_manifest_malformed_fixture_fails_closed() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        put_policy_manifest_bytes(&vault, 0x52, b"not-msgpack")?;

        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert!(policy.diagnostics().malformed_manifest_seen);
        assert!(policy.scoped_grants().is_empty());
        assert_eq!(
            policy.actor_ceiling("first_party", None),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(
            policy.criticality_for_predicate("profile.name"),
            PolicyCriticality::Critical
        );
        assert_auto_source_gate_rejected(
            &vault,
            0x67,
            ClaimSource::ToolOutput,
            "deny",
            &["gate.deny.policy_fail_closed"],
        )
    }

    #[test]
    fn policy_manifest_malformed_source_trust_fails_closed_with_diagnostics() -> Result<()> {
        enum SourceTrustMalformed {
            Duplicate,
            NotAMap,
        }

        let cases = [
            (
                "duplicate_source_trust",
                0xB0,
                SourceTrustMalformed::Duplicate,
            ),
            ("source_trust_not_map", 0xB2, SourceTrustMalformed::NotAMap),
        ];

        for (case_name, seed, malformed) in cases {
            let (_tmp, vault) = temp_vault();
            let mut data = encode_policy_manifest(vec![]);
            rewrite_policy_manifest_entries(&mut data, |entries| match malformed {
                SourceTrustMalformed::Duplicate => {
                    let entry = source_trust_entry(ClaimSource::UserStated, 0);
                    entries.push(entry.clone());
                    entries.push(entry);
                }
                SourceTrustMalformed::NotAMap => {
                    entries.push((Value::from(POLICY_SOURCE_TRUST_KEY), Value::from("bad")));
                }
            });
            put_policy_manifest_bytes(&vault, seed, &data)?;

            let policy = resolve(&vault)?;
            assert!(
                policy.diagnostics().malformed_manifest_seen,
                "{case_name}: malformed source_trust must set manifest diagnostics"
            );
            assert!(
                policy.is_fail_closed(),
                "{case_name}: policy must fail closed"
            );
            assert!(
                policy.enforces_write_gate(),
                "{case_name}: loaded malformed manifest must still enforce Gate"
            );

            let claim_id = test_id(seed + 1);
            let mut body = source_trust_claim(ClaimSource::UserStated);
            body.approval = ClaimApprovalStatus::Approved;
            let (candidate, envelope) = claim_candidate_write_parts(&vault, &body)?;
            let err = match vault
                .batch()
                .claim_candidate(&claim_id, candidate, &envelope, test_time(4), 4)
                .commit()
            {
                Ok(()) => {
                    panic!("{case_name}: fail-closed policy must reject non-auto normal claim")
                }
                Err(err) => err,
            };

            assert_gate_rejected(err, "deny", &["gate.deny.policy_fail_closed"]);
            assert!(vault.get_raw(&claim_id)?.is_none());
        }

        Ok(())
    }

    #[test]
    fn policy_manifest_missing_schema_fixture_fails_closed() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![
            source_trust_entry(ClaimSource::ToolOutput, 0),
            scoped_grants_entry(),
        ]);
        rewrite_policy_manifest_entries(&mut data, |entries| {
            entries.retain(|(key, _)| key.as_str() != Some(POLICY_SCHEMA_VERSION_KEY));
        });
        put_policy_manifest_bytes(&vault, 0x54, &data)?;

        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert!(policy.diagnostics().unsupported_schema_seen);
        assert!(policy.scoped_grants().is_empty());
        assert_eq!(
            policy.actor_ceiling("first_party", None),
            PolicyApprovalCeiling::Proposed
        );
        assert_auto_source_gate_rejected(
            &vault,
            0x69,
            ClaimSource::ToolOutput,
            "deny",
            &["gate.deny.policy_fail_closed"],
        )
    }

    #[test]
    fn policy_manifest_version_fixture_degrades_to_most_restrictive() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![
            source_trust_entry(ClaimSource::ToolOutput, 0),
            scoped_grants_entry(),
        ]);
        rewrite_policy_manifest_entries(&mut data, |entries| {
            for (key, value) in entries {
                if key.as_str() == Some(POLICY_MIN_ENGINE_VERSION_KEY) {
                    *value = Value::from("999.0.0");
                }
            }
        });
        put_policy_manifest_bytes(&vault, 0x53, &data)?;

        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert!(policy.diagnostics().engine_version_floor_seen);
        assert!(policy.scoped_grants().is_empty());
        assert_eq!(
            policy.actor_ceiling("first_party", None),
            PolicyApprovalCeiling::Proposed
        );
        assert_eq!(
            policy.criticality_for_predicate("health.allergy"),
            PolicyCriticality::Critical
        );
        assert_auto_source_gate_rejected(
            &vault,
            0x68,
            ClaimSource::ToolOutput,
            "deny",
            &["gate.deny.policy_fail_closed"],
        )
    }

    #[test]
    fn policy_manifest_unknown_axis_fails_closed_and_exposes_no_scoped_grants() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut data = encode_policy_manifest(vec![
            source_trust_entry(ClaimSource::ToolOutput, 0),
            scoped_grants_entry(),
        ]);
        rewrite_policy_manifest_entries(&mut data, |entries| {
            for (key, value) in entries {
                if key.as_str() == Some(POLICY_DEFAULTS_KEY) {
                    let Value::Map(defaults) = value else {
                        unreachable!("defaults are a map");
                    };
                    defaults.push((Value::from("future_axis"), Value::from("permit")));
                }
            }
        });
        put_policy_manifest_bytes(&vault, 0x55, &data)?;

        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert!(policy.diagnostics().unknown_axis_seen);
        assert!(policy.scoped_grants().is_empty());
        assert_eq!(
            policy.sensitivity_for_predicate("profile.name"),
            PolicySensitivity::Sensitive
        );
        assert_auto_source_gate_rejected(
            &vault,
            0x6A,
            ClaimSource::ToolOutput,
            "deny",
            &["gate.deny.policy_fail_closed"],
        )
    }

    #[test]
    fn legacy_source_trust_pack_entity_does_not_relax_policy_inputs() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let mut legacy = Vec::new();
        rmpv::encode::write_value(
            &mut legacy,
            &Value::Map(vec![
                (
                    Value::from("manifest"),
                    Value::from("dec_0005_predicate_pack"),
                ),
                source_trust_entry(ClaimSource::ToolOutput, 0),
            ]),
        )
        .expect("legacy source-trust encode");

        vault.put_entity(
            &test_id(0x56),
            crate::types::ENTITY_TYPE_TASK_LIST,
            test_time(1),
            1,
            &legacy,
        )?;

        let policy = resolve(&vault)?;
        assert!(policy.is_fail_closed());
        assert_eq!(policy.diagnostics().manifest_count, 0);
        assert_auto_source_rejected(&vault, 0x6B, ClaimSource::ToolOutput)
    }

    #[cfg(feature = "sync")]
    #[test]
    fn replay_path_skips_policy_source_trust_gate() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let id = test_id(0x81);
        let data = source_trust_claim_data(ClaimSource::ToolOutput);

        vault
            .batch()
            .put_replicated(&id, crate::types::ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
            .commit()?;

        assert!(
            vault.get_raw(&id)?.is_some(),
            "replicated replay must not re-gate remote source trust"
        );
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn replicated_generated_auto_claim_merges_but_is_not_consolidatable() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let strict_policy =
            encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]);
        put_policy_manifest_bytes(&vault, 0x87, &strict_policy)?;

        let id = test_id(0x88);
        let data = source_trust_claim_data(ClaimSource::Generated);
        vault
            .batch()
            .put_replicated(&id, crate::types::ENTITY_TYPE_CLAIM, test_time(5), 5, &data)
            .commit()?;

        let raw = vault
            .get_raw(&id)?
            .expect("foreign-manifest-approved descendant still merges");
        let body = decode_claim_body(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..], false)?;
        assert_eq!(body.source, Some(ClaimSource::Generated));
        assert!(
            crate::claim::claim_surfaceable(&body),
            "foreign-approved Auto/Generated descendant may still surface"
        );
        assert!(
            !crate::claim::claim_consolidatable(&body),
            "strict local consolidation must decline it as corroboration"
        );
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn federated_admission_allows_and_restamps_imported_claim() -> Result<()> {
        use crate::batch::ENTITY_METADATA_HEADER_LEN;
        use crate::sync::loro_support::{import_doc, map_get_bytes};
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::Imported, 0)]);
        put_policy_manifest_bytes(&vault, 0x8A, &data)?;

        let id = test_id(0x8B);
        let remote_body = source_trust_claim(ClaimSource::ToolOutput);
        let update = federated_claim_update(&id, &remote_body)?;
        let key = WindowKey::new("2026-03");
        let admitted =
            admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Member)?;

        let doc = create_window_doc("receiver", &key);
        import_doc(&doc, &admitted)?;
        let blob =
            map_get_bytes(&doc.get_map("entities"), &id.to_hex()).ok_or(Error::InvalidKey)?;
        let body = decode_claim_body(&blob[ENTITY_METADATA_HEADER_LEN..], false)?;
        assert_eq!(body.source, Some(ClaimSource::Imported));
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn federated_admission_denies_untrusted_import_with_auditable_reason() -> Result<()> {
        use crate::sync::types::WindowKey;
        use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

        let (_tmp, vault) = temp_vault();
        let id = test_id(0x8C);
        let remote_body = source_trust_claim(ClaimSource::ToolOutput);
        let update = federated_claim_update(&id, &remote_body)?;
        let key = WindowKey::new("2026-03");

        let err =
            admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Guest)
                .expect_err("imported auto claims need an explicit local trust floor");
        assert_gate_rejected(err, "pending", &["gate.pending.source_trust"]);
        assert!(vault.get_raw(&id)?.is_none());
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn federated_admission_denies_preapproved_untrusted_import() -> Result<()> {
        use crate::sync::types::WindowKey;
        use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

        let (_tmp, vault) = temp_vault();
        let id = test_id(0x8F);
        let mut remote_body = source_trust_claim(ClaimSource::ToolOutput);
        remote_body.approval = ClaimApprovalStatus::Approved;
        let update = federated_claim_update(&id, &remote_body)?;
        let key = WindowKey::new("2026-03");

        let err =
            admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Member)
                .expect_err("preapproved federated claims still need local imported trust");
        assert_gate_rejected(err, "pending", &["gate.pending.source_trust"]);
        assert!(vault.get_raw(&id)?.is_none());
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn federated_admission_denial_does_not_regress_own_device_replay() -> Result<()> {
        use crate::sync::types::WindowKey;
        use crate::sync::{FederationAdmissionRole, admit_federated_window_update};

        let (_tmp, vault) = temp_vault();
        let id = test_id(0x8D);
        let remote_body = source_trust_claim(ClaimSource::ToolOutput);
        let update = federated_claim_update(&id, &remote_body)?;
        let key = WindowKey::new("2026-03");
        let err =
            admit_federated_window_update(&vault, &key, &update, FederationAdmissionRole::Member)
                .expect_err("federated path must enforce local imported trust floor");
        assert_gate_rejected(err, "pending", &["gate.pending.source_trust"]);

        let replay_id = test_id(0x8E);
        let replay_data = crate::claim::encode_claim_body(&remote_body)?;
        vault
            .batch()
            .put_replicated(
                &replay_id,
                crate::types::ENTITY_TYPE_CLAIM,
                test_time(5),
                5,
                &replay_data,
            )
            .commit()?;
        assert!(
            vault.get_raw(&replay_id)?.is_some(),
            "own-device replicated replay remains trust-blind"
        );
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn gate_chokepoint_replicated_claim_stays_trust_blind() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![]);
        put_policy_manifest_bytes(&vault, 0x80, &data)?;

        let id = test_id(0x83);
        let claim = source_trust_claim_data(ClaimSource::ToolOutput);
        vault
            .batch()
            .put_replicated(
                &id,
                crate::types::ENTITY_TYPE_CLAIM,
                test_time(5),
                5,
                &claim,
            )
            .commit()?;

        assert!(
            vault.get_raw(&id)?.is_some(),
            "replicated replay must not call the local Gate chokepoint"
        );
        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn replicated_policy_manifest_is_rejected_and_cannot_relax_source_trust() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
        let occurred = test_time(1);

        let batch_id = test_id(0x82);
        let err = vault
            .batch()
            .put_replicated(&batch_id, ENTITY_TYPE_POLICY_MANIFEST, occurred, 1, &data)
            .commit()
            .expect_err("replicated policy manifests must be rejected");
        assert!(
            matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_POLICY_MANIFEST),
            "expected policy manifest maintenance rejection, got {err:?}"
        );
        assert!(vault.get_raw(&batch_id)?.is_none());

        let txn_id = test_id(0x83);
        let err = vault
            .with_write_txn(|wtxn| {
                vault
                    .batch_in()
                    .put_replicated(&txn_id, ENTITY_TYPE_POLICY_MANIFEST, occurred, 1, &data)
                    .apply(wtxn)
            })
            .expect_err("txn replicated policy manifests must be rejected");
        assert!(
            matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_POLICY_MANIFEST),
            "expected policy manifest maintenance rejection, got {err:?}"
        );
        assert!(vault.get_raw(&txn_id)?.is_none());

        assert_auto_source_rejected(&vault, 0x84, ClaimSource::ToolOutput)
    }

    #[cfg(feature = "sync")]
    #[test]
    fn replicated_access_grant_is_rejected_and_cannot_mint_local_grant() -> Result<()> {
        let (_tmp, vault) = temp_vault();
        let principal = test_id(0x90);
        let person = test_id(0x91);
        let persona = test_id(0x92);
        let data = crate::encode_access_grant_body(&crate::AccessGrant::companion_profile_read(
            principal, person, persona, 1,
        ))?;
        let occurred = test_time(1);

        let batch_id = test_id(0x93);
        let err = vault
            .batch()
            .put_replicated(&batch_id, ENTITY_TYPE_ACCESS_GRANT, occurred, 1, &data)
            .commit()
            .expect_err("replicated access grants must be rejected");
        assert!(
            matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_ACCESS_GRANT),
            "expected access grant maintenance rejection, got {err:?}"
        );
        assert!(vault.get_raw(&batch_id)?.is_none());
        assert_eq!(
            vault.companion_profile_access_grant(&principal, &person, &persona)?,
            None
        );

        let txn_id = test_id(0x94);
        let err = vault
            .with_write_txn(|wtxn| {
                vault
                    .batch_in()
                    .put_replicated(&txn_id, ENTITY_TYPE_ACCESS_GRANT, occurred, 1, &data)
                    .apply(wtxn)
            })
            .expect_err("txn replicated access grants must be rejected");
        assert!(
            matches!(err, Error::MaintenanceKindNotWritable(kind) if kind == ENTITY_TYPE_ACCESS_GRANT),
            "expected access grant maintenance rejection, got {err:?}"
        );
        assert!(vault.get_raw(&txn_id)?.is_none());
        assert_eq!(
            vault.companion_profile_access_grant(&principal, &person, &persona)?,
            None
        );

        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn forward_rematerialize_quarantines_replicated_policy_manifest() -> Result<()> {
        use crate::sync::bridge::Materializer;
        use crate::sync::loro_support::map_insert_bytes;
        use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window::forward_rematerialize;

        let (_tmp, vault) = temp_vault();
        let data = encode_policy_manifest(vec![source_trust_entry(ClaimSource::ToolOutput, 0)]);
        let id = test_id(0x85);
        let window_key = WindowKey::new("2026-03");
        let doc = create_window_doc("local", &window_key);
        let blob = policy_manifest_blob(&data);
        map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)
            .expect("insert policy manifest into CRDT");
        doc.commit();

        let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
        assert_eq!(materialized, 0);
        assert!(vault.get_raw(&id)?.is_none());
        let records = quarantined_records(&vault)?;
        assert!(
            records.iter().any(|(_, record)| {
                record.container == QuarantineContainer::Entities
                    && record.reason_code == "MaintenanceKindNotWritable"
            }),
            "rejected policy manifest replay should be quarantined, got {records:?}"
        );

        assert_auto_source_rejected(&vault, 0x86, ClaimSource::ToolOutput)
    }

    #[cfg(feature = "sync")]
    #[test]
    fn forward_rematerialize_quarantines_malformed_authority_log() -> Result<()> {
        use crate::sync::bridge::Materializer;
        use crate::sync::loro_support::map_insert_bytes;
        use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window::forward_rematerialize;

        let (_tmp, vault) = temp_vault();
        let id = test_id(0x87);
        let window_key = WindowKey::new("2026-03");
        let doc = create_window_doc("local", &window_key);
        let blob = authority_log_blob(b"not an authority log body");
        map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)
            .expect("insert malformed authority log into CRDT");
        doc.commit();

        let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
        assert_eq!(materialized, 0);
        assert!(vault.get_raw(&id)?.is_none());
        let records = quarantined_records(&vault)?;
        assert!(
            records.iter().any(|(_, record)| {
                record.container == QuarantineContainer::Entities
                    && record.reason_code == "InvalidAuthorityLogBody"
            }),
            "malformed authority log replay should be quarantined, got {records:?}"
        );

        Ok(())
    }

    #[cfg(feature = "sync")]
    #[test]
    fn forward_rematerialize_quarantines_replicated_access_grant() -> Result<()> {
        use crate::sync::bridge::Materializer;
        use crate::sync::loro_support::map_insert_bytes;
        use crate::sync::quarantine::{QuarantineContainer, quarantined_records};
        use crate::sync::schema::create_window_doc;
        use crate::sync::types::WindowKey;
        use crate::sync::window::forward_rematerialize;

        let (_tmp, vault) = temp_vault();
        let principal = test_id(0x95);
        let person = test_id(0x96);
        let persona = test_id(0x97);
        let data = crate::encode_access_grant_body(&crate::AccessGrant::companion_profile_read(
            principal, person, persona, 1,
        ))?;
        let id = test_id(0x98);
        let window_key = WindowKey::new("2026-03");
        let doc = create_window_doc("local", &window_key);
        let blob = access_grant_blob(&data);
        map_insert_bytes(&doc.get_map("entities"), &id.to_hex(), &blob)
            .expect("insert access grant into CRDT");
        doc.commit();

        let materialized = forward_rematerialize(&vault, &doc, &Materializer::new(), &window_key)?;
        assert_eq!(materialized, 0);
        assert!(vault.get_raw(&id)?.is_none());
        assert_eq!(
            vault.companion_profile_access_grant(&principal, &person, &persona)?,
            None
        );
        let records = quarantined_records(&vault)?;
        assert!(
            records.iter().any(|(_, record)| {
                record.container == QuarantineContainer::Entities
                    && record.reason_code == "MaintenanceKindNotWritable"
            }),
            "rejected access grant replay should be quarantined, got {records:?}"
        );

        Ok(())
    }
}
