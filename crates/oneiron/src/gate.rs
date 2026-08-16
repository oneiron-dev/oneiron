//! DEC-0005 Gate policy manifest resolver.
//!
//! GATE-001 added stable decision inputs. GATE-002 routes local write doors
//! through the evaluator while keeping replicated replay trust-blind.

#[cfg(test)]
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

use rmpv::Value;
use sha2::{Digest, Sha256};

use crate::authority::{CRITICAL_WRITE_CONFIRM_DOMAIN, CriticalWriteConfirmDisposition};

use crate::agent_def::{AgentCeiling, decode_agent_definition};
use crate::batch::{
    BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_session_bundle_claim_puts,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ScopedReadActorKey,
    SessionClaimBundle, SessionClaimBundleClaim, claim_sensitivity_band, encode_claim_body,
    sensitivity_band_from_value,
};
use crate::connector_key::{
    self, ConnectorKeyStatus, EffectorBudgetCharge, EffectorBudgetChargeOutcome,
    EffectorBudgetOnExhaust,
};
use crate::counterparty_contact::{
    CounterpartyContactRecord, CounterpartyFirstTouch, counterparty_contact_index_key,
    counterparty_contact_matches_channel_class, counterparty_contacts_by_party_channel,
    counterparty_contacts_by_party_full_scan, decode_counterparty_contact_index_value,
    normalize_channel_class, read_counterparty_contact_in_txn,
};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::edge::EdgeActorClass;
use crate::entity_id::{ENTITY_ID_LEN, EntityId, bytes_to_hex_lower};
use crate::error::{Error, Result};
use crate::genui::{GrantMintIntent, GrantMintIntentScope};
use crate::llm::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetPolicyRow, BudgetPolicySelector, BudgetPolicyTable,
    CallPurpose,
};
use crate::outbound_consent::{
    ScopedMcpCallContext, ScopedMcpConsentDecision, evaluate_scoped_mcp_call,
};
use crate::outbound_grant::{
    StandingOutboundGrant, decode_standing_outbound_grant_body,
    encode_standing_outbound_grant_body, standing_outbound_grant_principal_index_entity_id,
    standing_outbound_grant_principal_index_prefix,
};
use crate::provenance::PREDICATE_EDGE_PROVENANCE;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_COUNTERPARTY_CONTACT;
use crate::registry::{
    ENTITY_TYPE_ACCESS_GRANT, ENTITY_TYPE_AGENT_DEF, ENTITY_TYPE_CLAIM, ENTITY_TYPE_OUTBOUND_GRANT,
    ENTITY_TYPE_POLICY_MANIFEST,
};
use crate::store::{GateDecisionId, GateDecisionRecord, PendingGateConsentRecord, Store};
use crate::temporal::TimeRange;
use crate::vault::Vault;
use crate::write_envelope::{WriteActor, WriteEnvelope, WriteProvenance};

/// Receipt reason for a deny whose only restrictive source is a CA-01
/// `comm.do_not_contact` head. Inside `store.rs`'s closed `counterparty_*`
/// receipt-reason family.
const COUNTERPARTY_OPT_OUT_DO_NOT_CONTACT_RECEIPT_REASON: &str =
    "counterparty_opt_out_do_not_contact";

pub const CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS: u64 = 300;
// A public listing uses one expiry pass plus one listing pass: at most 512 rows total.
const CRITICAL_CONFIRM_SWEEP_PAGE_LIMIT: usize = 256;
const CRITICAL_CONFIRM_LIST_CALL_ROW_BUDGET: usize = CRITICAL_CONFIRM_SWEEP_PAGE_LIMIT * 2;
pub const GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED: &str =
    "gate.allow.critical_confirm_attached";
// The decision receipt uses the allow namespace; the durable pending row must
// remain in store.rs's existing pending namespace.
const GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED: &str =
    "gate.pending.critical_confirm_attached";
pub const GATE_REASON_CRITICAL_CONFIRM_TIMEOUT: &str = "gate.pending.critical_confirm_timeout";
pub const GATE_REASON_CRITICAL_CONFIRM_DECLINED: &str = "gate.retract.critical_confirm_declined";
pub(crate) const GATE_REASON_CRITICAL_CONFIRM_REPLICATED_OVERWRITE: &str =
    "gate.retract.critical_confirm_replicated_overwrite";

const POLICY_SCHEMA_VERSION_KEY: &str = "schema_version";
pub(crate) const POLICY_SCHEMA_VERSION: &str = "1.1";
const POLICY_PACK_ID_KEY: &str = "pack_id";
const POLICY_PACK_VERSION_KEY: &str = "pack_version";
const POLICY_MIN_ENGINE_VERSION_KEY: &str = "min_engine_version";
const POLICY_DEFAULTS_KEY: &str = "defaults";
const POLICY_RULES_KEY: &str = "rules";
const POLICY_ACTOR_CEILINGS_KEY: &str = "actor_ceilings";
pub(crate) const POLICY_DELEGATED_GRANTS_KEY: &str = "delegated_grants";
pub(crate) const MAX_DELEGATION_DEPTH: u8 = 8;
const POLICY_SOURCE_TRUST_KEY: &str = "source_trust";
const POLICY_SCOPED_GRANTS_KEY: &str = "scoped_grants";
const POLICY_SIGNATURE_KEY: &str = "signature";
const POLICY_SIGNATURES_KEY: &str = "signatures";
const POLICY_ON_BUDGET_EXHAUSTED_KEY: &str = "on_budget_exhausted";
/// Optional top-level manifest key whose value is an ordered MessagePack
/// array of row maps. Each row selects exactly one call set — one `purpose`
/// string (a pinned `CallPurpose` snake-case name, or any other non-empty
/// string for `CallPurpose::Other { name }`) or one `actor` ref (the
/// canonical lowercase 32-hex form of `WriteActor::entity_ref().to_hex()`) —
/// and carries a `floor`, a `cap`, or both, as unsigned 64-bit integers in
/// the LLM budget meter's units.
///
/// A floor is a non-borrowable reservation only matching calls may draw, and
/// a cap is conjunctive admission policy a matching call must fit under every
/// instance of. Both directions are deliberate policy rather than capacity
/// tuning: floors strand budget on quiet days, and caps refuse matching work
/// while the pool still has room. An absent key and an explicit empty array
/// resolve identically to the plain single-pool meter.
///
/// Rows are data the manifest authors; the engine installs no rows of its
/// own and gives no purpose an implicit reservation. Two shapes a manifest
/// may author (the numbers are illustrative, never engine defaults):
///
/// ```text
/// # Consolidation is guaranteed a reserved slice.
/// { purpose: "consolidation", floor: 200_000 }
///
/// # One autonomous agent is guaranteed a slice but cannot consume the vault.
/// { actor: "<canonical-actor-ref>", floor: 50_000, cap: 150_000 }
/// ```
const POLICY_BUDGET_POLICY_KEY: &str = "budget_policy";
const BUDGET_POLICY_PURPOSE_KEY: &str = "purpose";
const BUDGET_POLICY_ACTOR_KEY: &str = "actor";
const BUDGET_POLICY_FLOOR_KEY: &str = "floor";
const BUDGET_POLICY_CAP_KEY: &str = "cap";
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
const GATE_METRIC_REASON_CLASS_COUNT: usize = 15;

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

    /// Gate-side conversion from the persisted AGENT_DEF descriptor mirror.
    /// Lives here so the dependency direction stays `gate.rs` → `agent_def.rs`
    /// and `PolicyApprovalCeiling` stays `pub(crate)`.
    pub(crate) fn from_agent_ceiling(ceiling: AgentCeiling) -> Self {
        match ceiling {
            AgentCeiling::Auto => Self::Auto,
            AgentCeiling::Proposed => Self::Proposed,
        }
    }

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

/// OF-074 symmetry helper mirroring [`foreign_agent_effective_ceiling`]: a
/// dispatched agent's effective ceiling is its definition-authored bound
/// restricted by the owner's `actor_ceilings` manifest projection.
#[must_use]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn dispatched_agent_effective_ceiling(
    definition: PolicyApprovalCeiling,
    policy_projection: PolicyApprovalCeiling,
) -> PolicyApprovalCeiling {
    definition.restrict(policy_projection)
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
enum DelegationGrantRecord {
    Grant {
        grant_ref: String,
        actor_class: String,
        actor_ref: Option<String>,
        parent_grant_ref: Option<String>,
        ceiling: PolicyApprovalCeiling,
    },
    RevokeGrant {
        grant_ref: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FoldedDelegation {
    effective_ceiling: Option<PolicyApprovalCeiling>,
    depth: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DelegationFoldCache {
    by_grant_ref: BTreeMap<String, FoldedDelegation>,
    records: BTreeMap<String, DelegationGrantRecord>,
    /// Revocations remain durable even when a later manifest also mentions the grant.
    revoked: BTreeSet<String>,
}
impl DelegationFoldCache {
    pub(crate) fn effective_ceiling(&self, grant_ref: &str) -> Option<PolicyApprovalCeiling> {
        self.by_grant_ref
            .get(grant_ref)
            .and_then(|x| x.effective_ceiling)
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
    pub(crate) delegation_grant_ref: Option<String>,
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
    /// The AGENT_DEF-authored ceiling bound resolved live for definition-bound
    /// actors ([`agent_definition_ceiling_for_actor`]); `None` = no definition
    /// bound (owner writes, connectors, non-definition agent actors) —
    /// preserves pre-AGENT-2 behavior at every existing construction site.
    pub(crate) agent_definition_ceiling: Option<PolicyApprovalCeiling>,
    /// The DEC-0006 consent context, when the caller composed one. `None` =
    /// this door has not been moved onto the unified consent path yet and
    /// keeps its pre-DEC-0006 criticality behaviour.
    pub(crate) consent: Option<ConsentGateContext>,
}

/// The DEC-0006 inputs the Gate needs to run the consent ladder.
///
/// The Gate does not compose these: `consent.rs` owns the evaluation, and this
/// carries its verdict plus the reason the verdict was reached, so the receipt
/// records WHY an op asked rather than only THAT it asked.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConsentGateContext {
    /// The consent evaluator's verdict for this operation.
    pub(crate) decision: crate::consent::ConsentDecision,
    /// Why the verdict was reached, when it was not Auto.
    pub(crate) reason: Option<ConsentPendingReason>,
}

/// Stable pending-reason codes for the DEC-0006 consent ladder.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsentPendingReason {
    /// Irreversible in effect, with no approve-once receipt or covering grant.
    IrreversibleEffect,
    /// A standing grant exists but the candidate exceeds its bound.
    BoundExceeded,
    /// The closed catastrophe floor matched — the only always-gate.
    CatastropheFloor,
    /// Required write facts were malformed or absent (invariant 8 fallback).
    WriteClassificationFailed,
}

impl ConsentGateContext {
    /// Runs the DEC-0006 evaluator and packages its verdict for the Gate.
    ///
    /// This is the ONE composer: `consent.rs` owns the decision, and the Gate
    /// only translates it into reason codes. Keeping the call here means a
    /// door opts into the unified consent path by composing a
    /// [`crate::consent::ComposedEffect`], never by re-implementing the ladder.
    pub(crate) fn evaluate(
        effect: &crate::consent::ComposedEffect,
        approve_once: Option<&crate::consent::ApproveOnceAuthorization>,
        grants: &[crate::consent::StandingConsentGrant],
    ) -> Self {
        let decision = crate::consent::evaluate_consent(effect, approve_once, grants);
        Self {
            decision,
            reason: (decision != crate::consent::ConsentDecision::Auto)
                .then(|| Self::pending_reason(effect, grants)),
        }
    }

    /// Why a non-Auto verdict was reached, in the evaluator's own precedence:
    /// catastrophe first, then a classification failure, then a bound a grant
    /// names but does not cover, else the plain irreversible case.
    fn pending_reason(
        effect: &crate::consent::ComposedEffect,
        grants: &[crate::consent::StandingConsentGrant],
    ) -> ConsentPendingReason {
        if effect.catastrophe().is_some() {
            return ConsentPendingReason::CatastropheFloor;
        }
        if crate::consent::classify_composed_effect(effect.facts()).is_err() {
            return ConsentPendingReason::WriteClassificationFailed;
        }
        if crate::consent::bound_exceeded(effect, grants) {
            return ConsentPendingReason::BoundExceeded;
        }
        ConsentPendingReason::IrreversibleEffect
    }
}

impl ConsentPendingReason {
    const fn reason_code(self) -> GateReasonCode {
        match self {
            Self::IrreversibleEffect => GateReasonCode::PendingConsentIrreversibleEffect,
            Self::BoundExceeded => GateReasonCode::PendingConsentBoundExceeded,
            Self::CatastropheFloor => GateReasonCode::PendingConsentCatastropheFloor,
            Self::WriteClassificationFailed => {
                GateReasonCode::PendingConsentWriteClassificationFailed
            }
        }
    }
}

/// Translates a consent verdict into Gate pending reasons.
///
/// `Auto` contributes nothing (the op runs). `Ask` and `Hide` both hold the
/// write — the difference between them is the SURFACE the host raises, which
/// is the domain fail-safe (invariant 8) and is carried by the reason, not by
/// a second Gate outcome.
/// The stable `gate.`-namespaced reason-code strings for one consent verdict.
///
/// Empty exactly when the verdict is Auto.
pub(crate) fn consent_gate_reason_codes(consent: &ConsentGateContext) -> Vec<String> {
    consent_ladder_reasons(Some(consent))
        .into_iter()
        .map(|code| code.as_str().to_owned())
        .collect()
}

fn consent_ladder_reasons(consent: Option<&ConsentGateContext>) -> Vec<GateReasonCode> {
    let Some(consent) = consent else {
        return Vec::new();
    };
    match consent.decision {
        crate::consent::ConsentDecision::Auto => Vec::new(),
        crate::consent::ConsentDecision::Ask | crate::consent::ConsentDecision::Hide => {
            vec![
                consent
                    .reason
                    .unwrap_or(ConsentPendingReason::IrreversibleEffect)
                    .reason_code(),
            ]
        }
    }
}

/// Composes the DEC-0006 consent context for one external effect.
///
/// This is how the ONE production external-effect door
/// ([`evaluate_external_effect_policy`]) opts onto the unified consent path:
/// it maps the engine-observed effect facts into a [`crate::consent::ComposedEffect`]
/// and runs the ONE evaluator, so no caller re-implements the ladder or
/// smuggles a caller-chosen `reversible` verdict in (invariant 6 — every fact
/// here is host-observed: an outbound send is irreversible-in-effect by
/// construction, with external observers on the channel).
///
/// Returns `None` when the effect facts cannot be normalized into an honest
/// requirement pair (a verb or channel that fails the bound-ref rules) — the
/// door then keeps its pre-DEC-0006 criticality behaviour rather than
/// fabricate a bound no grant could ever cover or could always cover.
fn external_effect_composed_effect(
    effect: &ExternalEffectGateInput,
) -> Option<crate::consent::ComposedEffect> {
    let facts = external_effect_facts(effect);
    let requirement = external_effect_action_requirement(effect)?;
    crate::consent::ComposedEffect::new(facts)
        .with_action_requirement(requirement)
        .ok()
}

fn external_effect_consent_context(
    effect: &ExternalEffectGateInput,
    approve_once: Option<&crate::consent::ApproveOnceAuthorization>,
    grants: &[crate::consent::StandingConsentGrant],
) -> Option<ConsentGateContext> {
    let composed = external_effect_composed_effect(effect)?;
    Some(ConsentGateContext::evaluate(
        &composed,
        approve_once,
        grants,
    ))
}

/// The host-observed fact set for one external effect, in the consent
/// evaluator's vocabulary. An external send/deploy is irreversible-in-effect
/// and externally observable by definition; nothing here is caller-asserted.
fn external_effect_facts(effect: &ExternalEffectGateInput) -> crate::consent::EffectFacts {
    let operation_kind = if effect.verb.trim().is_empty() {
        format!("external:{}", effect.channel.trim())
    } else {
        format!("external:{}:{}", effect.channel.trim(), effect.verb.trim())
    };
    crate::consent::EffectFacts {
        operation_kind,
        // An outbound effect rides the transport's send hook chain.
        fires_hooks: true,
        // A dispatch leaves this vault: it is published to (observed by) the
        // channel's counterparties, so undo cannot retract it.
        triggers_publish: true,
        external_observers: true,
        undo_fidelity: crate::consent::UndoFidelity::None,
        blast_radius: 1,
        catastrophe: None,
    }
}

/// The action requirement one external effect must be covered by: acting actor
/// × its verb class × an envelope naming the verb selector.
///
/// The selector vocabulary mirrors the canonical
/// [`crate::consent::action_grant_from_standing_outbound_grant`] adapter
/// (`verb:<class>` / `channel:<channel>` / `contact:<ref>` / `brief:<ref>`),
/// so a legacy grant scope-matched onto this effect reads as consent-COVERING
/// it — the fold that closes the write-side residual without minting a second
/// rememberable lane. An effect whose verb class is not named by a grant's
/// dial is envelope-uncovered on the same axis, so it still asks (the DEC-0006
/// bound-exceeded path). The actor is NOT class-narrowed and the envelope is
/// NOT target-pinned: the adapter mints grants on `principal_ref` alone, and
/// the door's scope matcher already verified the channel/contact/brief axes on
/// this txn before this fold runs.
fn external_effect_action_requirement(
    effect: &ExternalEffectGateInput,
) -> Option<crate::consent::GrantBound> {
    let actor_ref = effect
        .actor
        .actor_ref
        .clone()
        .or_else(|| effect.provenance.actor_entity_ref.map(|id| id.to_hex()))?;
    let verb_class = if effect.verb.trim().is_empty() {
        effect.channel.trim()
    } else {
        effect.verb.trim()
    };
    // The envelope's selectors name the verb axis exactly as the legacy
    // adapter mints it (`verb:<class>`), so a scope-matched grant's fold reads
    // as containing the effect. The channel axis rides the TARGET pin instead
    // of the selector set — the selectors must stay verb-shaped or a
    // verb-class grant (selector `[verb:send]`) would fail subset-containment
    // against a candidate that also names its channel. Target-pinning to the
    // channel mirrors the `Channel` dial's target arm, so `Channel{email}`
    // contains an email-send while a `BriefVerbClass{brief}` grant covers only
    // its own brief; a verb-class grant with NO target pin covers both.
    let mut envelope = crate::consent::ActionEnvelope::new([format!("verb:{verb_class}")]).ok()?;
    let target = effect
        .brief_ref
        .as_deref()
        .unwrap_or_else(|| effect.channel.trim());
    if !target.is_empty() {
        envelope = envelope.with_target(target).ok()?;
    }
    crate::consent::GrantBound::action(
        crate::consent::ActorBound::new(actor_ref).ok()?,
        crate::consent::ActionClass::new(verb_class).ok()?,
        envelope,
    )
    .ok()
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
    pub(crate) scoped_mcp_call: Option<ScopedMcpCallContext>,
    pub(crate) scoped_mcp_grant_authorized: bool,
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
    pub(crate) scoped_mcp_call: Option<ScopedMcpCallContext>,
    pub(crate) counterparty_first_touch: Option<CounterpartyFirstTouch>,
    pub(crate) counterparty_opted_out: bool,
    pub(crate) counterparty_opt_out_receipt_reason: Option<&'static str>,
    pub(crate) has_opted_in: bool,
    pub(crate) has_permission: bool,
    pub(crate) policy_risk: ExternalEffectPolicyRisk,
}

#[cfg_attr(not(test), allow(dead_code))]
impl ExternalEffectGateInput {
    fn gate_input(
        &self,
        agent_definition_ceiling: Option<PolicyApprovalCeiling>,
        consent: Option<ConsentGateContext>,
    ) -> GateEvaluatorInput {
        GateEvaluatorInput {
            actor: self.actor.clone(),
            source: None,
            content_kind: GateContentKind::ExternalEffect,
            sensitivity_band: None,
            criticality: PolicyCriticality::Normal,
            policy_manifest_version: POLICY_SCHEMA_VERSION.to_owned(),
            provenance: self.provenance.clone(),
            agent_definition_ceiling,
            consent,
            external_effect: Some(ExternalEffectGateContext {
                verb: self.verb.clone(),
                channel: self.channel.clone(),
                channel_identity_ref: self.channel_identity_ref,
                counterparty: self.counterparty.clone(),
                brief_ref: self.brief_ref.clone(),
                send_ref: self.send_ref.clone(),
                standing_grant_ref: self.standing_grant_ref.clone(),
                scoped_mcp_call: self.scoped_mcp_call.clone(),
                scoped_mcp_grant_authorized: false,
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
    EffectorBudget,
    CharterPolicy,
    /// DEC-0006 consent ladder: catastrophe floor, irreversible effect, bound
    /// exceeded, and write-classification failure all meter here.
    Consent,
    /// CA-06 campaign compliance: a seeded legal rule row refused the dispatch.
    CampaignCompliance,
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
            Self::EffectorBudget => "effector_budget",
            Self::CharterPolicy => "charter_policy",
            Self::Consent => "consent",
            Self::CampaignCompliance => "campaign_compliance",
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
            Self::EffectorBudget => 11,
            Self::CharterPolicy => 12,
            Self::Consent => 13,
            Self::CampaignCompliance => 14,
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
            Self::EffectorBudget,
            Self::CharterPolicy,
            Self::Consent,
            Self::CampaignCompliance,
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
    PendingConnectorKeyUnregistered,
    DenyCounterpartyOptOut,
    DenyEffectorBudgetExhausted,
    DenyConnectorKeySuspended,
    DenyCharterNeverList,
    PendingCharterDrift,
    /// DEC-0006 invariant 1: the operation is irreversible in effect and no
    /// approve-once receipt or covering standing grant authorizes it.
    PendingConsentIrreversibleEffect,
    /// DEC-0006 invariant 3: a standing grant exists but the candidate exceeds
    /// its bound. Widening is its own owner decision, never a side effect of
    /// reuse — so this is a fresh ask, not a silent auto.
    PendingConsentBoundExceeded,
    /// DEC-0006 invariant 7: the operation matched the closed catastrophe
    /// floor. Gated at ANY trust level, non-rememberable.
    PendingConsentCatastropheFloor,
    /// DEC-0006 invariant 8: the engine-owned write facts were malformed or
    /// absent, so no reversibility verdict could be produced. Writes fail safe
    /// by asking.
    PendingConsentWriteClassificationFailed,
    /// CA-06 (ONE-1777): a seeded campaign-compliance row refused this
    /// dispatch. Enforcement, not an ask — an owner approval must not be able
    /// to unlock a send the governing legal row forbids, so this is a deny.
    DenyCampaignCompliance,
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
            Self::PendingConnectorKeyUnregistered => "gate.pending.connector_key_unregistered",
            Self::DenyCounterpartyOptOut => "gate.deny.counterparty_opt_out",
            Self::DenyEffectorBudgetExhausted => "gate.deny.effector_budget_exhausted",
            Self::DenyConnectorKeySuspended => "gate.deny.connector_key_suspended",
            Self::DenyCharterNeverList => "gate.deny.charter_never_list",
            Self::PendingCharterDrift => "gate.pending.charter_drift",
            Self::PendingConsentIrreversibleEffect => "gate.pending.consent.irreversible_effect",
            Self::PendingConsentBoundExceeded => "gate.pending.consent.bound_exceeded",
            Self::PendingConsentCatastropheFloor => "gate.pending.consent.catastrophe_floor",
            Self::PendingConsentWriteClassificationFailed => {
                "gate.pending.consent.write_classification_failed"
            }
            Self::DenyCampaignCompliance => "gate.deny.campaign_compliance",
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
            Self::PendingExternalEffectAuthority | Self::PendingConnectorKeyUnregistered => {
                GateMetricReasonClass::ExternalEffectAuthority
            }
            Self::DenyCounterpartyOptOut => GateMetricReasonClass::CounterpartyOptOut,
            Self::DenyEffectorBudgetExhausted | Self::DenyConnectorKeySuspended => {
                GateMetricReasonClass::EffectorBudget
            }
            Self::DenyCharterNeverList | Self::PendingCharterDrift => {
                GateMetricReasonClass::CharterPolicy
            }
            Self::PendingConsentIrreversibleEffect
            | Self::PendingConsentBoundExceeded
            | Self::PendingConsentCatastropheFloor
            | Self::PendingConsentWriteClassificationFailed => GateMetricReasonClass::Consent,
            Self::DenyCampaignCompliance => GateMetricReasonClass::CampaignCompliance,
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
    #[cfg(test)]
    GATE_METRIC_EMISSIONS.with(|count| count.set(count.get().saturating_add(1)));
    let outcome = decision.outcome();
    // A decision with multiple reason codes records one outcome/reason-class co-occurrence per code.
    for reason_code in decision.reason_codes() {
        let reason_class = reason_code.metric_reason_class();
        GATE_METRIC_COUNTERS[outcome.metric_index()][reason_class.metric_index()]
            .fetch_add(1, AtomicOrdering::Relaxed);
    }
}

#[cfg(test)]
thread_local! {
    static GATE_METRIC_EMISSIONS: Cell<u64> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn gate_metric_emission_count_for_test() -> u64 {
    GATE_METRIC_EMISSIONS.with(Cell::get)
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
    delegation_fold: DelegationFoldCache,
    source_trust: SourceTrustCeiling,
    scoped_grants: Vec<PolicyScopedGrant>,
    legal_floor_rows: Vec<PolicyLegalFloorRow>,
    owner_policy_rows: Vec<PolicyOwnerPolicyRow>,
    owner_policy_rows_dropped: bool,
    signatures: Vec<PolicySignature>,
    on_budget_exhausted: Option<BudgetExhaustionPolicy>,
    budget_policy: BudgetPolicyTable,
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

    /// The resolved `budget_policy` rows, fail-closed: a loaded manifest that
    /// forces fail-closed (malformed, unsupported schema, engine-version
    /// floor, unknown axis, row-count overflow) exposes no usable table, and
    /// the caller must refuse rather than substitute an empty table. An
    /// absent manifest keeps the bootstrap posture and exposes the empty
    /// table, which is exactly the single-pool meter.
    #[must_use]
    pub(crate) fn budget_policy(&self) -> Option<&BudgetPolicyTable> {
        if self.diagnostics.loaded_manifest_forces_fail_closed() {
            None
        } else {
            Some(&self.budget_policy)
        }
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
        // A payload-aware scoped MCP grant is the one external-effect path
        // that dissolves the Proposed fork: store-backed matching already
        // proved server, tool, endpoint, and data-class scope. Blind grants
        // and every non-effect write retain the authored clamp below.
        if matches!(
            input.agent_definition_ceiling,
            Some(PolicyApprovalCeiling::Proposed)
        ) {
            return input.content_kind == GateContentKind::ExternalEffect
                && input.external_effect.as_ref().is_some_and(|effect| {
                    effect.scoped_mcp_call.is_some() && effect.scoped_mcp_grant_authorized
                });
        }
        let actor_class = input.actor.actor_class.trim();
        if self.actor_ceiling(actor_class, input.actor.actor_ref.as_deref())
            == PolicyApprovalCeiling::Auto
        {
            return true;
        }

        // The edge-provenance no-matching-row auto exception is suppressed
        // for ANY definition-bound actor (B2 resolution 2026-07-10): an Auto
        // definition ceiling means "does not self-limit", not "inherits the
        // no-row exception" — no row → Proposed holds as written for
        // definition-bound actors.
        input.content_kind == GateContentKind::EdgeProvenanceClaim
            && matches!(actor_class, "agent" | "system")
            && !self.has_matching_actor_ceiling(actor_class, input.actor.actor_ref.as_deref())
            && input.agent_definition_ceiling.is_none()
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
    pub(crate) fn owner_policy_rows_dropped(&self) -> bool {
        self.owner_policy_rows_dropped
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
        let mut actor_ceiling_allows_auto = self.actor_ceiling_allows_auto_for_content(input);
        if let Some(grant_ref) = input.actor.delegation_grant_ref.as_deref() {
            let bound = self
                .delegation_fold
                .records
                .get(grant_ref)
                .and_then(|r| match r {
                    DelegationGrantRecord::Grant {
                        actor_class,
                        actor_ref,
                        ..
                    } => Some((actor_class, actor_ref)),
                    _ => None,
                });
            let matches = bound.is_some_and(|(class, reference)| {
                class.trim() == actor_class
                    && reference.as_deref() == input.actor.actor_ref.as_deref()
            });
            actor_ceiling_allows_auto = actor_ceiling_allows_auto
                && matches
                && self.delegation_fold.effective_ceiling(grant_ref)
                    == Some(PolicyApprovalCeiling::Auto);
        }
        if !actor_ceiling_allows_auto {
            pending.push(GateReasonCode::PendingActorCeiling);
        }

        /* actor ceiling is already restrictive; delegated authority can only narrow it. */
        if actor_ceiling_allows_auto
            && self.dreamer_auto_grant_requires_manifest_signature(input)
            && self.signatures.is_empty()
        {
            pending.push(GateReasonCode::PendingPolicyManifestAuthority);
        }

        if !self.source_trust_allows_auto(input.source, input.sensitivity_band) {
            pending.push(GateReasonCode::PendingSourceTrust);
        }

        // DEC-0006 write-side residual: `Critical` is a composed-effect SIGNAL,
        // not an unconditional gate. It contributes to the consent ladder
        // below (via `ConsentGateContext`), and the closed catastrophe set is
        // the only always-gate (invariant 7). The legacy unconditional floor
        // survives only where no consent context was composed, so a caller
        // that has not yet been moved onto the DEC-0006 path keeps its
        // pre-existing behaviour rather than silently losing a gate.
        if input.criticality == PolicyCriticality::Critical && input.consent.is_none() {
            pending.push(GateReasonCode::PendingCriticalityFloor);
        }

        pending.extend(consent_ladder_reasons(input.consent.as_ref()));

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
        if effect.verb.trim().is_empty() || effect.channel.trim().is_empty() {
            return false;
        }
        // Payload-aware scoped grants are the only safe MCP auto path. The
        // boolean is set only by the store-backed four-axis match below; a
        // caller-supplied standing-grant reference has no authority here.
        if effect.scoped_mcp_call.is_some() || is_mcp_effect_channel(&effect.channel) {
            return effect.scoped_mcp_grant_authorized;
        }
        if !effect.has_permission {
            return false;
        }

        // Blind/non-scoped grants keep the Proposed-ceiling restriction. A
        // scoped MCP grant reaches the return above only after all axes pass.
        if matches!(
            input.agent_definition_ceiling,
            Some(PolicyApprovalCeiling::Proposed)
        ) {
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
        let Some(id) = type_index_entity_id(&key, ENTITY_TYPE_ACCESS_GRANT) else {
            return Err(Error::CorruptedIndex("access grant type index key"));
        };
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            return Err(Error::CorruptedIndex("access grant entity row"));
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
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
    // The raw resolved table, never the fail-closed accessor: a malformed
    // manifest contributes no decoded rows at all and its malformed-ness is
    // already frontier-relevant through `hash_diagnostics`.
    hash_budget_policy_table(hasher, &resolution.budget_policy);

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

    hash_len(hasher, resolution.delegation_fold.records.len());
    for (key, record) in &resolution.delegation_fold.records {
        hash_str(hasher, key);
        match record {
            DelegationGrantRecord::Grant {
                actor_class,
                actor_ref,
                parent_grant_ref,
                ceiling,
                ..
            } => {
                hash_str(hasher, "grant");
                hash_str(hasher, actor_class);
                hash_opt_str(hasher, actor_ref.as_deref());
                hash_opt_str(hasher, parent_grant_ref.as_deref());
                hash_approval_ceiling(hasher, *ceiling);
            }
            DelegationGrantRecord::RevokeGrant { .. } => hash_str(hasher, "revoke_grant"),
        }
    }
    hash_len(hasher, resolution.delegation_fold.revoked.len());
    for grant_ref in &resolution.delegation_fold.revoked {
        hash_str(hasher, grant_ref);
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

/// Row order is hashed because row order defines `row_index`; an absent table
/// and an explicit empty table hash identically (both are zero rows).
fn hash_budget_policy_table(hasher: &mut Sha256, table: &BudgetPolicyTable) {
    hash_len(hasher, table.rows().len());
    for row in table.rows() {
        match row.selector() {
            BudgetPolicySelector::Purpose(purpose) => {
                hash_str(hasher, "purpose");
                hash_str(hasher, BudgetPolicySelector::purpose_manifest_name(purpose));
            }
            BudgetPolicySelector::Actor(actor) => {
                hash_str(hasher, "actor");
                hash_bytes(hasher, actor.as_bytes());
            }
        }
        hash_bool(hasher, row.floor_units().is_some());
        if let Some(floor_units) = row.floor_units() {
            hash_u64(hasher, floor_units);
        }
        hash_bool(hasher, row.cap_units().is_some());
        if let Some(cap_units) = row.cap_units() {
            hash_u64(hasher, cap_units);
        }
    }
}

struct DecodedPolicyManifest {
    pack: PolicyPack,
    actor_ceilings: Vec<ActorCeiling>,
    delegated_grants: Vec<DelegationGrantRecord>,
    source_trust: SourceTrustCeiling,
    scoped_grants: Vec<PolicyScopedGrant>,
    legal_floor_rows: Vec<PolicyLegalFloorRow>,
    owner_policy_rows: Vec<PolicyOwnerPolicyRow>,
    owner_policy_rows_dropped: bool,
    signatures: Vec<PolicySignature>,
    on_budget_exhausted: Option<BudgetExhaustionPolicy>,
    budget_policy: BudgetPolicyTable,
    unsupported_schema: bool,
    engine_version_floor: bool,
    unknown_axis_seen: bool,
}

pub(crate) fn first_party_eiri_connector_actor_ref() -> String {
    bytes_to_hex_lower(&FIRST_PARTY_EIRI_CONNECTOR_ACTOR_ID)
}

/// Resolves the AGENT_DEF-authored ceiling bound for a write actor, live at
/// evaluation time (D11: authority is never read from dispatch snapshots).
///
/// * non-`Agent` actor class → `None` (no definition bound);
/// * entity ABSENT → `Some(Proposed)` — deletion fails closed (B3 resolution
///   2026-07-10: a deleted Herald fork's definition can no longer drop its
///   Proposed self-limit);
/// * present but not type-17 → `None` (live person-backed agent actors keep
///   today's semantics);
/// * decoded definition → its ceiling restricted by the fork parent ROW's
///   stored ceiling, fail-closed (an unresolvable parent row clamps to
///   Proposed);
/// * unreadable/undecodable body → `Some(Proposed)` with a `tracing::warn!`
///   naming the actor entity id — the fail-closed re-clamp of a believed-Auto
///   agent must not be silent.
pub(crate) fn agent_definition_ceiling_for_actor(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor: WriteActor,
) -> Option<PolicyApprovalCeiling> {
    if actor.actor_class() != EdgeActorClass::Agent {
        return None;
    }
    match agent_bearing_for_entity(store, txn, actor.entity_ref()) {
        AgentBearing::Bound(ceiling) => Some(ceiling),
        // B3: a deleted definition can no longer drop its self-limit.
        AgentBearing::Absent => Some(PolicyApprovalCeiling::Proposed),
        // Live person-backed agent actors keep today's semantics.
        AgentBearing::NonAgent => None,
    }
}

/// How a governing entity id relates to the AGENT_DEF authority lattice.
/// Derived from the STORED ENTITY, never from a caller-asserted actor class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentBearing {
    /// The id holds a stored type-17 AGENT_DEF (or a fail-closed variant of
    /// one): it carries a definition ceiling.
    Bound(PolicyApprovalCeiling),
    /// No entity is stored at the id.
    Absent,
    /// An entity is stored, but it is not agent-bearing (non-type-17).
    NonAgent,
}

/// Classifies a governing entity id from stored state — READ-ONLY, and from
/// the ROW alone: no compiled table confers authority on any id, so a pinned
/// system-agent actor id classifies exactly like any other id (no row →
/// `Absent`, which both consumers map to `Proposed`). Read failures resolve
/// fail-closed to `Bound(Proposed)`.
fn agent_bearing_for_entity(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    entity_ref: EntityId,
) -> AgentBearing {
    let raw = match store.entities.get(txn, entity_ref.as_bytes()) {
        Ok(Some(raw)) => raw,
        Ok(None) => return AgentBearing::Absent,
        Err(error) => {
            tracing::warn!(
                actor_entity_id = %entity_ref.to_hex(),
                %error,
                "agent definition ceiling read failed; failing closed to proposed",
            );
            return AgentBearing::Bound(PolicyApprovalCeiling::Proposed);
        }
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        tracing::warn!(
            actor_entity_id = %entity_ref.to_hex(),
            "agent definition entity header failed to parse; failing closed to proposed",
        );
        return AgentBearing::Bound(PolicyApprovalCeiling::Proposed);
    };
    if header.entity_type != ENTITY_TYPE_AGENT_DEF {
        return AgentBearing::NonAgent;
    }
    match decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..]) {
        Ok(def) => {
            let mut ceiling = PolicyApprovalCeiling::from_agent_ceiling(def.ceiling);
            if let Some(parent_ref) = &def.forked_from {
                let parent_id = crate::agent_def::forked_from_row_ref(parent_ref);
                // GATE-HALF: the clamp reads the PARENT ROW's stored ceiling,
                // never a compiled table. Absent/undecodable/non-AGENT_DEF
                // parent fails closed.
                ceiling = ceiling.restrict(parent_row_ceiling(store, txn, &parent_id));
            }
            AgentBearing::Bound(ceiling)
        }
        Err(error) => {
            tracing::warn!(
                actor_entity_id = %entity_ref.to_hex(),
                %error,
                "agent definition body failed to decode; failing closed to proposed",
            );
            AgentBearing::Bound(PolicyApprovalCeiling::Proposed)
        }
    }
}

/// The no-widen bound a forked definition inherits: the stored `ceiling` of
/// the PARENT's own AGENT_DEF row (GATE-HALF — data over rows, never a
/// compiled preset table). Every arm that cannot READ a parent ceiling —
/// unreadable store, missing row, unparsable header, non-type-17, undecodable
/// body — warns and clamps to `Proposed`, so an unresolvable lineage can never
/// leave a fork wider than its parent.
fn parent_row_ceiling(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    parent_id: &EntityId,
) -> PolicyApprovalCeiling {
    let raw = match store.entities.get(txn, parent_id.as_bytes()) {
        Ok(Some(raw)) => raw,
        Ok(None) => {
            tracing::warn!(
                parent_entity_id = %parent_id.to_hex(),
                "fork parent definition row is absent; failing closed to proposed",
            );
            return PolicyApprovalCeiling::Proposed;
        }
        Err(error) => {
            tracing::warn!(
                parent_entity_id = %parent_id.to_hex(),
                %error,
                "fork parent definition read failed; failing closed to proposed",
            );
            return PolicyApprovalCeiling::Proposed;
        }
    };
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
        tracing::warn!(
            parent_entity_id = %parent_id.to_hex(),
            "fork parent entity header failed to parse; failing closed to proposed",
        );
        return PolicyApprovalCeiling::Proposed;
    };
    if header.entity_type != ENTITY_TYPE_AGENT_DEF {
        tracing::warn!(
            parent_entity_id = %parent_id.to_hex(),
            entity_type = header.entity_type,
            "fork parent entity is not an agent definition; failing closed to proposed",
        );
        return PolicyApprovalCeiling::Proposed;
    }
    match decode_agent_definition(&raw[ENTITY_METADATA_HEADER_LEN..]) {
        Ok(parent) => PolicyApprovalCeiling::from_agent_ceiling(parent.ceiling),
        Err(error) => {
            tracing::warn!(
                parent_entity_id = %parent_id.to_hex(),
                %error,
                "fork parent definition body failed to decode; failing closed to proposed",
            );
            PolicyApprovalCeiling::Proposed
        }
    }
}

/// The actor classes the gate recognizes as NON-agent effect principals.
/// Anything outside this set (and outside `"agent"`) is an unrecognized
/// assertion and resolves fail-closed.
const NON_AGENT_EFFECT_ACTOR_CLASSES: [&str; 3] = ["human", "system", "first_party"];

/// Resolves the definition ceiling for an EXTERNAL-EFFECT actor.
///
/// Effect inputs are the one gate door whose actor identity is fully
/// caller-asserted — `actor_class` (a free string), `actor_ref` (what the
/// manifest rows and scoped grants key on) and `provenance.actor_entity_ref`
/// (the audited identity) are three independent fields. Three hardenings:
///
/// * IDENTITY BINDING (F1/F2): `actor_ref` and `actor_entity_ref` must name
///   ONE governing identity before any authority is derived — otherwise a
///   Proposed-ceiling agent could pair its own provenance with an Auto
///   identity's ref. Mismatched or unparsable pairs fail closed to Proposed.
/// * ENTITY-TYPE-WINS (class-spoof): the ceiling is derived from what the
///   governing entity IS, not from the class the caller asserts. A stored
///   AGENT_DEF is clamped under ANY class string.
/// * CLASS FAIL-CLOSED (class-spoof): a class that is neither `"agent"` nor a
///   recognized non-agent principal — unknown, empty, or absent — resolves to
///   Proposed rather than skipping the clamp. Comparison is case-normalized,
///   so `"Agent"`/`"AGENT"` cannot dodge the agent path.
///
/// (The claim and edge-provenance doors derive both identity fields from a
/// single `WriteActor`/record and validate the class against the actor
/// entity's kind, so they are bound by construction.)
fn agent_definition_ceiling_for_effect_actor(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    actor_class: &str,
    actor_ref: Option<&str>,
    actor_entity_ref: Option<EntityId>,
) -> Option<PolicyApprovalCeiling> {
    let normalized_class = actor_class.trim().to_ascii_lowercase();
    let recognized_non_agent = NON_AGENT_EFFECT_ACTOR_CLASSES.contains(&normalized_class.as_str());
    let asserts_agent = normalized_class == "agent";

    // Without an audited identity the gate denies the effect outright
    // (DenyMissingActorProvenance). Resolve fail-closed anyway unless the
    // caller asserts a recognized non-agent principal, so no path derives
    // authority from an unaudited ref.
    let Some(governing) = actor_entity_ref else {
        return if recognized_non_agent {
            None
        } else {
            Some(PolicyApprovalCeiling::Proposed)
        };
    };
    if let Some(actor_ref) = actor_ref {
        match EntityId::from_hex(actor_ref) {
            // An entity-shaped ref MUST name the audited identity, whatever
            // class is asserted: the manifest keys Auto on `actor_ref` while
            // the clamp keys on the audited entity, so an unbound pair lets a
            // Proposed agent borrow an Auto identity's grant.
            Ok(ref_id) if ref_id != governing => {
                tracing::warn!(
                    actor_ref,
                    actor_entity_ref = %governing.to_hex(),
                    "effect actor_ref does not match actor_entity_ref; \
                     failing closed to proposed",
                );
                return Some(PolicyApprovalCeiling::Proposed);
            }
            Ok(_) => {}
            // An opaque principal name. Only recognized non-agent principals
            // key manifest rows by name; an agent's actor_ref is always the
            // hex entity id, so a non-hex ref under an agent (or unrecognized)
            // class is an unbindable assertion.
            Err(_) if !recognized_non_agent => {
                tracing::warn!(
                    actor_ref,
                    actor_entity_ref = %governing.to_hex(),
                    "effect actor_ref is not an entity id under a non-principal class; \
                     failing closed to proposed",
                );
                return Some(PolicyApprovalCeiling::Proposed);
            }
            Err(_) => {}
        }
    }

    match agent_bearing_for_entity(store, txn, governing) {
        // Entity-type-wins: an agent-bearing identity is clamped regardless of
        // the class the caller asserted.
        AgentBearing::Bound(ceiling) => Some(ceiling),
        AgentBearing::Absent => {
            if recognized_non_agent {
                // A connector/human/system principal whose entity is not
                // stored keeps today's semantics.
                None
            } else {
                // B3 for asserted agents; fail-closed for unrecognized classes.
                Some(PolicyApprovalCeiling::Proposed)
            }
        }
        AgentBearing::NonAgent => {
            if asserts_agent || recognized_non_agent {
                None
            } else {
                tracing::warn!(
                    actor_class,
                    actor_entity_ref = %governing.to_hex(),
                    "effect actor asserts an unrecognized class; \
                     failing closed to proposed",
                );
                Some(PolicyApprovalCeiling::Proposed)
            }
        }
    }
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
                    (Value::from(RULE_PREFIX_KEY), Value::from("calendar.")),
                    (
                        Value::from(RULE_AXES_KEY),
                        Value::Map(vec![
                            (Value::from(AXIS_CRITICALITY_KEY), Value::from("normal")),
                            (Value::from(AXIS_SENSITIVITY_KEY), Value::from("normal")),
                        ]),
                    ),
                ]),
                Value::Map(vec![
                    (Value::from(RULE_PREFIX_KEY), Value::from("booking.")),
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
                        Value::from(crate::skill_hub::PREDICATE_SKILL_SCAN_VERDICT),
                    ),
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
                        Value::from(crate::skill_hub::PREDICATE_SKILL_HUB_PROVENANCE),
                    ),
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
                        Value::from(crate::skill_hub::PREDICATE_SKILL_HUB_UPDATE_PROPOSAL),
                    ),
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
                        Value::from(crate::provider_confidence::PREDICATE_ACTOR_CONFIDENCE_PRIOR),
                    ),
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
                        Value::from(crate::provider_confidence::PREDICATE_PROVIDER_ENRICHMENT),
                    ),
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
    let mut delegated_rows: Vec<DelegationGrantRecord> = Vec::new();

    for index_entry in store
        .type_index
        .prefix_iter(txn, &[ENTITY_TYPE_POLICY_MANIFEST])?
    {
        let (key, _) = index_entry?;
        let Some(id) = type_index_entity_id(&key, ENTITY_TYPE_POLICY_MANIFEST) else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            resolution.diagnostics.malformed_manifest_seen = true;
            continue;
        };
        let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
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
                delegated_rows.extend(decoded.delegated_grants);
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
                // Deterministic resolved order: type-index manifest scan
                // order, then row order inside each manifest. Row indices in
                // ladder events index this concatenation.
                resolution.budget_policy.extend_rows(decoded.budget_policy);
                resolution.packs.push(decoded.pack);
            }
            None => {
                resolution.diagnostics.malformed_manifest_seen = true;
            }
        }
    }

    // A resolved table must stay addressable by a u16 row index: up to 65,536
    // rows (indices 0..=65535) are valid; the 65,537th row marks the whole
    // resolution malformed, fail-closing the write gate exactly like any
    // malformed manifest and refusing the budget-policy accessor. Never wrap
    // or silently truncate a row index.
    if resolution.budget_policy.rows().len() > usize::from(u16::MAX) + 1 {
        resolution.diagnostics.malformed_manifest_seen = true;
    }

    match fold_delegated_grants(&delegated_rows) {
        Some(fold) => resolution.delegation_fold = fold,
        None => {
            resolution.diagnostics.malformed_manifest_seen = true;
            resolution.delegation_fold = DelegationFoldCache::default();
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
    let mut recorded_decision = None;
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        ClaimGateWrite {
            body,
            envelope,
            defer_metrics_until_commit: false,
        },
        policy,
        mode,
        &mut recorded_decision,
        None,
    )
}

pub(crate) fn check_claim_policy_for_write_with_preflight_decision(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
    envelope: Option<&WriteEnvelope>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    preflight_decision_id: Option<GateDecisionId>,
) -> Result<()> {
    let mut recorded_decision = None;
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        ClaimGateWrite {
            body,
            envelope,
            defer_metrics_until_commit: false,
        },
        policy,
        mode,
        &mut recorded_decision,
        preflight_decision_id,
    )
}

pub(crate) fn check_claim_policy_for_write_with_record(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
) -> Result<()> {
    check_claim_policy_for_write_with_record_inner(
        store,
        wtxn,
        id,
        write,
        policy,
        mode,
        recorded_decision,
        None,
    )
}

fn check_claim_policy_for_write_with_record_inner(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    write: ClaimGateWrite<'_>,
    policy: &PolicyManifestResolution,
    mode: GateWriteMode,
    recorded_decision: &mut Option<RecordedClaimGateDecision>,
    preflight_decision_id: Option<GateDecisionId>,
) -> Result<()> {
    let ClaimGateWrite {
        body,
        envelope,
        defer_metrics_until_commit,
    } = write;
    *recorded_decision = None;
    if let Some(envelope) = envelope {
        validate_write_envelope(envelope)?;
    }

    if policy.enforces_write_gate() {
        let (actor, provenance, agent_definition_ceiling) = if let Some(envelope) = envelope {
            let actor = envelope.actor();
            let dreamer_run_id = dreamer_run_id_from_write_envelope(envelope);
            let agent_definition_ceiling = agent_definition_ceiling_for_actor(store, &*wtxn, actor);
            (
                GateActor {
                    actor_class: edge_actor_class_str(actor.actor_class()).to_owned(),
                    actor_ref: Some(actor.entity_ref().to_hex()),
                    delegation_grant_ref: None,
                },
                GateProvenanceHandles {
                    actor_entity_ref: Some(actor.entity_ref()),
                    dreamer_run_id,
                    ..GateProvenanceHandles::default()
                },
                agent_definition_ceiling,
            )
        } else {
            (
                GateActor {
                    actor_class: LOCAL_WRITE_ACTOR_CLASS.to_owned(),
                    actor_ref: None,
                    delegation_grant_ref: None,
                },
                GateProvenanceHandles {
                    actor_entity_ref: Some(local_write_actor_entity_ref()),
                    ..GateProvenanceHandles::default()
                },
                None,
            )
        };
        let input = claim_gate_input(
            body,
            policy,
            actor,
            GateContentKind::Claim,
            provenance,
            mode.include_source_in_gate_input,
            agent_definition_ceiling,
            // Claim bodies carry no effect-fact axes the consent evaluator
            // could classify honestly; this door keeps its pre-DEC-0006
            // criticality behaviour (the `None` arm of `evaluate_gate`)
            // rather than guess at defaults that would silently auto-run.
            None,
        );
        let mut decision = policy.evaluate_gate(&input);
        let attach_critical_confirm = body.approval == ClaimApprovalStatus::Auto
            && critical_claim_can_land_auto_with_confirm(
                &input,
                decision.reason_codes(),
                &body.predicate,
            );
        if attach_critical_confirm {
            decision = GateDecision::allow()
                .with_receipt_reasons([GATE_REASON_ALLOW_CRITICAL_CONFIRM_ATTACHED]);
        }
        let binding = GateConsentBinding::for_claim(body, policy)?;
        let decision_id = GateDecisionId::now();
        let created_at = crate::unix_seconds_now();
        let mut decision_record = GateDecisionRecord {
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
            system_notices: Vec::new(),
            actor_class: input.actor.actor_class.clone(),
            actor_ref: input.actor.actor_ref.clone(),
            content_kind: input.content_kind.as_str().to_owned(),
            policy_manifest_version: input.policy_manifest_version,
            claim_id: Some(*id.as_bytes()),
            grant_ref: None,
            diff_handle: binding.diff_handle.clone(),
            read_frontier_hash: binding.read_frontier_hash,
            redacted_at: None,
        };

        if mode.record_decision {
            if attach_critical_confirm {
                store.append_fresh_gate_decision_in_txn(wtxn, &mut decision_record)?;
            } else {
                store.append_gate_decision_in_txn(wtxn, &decision_record)?;
            }
            let recorded = RecordedClaimGateDecision {
                record: decision_record.clone(),
                decision: decision.clone(),
            };
            if !defer_metrics_until_commit {
                recorded.record_metrics();
            }
            *recorded_decision = Some(recorded);
        }

        if mode.persist_pending_consent
            && ((decision.outcome() == GateOutcome::Pending
                && body.approval == ClaimApprovalStatus::Proposed)
                || (attach_critical_confirm && body.approval == ClaimApprovalStatus::Auto))
        {
            let pending_decision = if mode.record_decision {
                decision_record.clone()
            } else if let Some(decision_id) = preflight_decision_id {
                let record = store.gate_decision_in_txn(&*wtxn, decision_id)?.ok_or(
                    Error::InvariantViolation(
                        "preflight gate decision missing during pending bind",
                    ),
                )?;
                if !gate_decision_matches_pending_candidate(&record, &decision_record) {
                    return Err(Error::InvariantViolation(
                        "preflight gate decision does not match pending candidate",
                    ));
                }
                record
            } else {
                // Caller-owned transactions have no same-transaction preflight
                // identity, so they always mint a new attachment receipt.
                store.append_fresh_gate_decision_in_txn(wtxn, &mut decision_record)?;
                record_gate_decision_metrics(&decision);
                decision_record.clone()
            };
            let pending = PendingGateConsentRecord {
                version: 0,
                claim_id: *id.as_bytes(),
                decision_id: pending_decision.decision_id,
                created_at: pending_decision.created_at,
                diff_handle: pending_decision.diff_handle,
                read_frontier_hash: pending_decision.read_frontier_hash,
                reason_codes: if attach_critical_confirm {
                    vec![GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED.to_owned()]
                } else {
                    pending_decision.reason_codes
                },
                dreamer_run_id: pending_consent_dreamer_run_id(envelope, body),
            };
            store.put_pending_gate_consent_in_txn(wtxn, &pending)?;
            // This is the sole reopening transition: a successful local
            // critical-confirm attachment replaces the invalidated ceremony in
            // this transaction. Pending ordinary work and replicated input do
            // not clear the claim-scoped marker.
            if attach_critical_confirm {
                store.delete_critical_confirm_invalidation_in_txn(wtxn, id)?;
            }
        }

        enforce_claim_gate_decision_with_consent(
            store,
            wtxn,
            id,
            &decision,
            body.approval,
            &binding,
            GateWriteMode {
                resolve_pending: mode.resolve_pending && !attach_critical_confirm,
                ..mode
            },
        )?;
    }

    check_claim_source_trust(body, policy)
}

/// A private, single-use authority for a settlement status rewrite.
///
/// Its fields are deliberately not caller supplied at the materialization door:
/// only the verified timeout/sweep and authority-fold paths below can construct it.
#[derive(Clone, Copy)]
enum PreauthorizedClaimStatusGrant {
    TimeoutDemotion,
    FoldDecline,
}

#[cfg(test)]
impl PreauthorizedClaimStatusGrant {
    // Test-only access verifies the materialization door's row/header binding.
    fn test_timeout_demotion() -> Self {
        Self::TimeoutDemotion
    }
}

fn put_preauthorized_claim_status_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    expected: &ClaimBody,
    grant: PreauthorizedClaimStatusGrant,
    occurred: TimeRange,
    learned_at: u64,
) -> Result<()> {
    let current = vault
        .get_claim_in_txn(&*wtxn, id)?
        .ok_or(Error::EntityNotFound)?;
    let raw = vault
        .store
        .entities
        .get(&*wtxn, id.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
    if header.entity_type != ENTITY_TYPE_CLAIM
        || header.occurred_start != occurred.start
        || header.occurred_end != occurred.end
        || header.learned_at != learned_at
        || current != *expected
    {
        return Err(Error::InvariantViolation(
            "preauthorized claim status update does not bind current claim row",
        ));
    }
    let mut updated = current.clone();
    match grant {
        PreauthorizedClaimStatusGrant::TimeoutDemotion => {
            updated.approval = ClaimApprovalStatus::Proposed;
        }
        PreauthorizedClaimStatusGrant::FoldDecline => {
            updated.lifecycle = ClaimLifecycleStatus::Retracted;
        }
    }
    let data = encode_claim_body(&updated)?;
    crate::claim::validate_claim_body_bytes(&data, false)?;
    apply_session_bundle_claim_puts(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        wtxn,
        vec![BatchOp::Put {
            id: *id,
            entity_type: ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }],
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
    )
}

impl Vault {
    /// Lists live confirmations in deterministic order within one bounded page.
    /// Calls advance a bounded sweep cursor; this is not a global ordering guarantee.
    /// One expiry pass and one listing pass inspect at most
    /// `CRITICAL_CONFIRM_LIST_CALL_ROW_BUDGET` logical pending records combined.
    /// Each logical record separately touches its sequence-index row and primary row.
    pub fn pending_critical_write_confirms(
        &self,
        limit: usize,
    ) -> Result<Vec<CriticalWriteConfirmBinding>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now = crate::unix_seconds_now();
        debug_assert!(
            CRITICAL_CONFIRM_LIST_CALL_ROW_BUDGET <= 512,
            "a public list call may inspect no more than 512 logical pending records",
        );
        self.expire_critical_write_confirms()?;
        self.with_write_txn(|wtxn| {
            let (cursor, prior_fence) = self
                .store
                .critical_confirm_list_sweep_state_in_txn(&*wtxn)?;
            let fence = match prior_fence {
                Some(fence) => Some(fence),
                None => self.store.pending_gate_consents_high_water_in_txn(&*wtxn)?,
            };
            let page = self.store.pending_gate_consents_page_in_txn(
                &*wtxn,
                cursor,
                fence,
                CRITICAL_CONFIRM_SWEEP_PAGE_LIMIT,
            )?;
            let mut bindings = Vec::with_capacity(limit.min(page.len()));
            let mut last_inspected = None;
            for (sequence, pending) in page {
                last_inspected = Some(sequence);
                if let Ok(binding) = critical_write_confirm_binding(&pending) {
                    if binding.expires_at > now {
                        // Preserve the established public ordering for each
                        // bounded result page; sequence only controls sweep progress.
                        bindings.push((
                            pending.created_at,
                            pending.decision_id,
                            pending.claim_id,
                            binding,
                        ));
                        if bindings.len() == limit {
                            break;
                        }
                    }
                }
            }
            bindings.sort_by(|left, right| {
                left.0
                    .cmp(&right.0)
                    .then_with(|| left.1.as_bytes().cmp(&right.1.as_bytes()))
                    .then_with(|| left.2.cmp(&right.2))
            });
            let bindings = bindings
                .into_iter()
                .map(|(_, _, _, binding)| binding)
                .collect();
            let complete = last_inspected.is_none() || last_inspected == fence;
            self.store.put_critical_confirm_list_sweep_state_in_txn(
                wtxn,
                if complete { None } else { last_inspected },
                if complete { None } else { fence },
            )?;
            Ok(bindings)
        })
    }

    pub fn settle_critical_write_confirm(
        &self,
        confirm_id: [u8; 32],
    ) -> Result<CriticalWriteConfirmResolution> {
        let now = crate::unix_seconds_now();
        let outcome = self.with_write_txn(|wtxn| {
            let fold = self.authority_fold_readonly_in_txn(&*wtxn)?;
            // Confirm IDs have a dedicated exact index; unrelated calls cannot
            // influence absence detection or turn a live target into terminal state.
            let Some(claim_id) = self
                .store
                .critical_confirm_claim_id_in_txn(&*wtxn, &confirm_id)?
            else {
                return Ok(Ok(CriticalWriteConfirmResolution::AlreadySettled));
            };
            let Some(pending) = self.store.pending_gate_consent_in_txn(&*wtxn, &claim_id)? else {
                // A stale sidecar is removed transactionally and never causes
                // a scan for a different confirmation.
                self.store
                    .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                return Ok(Ok(CriticalWriteConfirmResolution::AlreadySettled));
            };
            let binding = match critical_write_confirm_binding(&pending) {
                Ok(binding) => binding,
                Err(error) => {
                    // A malformed or non-critical primary cannot retain an
                    // exact-confirm alias forever. Remove it, but preserve the
                    // validation error so settlement remains fail-closed.
                    self.store
                        .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                    return Ok(Err(error));
                }
            };
            // The sidecar is only an address; re-derive authority from the
            // primary row before reading state or mutating a claim.
            if binding.confirm_id != confirm_id {
                self.store
                    .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                return Ok(Ok(CriticalWriteConfirmResolution::AlreadySettled));
            }
            let mut body = self
                .get_claim_in_txn(&*wtxn, &binding.claim_id)?
                .ok_or(Error::EntityNotFound)?;
            let raw = self
                .store
                .entities
                .get(&*wtxn, binding.claim_id.as_bytes())?
                .ok_or(Error::EntityNotFound)?;
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            let expired = binding.expires_at <= now;
            if expired {
                put_preauthorized_claim_status_in_txn(
                    self,
                    wtxn,
                    &binding.claim_id,
                    &body,
                    PreauthorizedClaimStatusGrant::TimeoutDemotion,
                    TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                )?;
                // The decline below must bind the transaction's staged Proposed row.
                body.approval = ClaimApprovalStatus::Proposed;
                let mut timed_out = pending.clone();
                timed_out.reason_codes = vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()];
                self.store
                    .put_pending_gate_consent_in_txn(wtxn, &timed_out)?;
            }
            let Some(state) = fold.critical_write_confirms.get(&confirm_id) else {
                return Ok(Ok(if expired {
                    CriticalWriteConfirmResolution::DemotedToProposed
                } else {
                    CriticalWriteConfirmResolution::AlreadySettled
                }));
            };
            if fold
                .conflicted_critical_write_confirms
                .contains(&confirm_id)
            {
                return Ok(Ok(if expired {
                    CriticalWriteConfirmResolution::DemotedToProposed
                } else {
                    CriticalWriteConfirmResolution::AlreadySettled
                }));
            }
            if expired && state.action.disposition == CriticalWriteConfirmDisposition::Clear {
                return Ok(Ok(CriticalWriteConfirmResolution::DemotedToProposed));
            }
            if state.action.gate_decision_id != binding.gate_decision_id.as_bytes()
                || state.action.claim_id != binding.claim_id
                || state.action.effect_digest != binding.effect_digest
                || state.action.read_frontier_hash != binding.read_frontier_hash
                || state.action.nonce != binding.nonce
                || state.action.expires_at != binding.expires_at
            {
                return Ok(Ok(CriticalWriteConfirmResolution::AlreadySettled));
            }
            match state.action.disposition {
                CriticalWriteConfirmDisposition::Clear => {
                    self.store
                        .delete_pending_gate_consent_in_txn(wtxn, &binding.claim_id)?;
                    self.store
                        .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                    Ok(Ok(CriticalWriteConfirmResolution::Cleared))
                }
                CriticalWriteConfirmDisposition::Decline => {
                    put_preauthorized_claim_status_in_txn(
                        self,
                        wtxn,
                        &binding.claim_id,
                        &body,
                        PreauthorizedClaimStatusGrant::FoldDecline,
                        TimeRange {
                            start: header.occurred_start,
                            end: header.occurred_end,
                        },
                        header.learned_at,
                    )?;
                    self.store.close_pending_gate_consent_in_txn(
                        wtxn,
                        &binding.claim_id,
                        now,
                        "rejected",
                        vec![GATE_REASON_CRITICAL_CONFIRM_DECLINED.to_owned()],
                        None,
                    )?;
                    self.store
                        .delete_critical_confirm_index_in_txn(wtxn, &confirm_id)?;
                    Ok(Ok(CriticalWriteConfirmResolution::Retracted))
                }
            }
        })?;
        outcome
    }

    pub(crate) fn expire_critical_write_confirms(&self) -> Result<usize> {
        self.expire_critical_write_confirms_impl(crate::unix_seconds_now())
    }

    #[cfg(test)]
    fn expire_critical_write_confirms_at(&self, now: u64) -> Result<usize> {
        self.expire_critical_write_confirms_impl(now)
    }

    fn expire_critical_write_confirms_impl(&self, now: u64) -> Result<usize> {
        self.with_write_txn(|wtxn| {
            let (cursor, prior_fence) = self
                .store
                .critical_confirm_expiry_sweep_state_in_txn(&*wtxn)?;
            let fence = match prior_fence {
                Some(fence) => Some(fence),
                None => self.store.pending_gate_consents_high_water_in_txn(&*wtxn)?,
            };
            let pending = self.store.pending_gate_consents_page_in_txn(
                &*wtxn,
                cursor,
                fence,
                CRITICAL_CONFIRM_SWEEP_PAGE_LIMIT,
            )?;
            let last_inspected = pending.last().map(|(sequence, _)| *sequence);
            let complete = last_inspected.is_none() || last_inspected == fence;
            self.store.put_critical_confirm_expiry_sweep_state_in_txn(
                wtxn,
                if complete { None } else { last_inspected },
                if complete { None } else { fence },
            )?;
            let mut demoted = 0;
            for (_, row) in pending {
                let Ok(binding) = critical_write_confirm_binding(&row) else {
                    continue;
                };
                if binding.expires_at > now {
                    continue;
                }
                let Some(body) = self.get_claim_in_txn(&*wtxn, &binding.claim_id)? else {
                    continue;
                };
                if body.approval != ClaimApprovalStatus::Auto {
                    continue;
                }
                let raw = self
                    .store
                    .entities
                    .get(&*wtxn, binding.claim_id.as_bytes())?
                    .ok_or(Error::EntityNotFound)?;
                let header = EntityMetadataHeader::parse(&raw)
                    .ok_or(Error::CorruptedIndex("entity header"))?;
                put_preauthorized_claim_status_in_txn(
                    self,
                    wtxn,
                    &binding.claim_id,
                    &body,
                    PreauthorizedClaimStatusGrant::TimeoutDemotion,
                    TimeRange {
                        start: header.occurred_start,
                        end: header.occurred_end,
                    },
                    header.learned_at,
                )?;
                let mut timed_out = row;
                timed_out.reason_codes = vec![GATE_REASON_CRITICAL_CONFIRM_TIMEOUT.to_owned()];
                self.store
                    .put_pending_gate_consent_in_txn(wtxn, &timed_out)?;
                demoted += 1;
            }
            Ok(demoted)
        })
    }

    pub fn review_session_bundle(
        &self,
        actor: &WriteActor,
        expected_producer: &EntityId,
        session_tag: &str,
    ) -> Result<SessionClaimBundle> {
        let rtxn = self.store.env.read_txn()?;
        self.validate_session_bundle_actor_in_txn(&rtxn, actor)?;
        let members =
            self.session_claim_bundle_members_in_txn(&rtxn, expected_producer, session_tag)?;
        let policy = resolve_policy_manifest(&self.store, &rtxn)?;
        for member in &members {
            let mut approved = member.body.clone();
            approved.approval = ClaimApprovalStatus::Approved;
            check_session_bundle_actor_policy(&self.store, &rtxn, actor, &approved, &policy)?;
        }
        Ok(session_claim_bundle(session_tag, members))
    }

    /// Replays every active proposed claim in a session bundle through the
    /// ordinary gate and commits all resulting approvals atomically.
    ///
    /// Any gate denial or stale pending-consent binding aborts the enclosing
    /// write transaction, leaving every member of the producer-bound session
    /// bundle unchanged.
    pub fn merge_session_bundle(
        &self,
        actor: &WriteActor,
        expected_producer: &EntityId,
        session_tag: &str,
    ) -> Result<SessionClaimBundle> {
        let (bundle, recorded_decisions) = self.with_write_txn(|wtxn| {
            self.validate_session_bundle_actor_in_txn(&*wtxn, actor)?;
            let members =
                self.session_claim_bundle_members_in_txn(&*wtxn, expected_producer, session_tag)?;
            if members.is_empty() {
                return Ok((
                    session_claim_bundle(session_tag, members),
                    Vec::<RecordedClaimGateDecision>::new(),
                ));
            }

            let policy = resolve_policy_manifest(&self.store, &*wtxn)?;
            let mut merged = Vec::with_capacity(members.len());
            let mut ops = Vec::with_capacity(members.len());
            let mut recorded_decisions = Vec::with_capacity(members.len());
            for member in members {
                let mut body = member.body;
                body.approval = ClaimApprovalStatus::Approved;
                let source = body.source.ok_or(Error::InvalidClaimBody(
                    "session bundle member missing claim source",
                ))?;
                let envelope = WriteEnvelope::new(
                    *actor,
                    source,
                    WriteProvenance::new(Value::from("session-claim-bundle-merge"))?,
                    ClaimApprovalStatus::Approved,
                );
                let mut recorded_decision = None;
                let gate_result = check_claim_policy_for_write_with_record(
                    &self.store,
                    wtxn,
                    &member.id,
                    ClaimGateWrite {
                        body: &body,
                        envelope: Some(&envelope),
                        defer_metrics_until_commit: true,
                    },
                    &policy,
                    GateWriteMode {
                        record_decision: true,
                        persist_pending_consent: false,
                        resolve_pending: true,
                        can_resolve_pending_consent: false,
                        include_source_in_gate_input: true,
                    },
                    &mut recorded_decision,
                );
                if let Some(recorded_decision) = recorded_decision {
                    recorded_decisions.push(recorded_decision);
                }
                gate_result?;
                let data = encode_claim_body(&body)?;
                merged.push(SessionClaimBundleClaim {
                    id: member.id,
                    body,
                });
                ops.push(BatchOp::Put {
                    id: member.id,
                    entity_type: ENTITY_TYPE_CLAIM,
                    occurred: member.occurred,
                    learned_at: member.learned_at,
                    data,
                    allow_maintenance: false,
                    allow_reserved_predicate: false,
                    hub_sync_imported: false,
                });
            }

            apply_session_bundle_claim_puts(
                &self.store,
                &self.config,
                &self.analyzer,
                wtxn,
                ops,
                self.text_index_trusted
                    .load(std::sync::atomic::Ordering::Acquire),
            )?;

            Ok((
                SessionClaimBundle {
                    session_tag: session_tag.to_owned(),
                    claims: merged,
                },
                recorded_decisions,
            ))
        })?;
        for decision in recorded_decisions {
            decision.record_metrics();
        }
        Ok(bundle)
    }

    fn validate_session_bundle_actor_in_txn(
        &self,
        rtxn: &heed::RoTxn<'_>,
        actor: &WriteActor,
    ) -> Result<()> {
        let actor_raw = self
            .store
            .entities
            .get(rtxn, actor.entity_ref().as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        let actor_header = EntityMetadataHeader::parse(&actor_raw)
            .ok_or(Error::CorruptedIndex("entity header"))?;
        crate::provenance::validate_actor_class(actor_header.entity_type, actor.actor_class())
    }

    /// Builds the ONE policy-aware LLM budget meter for one wake pass: the
    /// same `BudgetGuard`, bound at construction to the engine-stamped actor
    /// and to the live manifest's resolved `budget_policy` table.
    ///
    /// The factory resolves the manifest itself and is fail-closed: when the
    /// loaded resolution forces fail-closed (malformed manifest, unsupported
    /// schema version, engine-version floor, unknown axis, row-count
    /// overflow) it refuses with [`Error::InvalidConfig`] and never
    /// substitutes an empty or fabricated table. Production callers keep
    /// admitting with `guard.admit_for_request(&request)` exactly as before.
    pub fn policy_budget_guard(
        &self,
        attempt_id: impl Into<String>,
        limit_units: u64,
        reserve_units: u64,
        on_budget_exhausted: BudgetExhaustionPolicy,
        actor: WriteActor,
    ) -> Result<BudgetGuard> {
        let rtxn = self.store.env.read_txn()?;
        let resolution = resolve_policy_manifest(&self.store, &rtxn)?;
        let table = resolution.budget_policy().ok_or_else(|| {
            Error::InvalidConfig(
                "policy manifest resolution is fail-closed; refusing to build a policy budget guard"
                    .to_owned(),
            )
        })?;
        Ok(BudgetGuard::with_policy_table(
            attempt_id,
            limit_units,
            reserve_units,
            on_budget_exhausted,
            actor,
            table,
        ))
    }
}

/// Read-only authorization check for the proposed bodies exposed by review.
/// It uses the same actor, source, sensitivity, and live agent-definition
/// ceiling as merge, but does not persist a decision or consume consent.
fn check_session_bundle_actor_policy(
    store: &Store,
    rtxn: &heed::RoTxn<'_>,
    actor: &WriteActor,
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    if policy.enforces_write_gate() {
        let agent_definition_ceiling = agent_definition_ceiling_for_actor(store, rtxn, *actor);
        let input = claim_gate_input(
            body,
            policy,
            GateActor {
                actor_class: edge_actor_class_str(actor.actor_class()).to_owned(),
                actor_ref: Some(actor.entity_ref().to_hex()),
                delegation_grant_ref: None,
            },
            GateContentKind::Claim,
            GateProvenanceHandles {
                actor_entity_ref: Some(actor.entity_ref()),
                ..GateProvenanceHandles::default()
            },
            true,
            agent_definition_ceiling,
            // Read-only review door over proposed claims; no effect facts to
            // classify, so no consent context is composed (pre-DEC-0006 path).
            None,
        );
        enforce_gate_decision(policy.evaluate_gate(&input))?;
    }
    check_claim_source_trust(body, policy)
}

fn session_claim_bundle(
    session_tag: &str,
    members: Vec<crate::claim::SessionClaimBundleMember>,
) -> SessionClaimBundle {
    SessionClaimBundle {
        session_tag: session_tag.to_owned(),
        claims: members
            .into_iter()
            .map(|member| SessionClaimBundleClaim {
                id: member.id,
                body: member.body,
            })
            .collect(),
    }
}

/// Connector-key target selected by governance. Accounting consumes this
/// value only after governance allows an effect.
pub(crate) struct ExternalEffectBudgetTarget {
    pub(crate) key_id: EntityId,
    pub(crate) key: connector_key::ConnectorKeyRecord,
    pub(crate) governing_connector: String,
}

/// Uneffected external-policy decision. The chokepoint may debit the returned
/// target and adjust an exhaustion denial before this decision is recorded.
pub(crate) struct ExternalEffectGovernance {
    decision_id: GateDecisionId,
    decision: GateDecision,
    created_at: u64,
    input: GateEvaluatorInput,
    binding: GateConsentBinding,
    grant_ref: Option<String>,
    approve_once: Option<crate::consent::ApproveOnceAuthorization>,
    matched_grant: Option<(EntityId, StandingOutboundGrant)>,
    budget_target: Option<ExternalEffectBudgetTarget>,
}

impl ExternalEffectGovernance {
    #[must_use]
    pub(crate) fn outcome(&self) -> GateOutcome {
        self.decision.outcome()
    }

    #[must_use]
    pub(crate) fn budget_target_mut(&mut self) -> Option<&mut ExternalEffectBudgetTarget> {
        self.budget_target.as_mut()
    }

    pub(crate) fn deny_budget_exhausted(&mut self) {
        self.decision = GateDecision::deny(GateReasonCode::DenyEffectorBudgetExhausted)
            .with_receipt_reasons(["effector_budget_exhausted"])
            .with_receipt_reasons(external_effect_receipt_reasons(
                self.input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
    }
}

/// Evaluates consent and connector governance without charging or recording.
/// The caller must either finalize the returned decision or abort its txn.
pub(crate) fn evaluate_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    required_grant_id: Option<EntityId>,
) -> Result<ExternalEffectGovernance> {
    let mut hydrated_effect = hydrate_external_effect_contact(store, &*wtxn, effect)?;
    hydrated_effect.standing_grant_ref = None;
    let mut scoped_mcp_grant_authorized = false;
    let matched_grant = standing_outbound_grant_for_effect(
        store,
        wtxn,
        &hydrated_effect,
        policy,
        required_grant_id,
    )?;
    if let Some((grant_id, grant)) = matched_grant.as_ref() {
        hydrated_effect.standing_grant_ref = Some(format!("grant:{}", grant_id.to_hex()));
        scoped_mcp_grant_authorized = grant.scope.scoped_mcp_grant().is_some();
    }
    // The effect door NEVER gates ceiling resolution on the caller-asserted
    // class alone: the resolver binds the identity pair, derives authority
    // from the governing entity's own type, and fails closed on unrecognized
    // class assertions.
    let agent_definition_ceiling = agent_definition_ceiling_for_effect_actor(
        store,
        &*wtxn,
        &hydrated_effect.actor.actor_class,
        hydrated_effect.actor.actor_ref.as_deref(),
        hydrated_effect.provenance.actor_entity_ref,
    );
    // DEC-0006: this door composes its consent context at the chokepoint, so
    // consent is evaluated by the one ladder rather than re-implemented per
    // call site. The coverage set folds three already-verified authorization
    // facts read on THIS write txn — the vault's ACTIVE consent grants, the
    // scope-matched `StandingOutboundGrant` (through the pinned adapter), and
    // any budget-free POLICY-scoped grant the compiler's four-axis matcher
    // accepts (echoed as a covering grant; see below) — so an effect already
    // authorized on remembered state is Auto on the consent axis exactly once,
    // honors revocation immediately, and an UNGRANTED irreversible effect is
    // the only one that enters the ask lane (invariant 1).
    let mut consent_grants = crate::consent::load_active_standing_grants(store, wtxn)?;
    let provisional = hydrated_effect.gate_input(agent_definition_ceiling, None);
    let requirement = external_effect_action_requirement(&hydrated_effect);
    if let (Some(requirement), Some(effect_ctx)) =
        (requirement, provisional.external_effect.as_ref())
    {
        let scoped_covers = policy.scoped_grants().iter().any(|grant| {
            grant.budget.is_none()
                && external_effect_grant_matches(grant, &provisional.actor, effect_ctx)
        });
        if scoped_covers && let Ok(grant) = crate::consent::ActionGrant::new(requirement.clone()) {
            consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
        }
        // A scope-matched `StandingOutboundGrant` resolved on this txn — the
        // matcher already enforced actor identity, channel/contact/verb-class
        // scope, and ACTIVE status — is folded as remembered coverage by
        // ECHOING the requirement as its covering grant. Dial vocabularies
        // differ per scope kind (channel/contact/brief/scoped-MCP), so the
        // adapter's normalized bound cannot be trusted to subset-match the
        // requirement's verb-shaped selectors; the door's own four-axis match
        // is the authority the echo records. Revocation is honored by the
        // matcher upstream: a revoked row never reaches this arm.
        if matched_grant.is_some()
            && let Ok(grant) = crate::consent::ActionGrant::new(requirement)
        {
            consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
        }
    }
    // A payload-aware scoped-MCP grant ALREADY authorized this effect at the
    // registry-match stage (`scoped_mcp_grant_authorized`) — the only safe MCP
    // auto path. Fold it: the effect is consent-covered, not re-asked.
    if scoped_mcp_grant_authorized
        && let Some(requirement) = external_effect_action_requirement(&hydrated_effect)
        && let Ok(grant) = crate::consent::ActionGrant::new(requirement)
    {
        consent_grants.push(crate::consent::StandingConsentGrant::Action(grant));
    }
    // The exact engine-computed digest is the only approve-once lookup key.
    // Reading it on THIS write transaction yields either no approval, one
    // unforgeable available authorization, or a typed spent-replay refusal.
    // The marker is changed to spent only when the final Gate decision is
    // recorded as Allow in this same transaction.
    let approve_once = external_effect_composed_effect(&hydrated_effect)
        .map(|effect| {
            crate::consent::approve_once_authorization_in_txn(store, &*wtxn, &effect.digest())
        })
        .transpose()?
        .flatten();
    let consent =
        external_effect_consent_context(&hydrated_effect, approve_once.as_ref(), &consent_grants);
    let mut input = hydrated_effect.gate_input(agent_definition_ceiling, consent);
    if let Some(effect) = input.external_effect.as_mut() {
        effect.scoped_mcp_grant_authorized = scoped_mcp_grant_authorized;
    }
    let mut decision = policy.evaluate_gate(&input);
    let binding = GateConsentBinding::for_external_effect(&input, policy)?;
    let decision_id = GateDecisionId::now();
    let created_at = crate::unix_seconds_now();
    let grant_ref = input
        .external_effect
        .as_ref()
        .and_then(|effect| effect.standing_grant_ref.clone());

    // CA-06 campaign-compliance stage (ONE-1777). The evaluator hydrates its
    // own typed facts from the claim substrate on THIS txn and answers with a
    // pure verdict; the mapping to a decision stays here, where decisions are
    // constructed. It runs BEFORE the connector-key and budget stages — both
    // guarded on would-be-Allow — so a legal-row refusal never consumes budget,
    // exactly like the counterparty-opt-out wall. It converts a would-be Allow
    // AND a Pending: an owner approval must not be able to unlock a dispatch
    // the governing row forbids. It is enforcement, not a new approval step;
    // effects outside a campaign never reach the evaluator at all.
    if decision.outcome() != GateOutcome::Deny
        && let Some(crate::campaign::compliance::ComplianceVerdict::Block { reason, .. }) =
            crate::campaign::compliance::campaign_compliance_gate(
                store,
                &*wtxn,
                &hydrated_effect,
                created_at,
            )?
    {
        decision = GateDecision::deny(GateReasonCode::DenyCampaignCompliance)
            .with_receipt_reasons([reason.receipt_reason()])
            .with_receipt_reasons(external_effect_receipt_reasons(
                input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
    }

    // GOV-01 connector-key stage (ONE-1416). Channel keys retain
    // unset-is-noop; synthetic scoped-MCP keys fail closed below. The status
    // wall and the budget stage are BOTH guarded on would-be-Allow (M1
    // resolution 2026-07-10): a law-class deny from `evaluate_gate` (e.g.
    // counterparty opt-out) keeps its reason code and never consumes budget.
    let normalized_channel = connector_key::normalize_connector_key(&hydrated_effect.channel);
    let scoped_mcp_governing_connector = matched_grant.as_ref().and_then(|(grant_id, grant)| {
        grant.scope.scoped_mcp_grant().and_then(|_| {
            hydrated_effect
                .scoped_mcp_call
                .as_ref()
                .map(|call| scoped_mcp_credential_connector_key(&call.server, grant_id))
        })
    });
    let uses_scoped_mcp_governing_connector = scoped_mcp_governing_connector.is_some();
    let governing_connector =
        scoped_mcp_governing_connector.unwrap_or_else(|| normalized_channel.clone());
    let governing = connector_key::governing_connector_key(
        store,
        wtxn,
        &governing_connector,
        hydrated_effect.provenance.actor_entity_ref.as_ref(),
    )?;
    let budget_target = governing
        .as_ref()
        .map(|(key_id, key)| ExternalEffectBudgetTarget {
            key_id: *key_id,
            key: key.clone(),
            governing_connector: governing_connector.clone(),
        });
    if uses_scoped_mcp_governing_connector
        && decision.outcome() == GateOutcome::Allow
        && governing.is_none()
    {
        // The real completion—registering each per-grant connector key through
        // the connector lifecycle—rides ONE-1794 with the live transport.
        // Until then, scoped MCP authority fails closed instead of inheriting
        // the channel unset-is-noop behavior.
        decision = GateDecision::pending(vec![GateReasonCode::PendingConnectorKeyUnregistered])
            .with_receipt_reasons(["connector_key_unregistered"])
            .with_receipt_reasons(external_effect_receipt_reasons(
                input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
    }
    if let Some((_key_id, key)) = governing
        && decision.outcome() == GateOutcome::Allow
    {
        // GOV-10 charter stage (ONE-1417), between the status wall and the
        // budget stage: enforcement reads ONLY the compiled policy, never the
        // charter text. Drift degrades to proposed-only (Pending) until a
        // human re-stamps; a never-list match denies. Neither debits.
        let mut charter_wall = None;
        if key.status == ConnectorKeyStatus::Active
            && let Some(block) = key.charter.as_ref()
        {
            if connector_key::charter_block_drifted(block)? {
                charter_wall = Some(
                    GateDecision::pending(vec![GateReasonCode::PendingCharterDrift])
                        .with_receipt_reasons(["charter_drift"]),
                );
            } else if connector_key::charter_never_list_matches(
                block,
                &governing_connector,
                hydrated_effect
                    .scoped_mcp_call
                    .as_ref()
                    .map_or(hydrated_effect.verb.as_str(), |call| call.tool.as_str()),
            ) {
                charter_wall = Some(
                    GateDecision::deny(GateReasonCode::DenyCharterNeverList)
                        .with_receipt_reasons(["charter_never_list"]),
                );
            }
        }

        if key.status != ConnectorKeyStatus::Active {
            let status_reason = match key.status {
                ConnectorKeyStatus::Suspended => "connector_key_suspended",
                ConnectorKeyStatus::Revoked => "connector_key_revoked",
                ConnectorKeyStatus::Pending => "connector_key_pending",
                ConnectorKeyStatus::Active => unreachable!("guarded above"),
            };
            decision = GateDecision::deny(GateReasonCode::DenyConnectorKeySuspended)
                .with_receipt_reasons([status_reason])
                .with_receipt_reasons(external_effect_receipt_reasons(
                    input
                        .external_effect
                        .as_ref()
                        .expect("external effect input"),
                ));
        } else if let Some(wall) = charter_wall {
            // Charter drift / never-list are governance walls, not
            // accounting: they convert the decision whether or not the
            // pipeline will execute this dispatch.
            decision = wall.with_receipt_reasons(external_effect_receipt_reasons(
                input
                    .external_effect
                    .as_ref()
                    .expect("external effect input"),
            ));
        }
    }

    Ok(ExternalEffectGovernance {
        decision_id,
        decision,
        created_at,
        input,
        binding,
        grant_ref,
        approve_once,
        matched_grant,
        budget_target,
    })
}

pub(crate) fn record_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    governance: ExternalEffectGovernance,
) -> Result<(GateDecisionId, GateDecision)> {
    let ExternalEffectGovernance {
        decision_id,
        decision,
        created_at,
        input,
        binding,
        grant_ref,
        approve_once,
        matched_grant,
        budget_target: _,
    } = governance;
    if decision.outcome() == GateOutcome::Allow
        && let Some(authorization) = approve_once.as_ref()
    {
        crate::consent::spend_approve_once_in_txn(store, wtxn, authorization)?;
    }
    crate::off_record::FloorWrites::new(store).append_egress_gate_decision(
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
            system_notices: Vec::new(),
            actor_class: input.actor.actor_class.clone(),
            actor_ref: input.actor.actor_ref.clone(),
            content_kind: input.content_kind.as_str().to_owned(),
            policy_manifest_version: input.policy_manifest_version,
            claim_id: None,
            grant_ref,
            diff_handle: binding.diff_handle,
            read_frontier_hash: binding.read_frontier_hash,
            redacted_at: None,
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

/// Governance surface for external-effect callers that finalize the decision in
/// their own transaction. When `admit_for_execution` is set the caller applies
/// the effect immediately in this same txn (e.g. an identity lifecycle intent),
/// so the governing connector key is debited exactly once here and an exhausted
/// key flips the recorded decision to a budget-exhausted denial before the
/// effect is applied — one durable accounting event per genuinely-new effect
/// (design.out §2/§3). Governance-only callers pass `false` and never debit.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn check_external_effect_policy(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    admit_for_execution: bool,
) -> Result<(GateDecisionId, GateDecision, Option<EffectorBudgetCharge>)> {
    let mut governance = evaluate_external_effect_policy(store, wtxn, effect, policy, None)?;
    let mut effector_charge = None;
    if admit_for_execution && governance.outcome() == GateOutcome::Allow {
        let (charge, exhausted) = charge_admitted_external_effect(
            store,
            wtxn,
            &mut governance,
            effect.send_ref.is_some(),
        )?;
        if exhausted {
            governance.deny_budget_exhausted();
        }
        effector_charge = charge;
    }
    let (decision_id, decision) = record_external_effect_policy(store, wtxn, governance)?;
    Ok((decision_id, decision, effector_charge))
}

/// Debits the governance-selected connector key exactly once for an admitted
/// effect, mirroring the chokepoint `charge_once`: send-dimension rows debit
/// only for send-like effects, an exhausted suspend-class row suspends the key,
/// and the caller converts exhaustion into a denial.
fn charge_admitted_external_effect(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    governance: &mut ExternalEffectGovernance,
    send_like: bool,
) -> Result<(Option<EffectorBudgetCharge>, bool)> {
    let Some(target) = governance.budget_target_mut() else {
        return Ok((None, false));
    };
    // Budget windows advance on the engine's trusted clock, not a caller
    // timestamp, so the debit and any receipt echo share the same window.
    let budget_now = crate::unix_seconds_now();
    let outcome = connector_key::charge_effector_budgets(
        store,
        wtxn,
        &target.key_id,
        &mut target.key,
        &target.governing_connector,
        send_like,
        budget_now,
    )?;
    let (mut charge, exhausted) = match outcome {
        EffectorBudgetChargeOutcome::NoRows(charge)
        | EffectorBudgetChargeOutcome::Charged(charge) => (charge, false),
        EffectorBudgetChargeOutcome::Exhausted {
            row_index,
            on_exhaust,
            mut charge,
        } => {
            if on_exhaust == EffectorBudgetOnExhaust::Suspend {
                connector_key::suspend_connector_key_in_txn(
                    store,
                    wtxn,
                    &target.key_id,
                    &target.key,
                    connector_key::budget_exhausted_reason(row_index),
                    budget_now,
                )?;
                charge.read.status = ConnectorKeyStatus::Suspended;
            }
            (charge, true)
        }
    };
    charge.matched_rows.sort_unstable();
    charge.matched_rows.dedup();
    Ok((Some(charge), exhausted))
}

fn standing_outbound_grant_for_effect(
    store: &Store,
    txn: &heed::RwTxn<'_>,
    effect: &ExternalEffectGateInput,
    policy: &PolicyManifestResolution,
    required_grant_id: Option<EntityId>,
) -> Result<Option<(EntityId, StandingOutboundGrant)>> {
    let current_policy_floor = policy.read_frontier_hash()?;
    let mut candidate_ids = if let Some(required_grant_id) = required_grant_id {
        vec![required_grant_id]
    } else {
        Vec::new()
    };
    if candidate_ids.is_empty() {
        let candidate_principals = if effect.scoped_mcp_call.is_some() {
            verified_standing_outbound_grant_principal(effect)
                .into_iter()
                .collect()
        } else {
            standing_outbound_grant_candidate_principals(effect)
        };
        for principal_ref in candidate_principals {
            let prefix = standing_outbound_grant_principal_index_prefix(&principal_ref)?;
            for entry in store.vault_meta.prefix_iter(txn, &prefix)? {
                let (key, _) = entry?;
                let id = standing_outbound_grant_principal_index_entity_id(&key, &principal_ref)?;
                if !candidate_ids.contains(&id) {
                    candidate_ids.push(id);
                }
            }
        }
    }
    for id in candidate_ids {
        let Some(raw) = store.entities.get(txn, id.as_bytes())? else {
            if required_grant_id == Some(id) {
                return Ok(None);
            }
            return Err(Error::CorruptedIndex("outbound grant entity row"));
        };
        let Some(header) = EntityMetadataHeader::parse(&raw) else {
            return Err(Error::CorruptedIndex("outbound grant entity header"));
        };
        if header.entity_type != ENTITY_TYPE_OUTBOUND_GRANT {
            if required_grant_id == Some(id) {
                return Ok(None);
            }
            return Err(Error::CorruptedIndex("outbound grant entity type"));
        }
        let grant = decode_standing_outbound_grant_body(&raw[ENTITY_METADATA_HEADER_LEN..])?;
        if !grant.is_active_under_policy(&current_policy_floor) {
            continue;
        }
        if !standing_outbound_grant_actor_matches(&grant, effect) {
            continue;
        }
        if let Some(call) = effect.scoped_mcp_call.as_ref() {
            if !is_mcp_effect_channel(&effect.channel) {
                continue;
            }
            if let Some(scoped_grant) = grant.scope.scoped_mcp_grant()
                && evaluate_scoped_mcp_call(scoped_grant, call.as_call())
                    == ScopedMcpConsentDecision::AutoFire
            {
                return Ok(Some((id, grant)));
            }
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

fn is_mcp_effect_channel(channel: &str) -> bool {
    channel
        .trim()
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("mcp:"))
}

pub(crate) fn scoped_mcp_credential_connector_key(server: &str, grant_id: &EntityId) -> String {
    connector_key::normalize_connector_key(&format!("mcp:{server}:grant:{}", grant_id.to_hex()))
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

fn verified_standing_outbound_grant_principal(effect: &ExternalEffectGateInput) -> Option<String> {
    let actor_ref = effect
        .actor
        .actor_ref
        .as_deref()
        .map(str::trim)
        .filter(|actor_ref| !actor_ref.is_empty());
    match (actor_ref, effect.provenance.actor_entity_ref) {
        (Some(actor_ref), Some(actor_entity_ref)) => EntityId::from_hex(actor_ref)
            .ok()
            .filter(|actor_ref| *actor_ref == actor_entity_ref)
            .map(|_| actor_entity_ref.to_hex()),
        (Some(actor_ref), None) => Some(actor_ref.to_owned()),
        (None, Some(actor_entity_ref)) => Some(actor_entity_ref.to_hex()),
        (None, None) => None,
    }
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
    let Some(header) = EntityMetadataHeader::parse(&raw) else {
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

/// Hydrates the counterparty consent facts the external-effect door decides on.
///
/// ONE-1868: `counterparty` is the ONLY required input. The lookup key is
/// `(party_ref, channel_class)` per ARCH-0057 §3, and `channel_identity_ref` is
/// ENRICHMENT that may add candidates — its absence can never return early,
/// because every shipping constructor leaves it `None` and the legal-class hard
/// deny below it was therefore unreachable.
///
/// Every restrictive source is OR-folded: COUNTERPARTY_CONTACT records AND CA-01's
/// `comm.do_not_contact` heads. No leg may clear suppression another leg
/// established.
fn hydrate_external_effect_contact(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    effect: &ExternalEffectGateInput,
) -> Result<ExternalEffectGateInput> {
    let mut hydrated = effect.clone();
    let Some(party_ref) = effect.counterparty.as_deref() else {
        return Ok(hydrated);
    };

    let channel_class = normalize_channel_class(&effect.channel);
    for record in counterparty_contacts_for_send(
        store,
        txn,
        party_ref,
        &channel_class,
        effect.channel_identity_ref.as_ref(),
    )? {
        hydrated.counterparty_first_touch = hydrated
            .counterparty_first_touch
            .or(Some(record.first_touch));
        if record.first_touch == CounterpartyFirstTouch::Public
            && hydrated.policy_risk == ExternalEffectPolicyRisk::Normal
        {
            hydrated.policy_risk = ExternalEffectPolicyRisk::HoldToProposal;
        }
        hydrated.counterparty_opted_out |= record.is_opted_out();
        if record.is_opted_out() && hydrated.counterparty_opt_out_receipt_reason.is_none() {
            hydrated.counterparty_opt_out_receipt_reason = record
                .opt_out
                .map(super::counterparty_contact::CounterpartyOptOut::receipt_reason);
        }
    }

    fold_matching_comm_do_not_contact_heads(store, txn, party_ref, &channel_class, &mut hydrated)?;
    Ok(hydrated)
}

/// Every contact record that participates in this send's restrictive aggregate.
///
/// Three CANDIDATE sources, de-duplicated by contact ref and ordered by it so
/// the folded first-touch and receipt reason are deterministic:
///
/// 1. the identity-independent `(party_ref, channel_class)` index;
/// 2. the legacy identity+counterparty index, when an identity is known — it may
///    only ADD candidates;
/// 3. an unbounded COUNTERPARTY_CONTACT scan, which is MANDATORY: the party-channel index
///    cannot prove its own completeness at HEAD, and a bounded fallback that
///    missed one opted-out row would answer a false "no".
///
/// Channel scope is then applied ONCE, here, to the merged set. Sources find
/// rows for the party; this predicate decides which are in scope for the class.
/// Keeping it at the single fold point is what makes `channel_identity_ref`
/// enrichment rather than a verdict input: source 2 is keyed by identity alone,
/// so a stale or explicitly-pinned cross-class identity would otherwise drag a
/// foreign-channel opt-out into the aggregate and let enrichment move the
/// verdict. A per-source predicate is one forgotten call from that bug; this is
/// zero.
fn counterparty_contacts_for_send(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    channel_identity_ref: Option<&EntityId>,
) -> Result<Vec<CounterpartyContactRecord>> {
    let mut candidates =
        counterparty_contacts_by_party_channel(store, txn, party_ref, channel_class)?;
    if let Some(identity_ref) = channel_identity_ref
        && let Some(hit) =
            counterparty_contact_by_identity_index(store, txn, identity_ref, party_ref)?
    {
        candidates.push(hit);
    }
    candidates.extend(counterparty_contacts_by_party_full_scan(
        store, txn, party_ref,
    )?);

    candidates.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
    candidates.dedup_by(|(left, _), (right, _)| left == right);

    let mut records = Vec::with_capacity(candidates.len());
    for (_, record) in candidates {
        if counterparty_contact_matches_channel_class(store, txn, &record, channel_class)? {
            records.push(record);
        }
    }
    Ok(records)
}

/// Legacy identity+counterparty index hit, when a channel identity is known.
fn counterparty_contact_by_identity_index(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    identity_ref: &EntityId,
    counterparty: &str,
) -> Result<Option<(EntityId, CounterpartyContactRecord)>> {
    let key = counterparty_contact_index_key(identity_ref, counterparty)?;
    let Some(raw_id) = store.vault_meta.get(txn, &key)? else {
        return Ok(None);
    };
    let id = decode_counterparty_contact_index_value(&raw_id)?;
    let Some(record) = read_counterparty_contact_in_txn(store, txn, &id)? else {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index entity row",
        ));
    };
    if !record.matches_counterparty(identity_ref, counterparty) {
        return Err(Error::CorruptedIndex(
            "counterparty contact lookup index assignment",
        ));
    }
    Ok(Some((id, record)))
}

/// OR-folds CA-01's `comm.do_not_contact` heads into the hydrated effect.
///
/// The predicate, the value codec, and the restrictive-wins semantics
/// (`Proposed` is effective; staleness never clears; only an authorized clear
/// stamp removes a head) are CA-01's — imported, never redefined here. The fold
/// is monotonic: it can only ADD suppression.
fn fold_matching_comm_do_not_contact_heads(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    party_ref: &str,
    channel_class: &str,
    hydrated: &mut ExternalEffectGateInput,
) -> Result<()> {
    if !crate::campaign::claims::counterparty_do_not_contact_in_txn(
        store,
        txn,
        party_ref,
        Some(channel_class),
        &hydrated.verb,
    )? {
        return Ok(());
    }
    hydrated.counterparty_opted_out = true;
    // A COUNTERPARTY_CONTACT reason already folded above wins; otherwise the deny would
    // reach the receipt with no reason at all.
    if hydrated.counterparty_opt_out_receipt_reason.is_none() {
        hydrated.counterparty_opt_out_receipt_reason =
            Some(COUNTERPARTY_OPT_OUT_DO_NOT_CONTACT_RECEIPT_REASON);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateWriteMode {
    pub(crate) record_decision: bool,
    pub(crate) persist_pending_consent: bool,
    pub(crate) resolve_pending: bool,
    pub(crate) can_resolve_pending_consent: bool,
    pub(crate) include_source_in_gate_input: bool,
}

pub(crate) struct ClaimGateWrite<'a> {
    pub(crate) body: &'a ClaimBody,
    pub(crate) envelope: Option<&'a WriteEnvelope>,
    pub(crate) defer_metrics_until_commit: bool,
}

pub(crate) struct RecordedClaimGateDecision {
    record: GateDecisionRecord,
    decision: GateDecision,
}

impl RecordedClaimGateDecision {
    pub(crate) fn decision_id(&self) -> GateDecisionId {
        self.record.decision_id
    }

    pub(crate) fn outcome(&self) -> &str {
        &self.record.outcome
    }

    pub(crate) fn record_metrics(&self) {
        record_gate_decision_metrics(&self.decision);
    }

    pub(crate) fn into_record(self) -> GateDecisionRecord {
        self.record
    }
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
        }) && value.as_str() == Some(DREAMER_RUNNER_ATTEMPT_KIND)
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
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
    record: &crate::provenance::EdgeProvenanceClaimBody,
    actor_class: EdgeActorClass,
    policy: &PolicyManifestResolution,
) -> Result<()> {
    if policy.enforces_write_gate() {
        let agent_definition_ceiling = agent_definition_ceiling_for_actor(
            store,
            txn,
            WriteActor::new(record.actor_entity_ref, actor_class),
        );
        let input = claim_gate_input(
            body,
            policy,
            GateActor {
                actor_class: edge_actor_class_str(actor_class).to_owned(),
                actor_ref: Some(record.actor_entity_ref.to_hex()),
                delegation_grant_ref: None,
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
            agent_definition_ceiling,
            // Edge-provenance claims, like ordinary claims, carry no effect-fact
            // axes; the door keeps its pre-DEC-0006 behaviour (None arm).
            None,
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

// The claim-door assembler takes the full axis tuple one call site at a time
// spells out; boxing the tail two `Option` knobs would hide the consent seam
// this lane opened.
#[allow(clippy::too_many_arguments)]
fn claim_gate_input(
    body: &ClaimBody,
    policy: &PolicyManifestResolution,
    actor: GateActor,
    content_kind: GateContentKind,
    provenance: GateProvenanceHandles,
    include_source: bool,
    agent_definition_ceiling: Option<PolicyApprovalCeiling>,
    consent: Option<ConsentGateContext>,
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
        agent_definition_ceiling,
        consent,
    }
}

fn enforce_gate_decision(decision: GateDecision) -> Result<()> {
    if decision.outcome() == GateOutcome::Allow {
        return Ok(());
    }

    reject_gate_decision(decision)
}

/// The deterministic authority-log binding for a critical claim attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalWriteConfirmBinding {
    pub confirm_id: [u8; 32],
    pub gate_decision_id: GateDecisionId,
    pub claim_id: EntityId,
    pub effect_digest: [u8; 32],
    pub read_frontier_hash: [u8; 32],
    pub nonce: [u8; 16],
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CriticalWriteConfirmResolution {
    Cleared,
    Retracted,
    DemotedToProposed,
    AlreadySettled,
}

/// Reconciles replicated claim input against the claim-scoped critical-confirm
/// lifecycle. The durable invalidation is consulted before classifying ordinary
/// pending rows, so neither deletion nor an unrelated pending row can shadow it.
/// A live attachment is closed only for a changed/missing stored body; an exact
/// replay preserves that attachment.
pub(crate) fn reconcile_critical_write_confirm_on_replicated_overwrite(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    claim_id: &EntityId,
    replacement_body: &[u8],
    body_changed_or_missing: bool,
) -> Result<bool> {
    let pending = store.pending_gate_consent_in_txn(wtxn, claim_id)?;
    // Strictly parse a critical-marked row before every marker decision. This
    // keeps malformed attachments fail-closed even when a tombstone also exists.
    let live_binding = pending
        .as_ref()
        .filter(|row| {
            row.reason_codes
                .iter()
                .any(|reason| reason.contains("critical_confirm"))
        })
        .map(critical_write_confirm_binding)
        .transpose()?;

    if store.critical_confirm_invalidation_exists_in_txn(wtxn, claim_id)? {
        return Ok(true);
    }
    let Some(binding) = live_binding else {
        return Ok(false);
    };
    let pending = pending.ok_or(Error::InvariantViolation(
        "critical binding without pending",
    ))?;
    if !body_changed_or_missing {
        return Ok(false);
    }
    store.close_pending_gate_consent_in_txn(
        wtxn,
        claim_id,
        pending.created_at,
        "invalidated",
        vec![GATE_REASON_CRITICAL_CONFIRM_REPLICATED_OVERWRITE.to_owned()],
        None,
    )?;
    store.put_critical_confirm_invalidation_in_txn(
        wtxn,
        claim_id,
        binding.gate_decision_id,
        replacement_body,
    )?;
    Ok(true)
}

pub(crate) fn critical_write_confirm_binding(
    pending: &PendingGateConsentRecord,
) -> Result<CriticalWriteConfirmBinding> {
    if !matches!(
        pending.reason_codes.as_slice(),
        [reason]
            if reason.as_str() == GATE_REASON_PENDING_CRITICAL_CONFIRM_ATTACHED
                || reason.as_str() == GATE_REASON_CRITICAL_CONFIRM_TIMEOUT
    ) {
        return Err(Error::InvalidClaimBody("not a critical-confirm attachment"));
    }
    let claim_id = EntityId::from_bytes(pending.claim_id)
        .map_err(|_| Error::InvalidClaimBody("pending critical-confirm claim id"))?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"oneiron:critical-confirm:v1");
    digest.update(claim_id.as_bytes());
    digest.update(&pending.decision_id.as_bytes());
    digest.update(&pending.diff_handle);
    digest.update(&pending.read_frontier_hash);
    let effect_digest = *digest.finalize().as_bytes();
    let nonce = pending.decision_id.as_bytes();
    let expires_at = pending
        .created_at
        .saturating_add(CRITICAL_WRITE_CONFIRM_TIMEOUT_SECS);
    let mut confirm = Sha256::new();
    confirm.update(CRITICAL_WRITE_CONFIRM_DOMAIN);
    confirm.update(pending.decision_id.as_bytes());
    confirm.update(claim_id.as_bytes());
    confirm.update(effect_digest);
    confirm.update(pending.read_frontier_hash);
    confirm.update(nonce);
    confirm.update(expires_at.to_be_bytes());
    Ok(CriticalWriteConfirmBinding {
        confirm_id: confirm.finalize().into(),
        gate_decision_id: pending.decision_id,
        claim_id,
        effect_digest,
        read_frontier_hash: pending.read_frontier_hash,
        nonce,
        expires_at,
    })
}

/// Whether a critical claim write may land `Auto` with an attached owner
/// confirmation instead of being floored.
///
/// The ceremony this authorizes is a HUMAN one: the write lands now and an owner
/// closes the attached confirmation afterwards. That trade only makes sense for
/// a claim a person actually authored. `comm.*` standing state is not that — it
/// is DERIVED state a projector folds out of already-recorded comm events
/// (`Auto`, `Observed`, first-party), with no author to confirm anything and no
/// reviewer looking for the attachment. Converting its criticality floor into an
/// `Allow` would let projector output cross a gate that the default policy
/// manifest closes, which is fail-OPEN at the claim door; the floor must stand
/// and the write must be rejected (ONE-1716 sweep-11, oracle ES-03).
///
/// The prefix is matched inline rather than against `comm::COMM_CLAIM_PREDICATES`
/// on purpose: this is a gate-side exclusion of a predicate LAYER, so it must
/// also cover any future `comm.*` predicate without the gate importing the comm
/// module. Every other condition is unchanged, so this is strictly more
/// restrictive than before — it can only remove `Allow`s, never add one.
fn critical_claim_can_land_auto_with_confirm(
    input: &GateEvaluatorInput,
    pending: &[GateReasonCode],
    predicate: &str,
) -> bool {
    input.content_kind == GateContentKind::Claim
        && input.criticality == PolicyCriticality::Critical
        && input.consent.is_none()
        && pending == [GateReasonCode::PendingCriticalityFloor]
        && !predicate.starts_with("comm.")
}

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
                hash_opt_str(&mut hasher, effect.standing_grant_ref.as_deref());
                match effect.scoped_mcp_call.as_ref() {
                    Some(call) => {
                        hash_bool(&mut hasher, true);
                        hash_str(&mut hasher, &call.server);
                        hash_str(&mut hasher, &call.tool);
                        hash_str(&mut hasher, call.payload_data_class.as_str());
                        hash_str(&mut hasher, &call.resolved_endpoint);
                    }
                    None => hash_bool(&mut hasher, false),
                }
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

/// Computes the content-addressed consent binding parts for a claim body
/// against the currently-resolved policy manifest. The OF-234 inbox uses
/// this to verify a pending proposal has not drifted (content or policy
/// floor) before redeeming bundle consent on it.
pub(crate) fn claim_consent_binding_parts(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<(Vec<u8>, [u8; 32])> {
    let policy = resolve_policy_manifest(store, txn)?;
    let binding = GateConsentBinding::for_claim(body, &policy)?;
    Ok((binding.diff_handle, binding.read_frontier_hash))
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
        GrantMintIntentScope::Calendar { .. } => {
            return Err(Error::InvalidOutboundGrantBody(
                "calendar disclosure scope is a read grant, not an outbound grant scope",
            ));
        }
    }
    Ok((hasher.finalize().to_vec(), policy.read_frontier_hash()?))
}

fn gate_decision_matches_pending_candidate(
    record: &GateDecisionRecord,
    expected: &GateDecisionRecord,
) -> bool {
    record.version == expected.version
        && record.redacted_at == expected.redacted_at
        && record.outcome == expected.outcome
        && record.reason_codes == expected.reason_codes
        && record.receipt_reasons == expected.receipt_reasons
        && record.system_notices == expected.system_notices
        && record.actor_class == expected.actor_class
        && record.actor_ref == expected.actor_ref
        && record.content_kind == expected.content_kind
        && record.policy_manifest_version == expected.policy_manifest_version
        && record.claim_id == expected.claim_id
        && record.grant_ref == expected.grant_ref
        && record.diff_handle == expected.diff_handle
        && record.read_frontier_hash == expected.read_frontier_hash
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
    for (key, _) in &entries {
        let key = key.as_str()?;
        if !matches!(
            key,
            POLICY_SCHEMA_VERSION_KEY
                | POLICY_PACK_ID_KEY
                | POLICY_PACK_VERSION_KEY
                | POLICY_MIN_ENGINE_VERSION_KEY
                | POLICY_DEFAULTS_KEY
                | POLICY_RULES_KEY
                | POLICY_ACTOR_CEILINGS_KEY
                | POLICY_DELEGATED_GRANTS_KEY
                | POLICY_SOURCE_TRUST_KEY
                | POLICY_SCOPED_GRANTS_KEY
                | POLICY_LEGAL_FLOOR_ROWS_KEY
                | POLICY_OWNER_POLICY_ROWS_KEY
                | POLICY_SIGNATURE_KEY
                | POLICY_SIGNATURES_KEY
                | POLICY_ON_BUDGET_EXHAUSTED_KEY
                | POLICY_BUDGET_POLICY_KEY
        ) {
            return None;
        }
    }

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

    let delegated_grants = match single_map_value(&entries, POLICY_DELEGATED_GRANTS_KEY) {
        MapValue::Missing => Vec::new(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_delegated_grants(value)?,
    };
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
    let budget_policy = match single_map_value(&entries, POLICY_BUDGET_POLICY_KEY) {
        MapValue::Missing => BudgetPolicyTable::default(),
        MapValue::Duplicate => return None,
        MapValue::Present(value) => parse_budget_policy(value)?,
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
        delegated_grants,
        source_trust,
        scoped_grants,
        legal_floor_rows,
        owner_policy_rows,
        owner_policy_rows_dropped,
        signatures,
        on_budget_exhausted,
        budget_policy,
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

fn parse_delegated_grants(value: &Value) -> Option<Vec<DelegationGrantRecord>> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut out = Vec::new();
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        let op = match (
            single_map_value(entries, "op"),
            single_map_value(entries, "kind"),
        ) {
            (MapValue::Present(v), MapValue::Missing)
            | (MapValue::Missing, MapValue::Present(v)) => v.as_str()?,
            _ => return None,
        };
        let grant_ref = required_nonempty_string(entries, "grant_ref")?;
        for (key, _) in entries {
            let key = key.as_str()?;
            let allowed = match op {
                "revoke_grant" => matches!(key, "op" | "kind" | "grant_ref"),
                "grant" => matches!(
                    key,
                    "op" | "kind"
                        | "grant_ref"
                        | ACTOR_CLASS_KEY
                        | ACTOR_REF_KEY
                        | "parent_grant_ref"
                        | ACTOR_CEILING_KEY
                ),
                _ => false,
            };
            if !allowed {
                return None;
            }
        }
        match op {
            "revoke_grant" => out.push(DelegationGrantRecord::RevokeGrant { grant_ref }),
            "grant" => out.push(DelegationGrantRecord::Grant {
                grant_ref,
                actor_class: required_nonempty_string(entries, ACTOR_CLASS_KEY)?,
                actor_ref: optional_string(entries, ACTOR_REF_KEY)?,
                parent_grant_ref: optional_string(entries, "parent_grant_ref")?,
                ceiling: PolicyApprovalCeiling::parse(required_value(entries, ACTOR_CEILING_KEY)?)?,
            }),
            _ => return None,
        }
    }
    Some(out)
}

fn fold_delegated_grants(records: &[DelegationGrantRecord]) -> Option<DelegationFoldCache> {
    let mut revoked = BTreeSet::new();
    let mut map = BTreeMap::new();
    for r in records {
        match r {
            DelegationGrantRecord::RevokeGrant { grant_ref } => {
                revoked.insert(grant_ref.clone());
            }
            DelegationGrantRecord::Grant { grant_ref, .. } => {
                map.entry(grant_ref.clone()).or_insert_with(|| r.clone());
            }
        }
    }
    let mut cache = DelegationFoldCache {
        by_grant_ref: BTreeMap::new(),
        records: map,
        revoked,
    };
    #[allow(clippy::items_after_statements)]
    fn visit(
        key: &str,
        cache: &mut DelegationFoldCache,
        revoked: &BTreeSet<String>,
        stack: &mut BTreeSet<String>,
    ) -> Option<FoldedDelegation> {
        if revoked.contains(key) {
            return Some(FoldedDelegation {
                effective_ceiling: None,
                depth: 1,
            });
        }
        if let Some(v) = cache.by_grant_ref.get(key) {
            return Some(v.clone());
        }
        if !stack.insert(key.to_owned()) {
            return None;
        }
        if stack.len() > usize::from(MAX_DELEGATION_DEPTH) {
            return None;
        }
        let result = match cache.records.get(key)?.clone() {
            DelegationGrantRecord::Grant {
                parent_grant_ref,
                ceiling,
                ..
            } => {
                let (effective, depth) = if let Some(parent) = parent_grant_ref {
                    let p = visit(&parent, cache, revoked, stack)?;
                    (
                        p.effective_ceiling.map(|x| x.restrict(ceiling)),
                        p.depth.saturating_add(1),
                    )
                } else {
                    (Some(ceiling), 1)
                };
                if depth > MAX_DELEGATION_DEPTH {
                    return None;
                }
                FoldedDelegation {
                    effective_ceiling: effective,
                    depth,
                }
            }
            _ => FoldedDelegation {
                effective_ceiling: None,
                depth: 1,
            },
        };
        stack.remove(key);
        cache.by_grant_ref.insert(key.to_owned(), result.clone());
        Some(result)
    }
    let revoked = cache.revoked.clone();
    #[allow(clippy::needless_collect)]
    for key in cache.records.keys().cloned().collect::<Vec<_>>() {
        visit(&key, &mut cache, &revoked, &mut BTreeSet::new())?;
    }
    Some(cache)
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

/// Parses the ordered `budget_policy` row array. Every entry must be a valid
/// row map; any malformed entry rejects the whole table so
/// `decode_policy_manifest` drops the manifest rather than silently widening
/// the policy by ignoring rows.
fn parse_budget_policy(value: &Value) -> Option<BudgetPolicyTable> {
    let Value::Array(rows) = value else {
        return None;
    };
    let mut parsed = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Map(entries) = row else {
            return None;
        };
        parsed.push(parse_budget_policy_row(entries)?);
    }
    Some(BudgetPolicyTable::from_rows(parsed))
}

/// One row is valid only with exactly one of `purpose`/`actor`, at least one
/// of `floor`/`cap`, unsigned 64-bit units (`0` is valid: `cap: 0` denies the
/// row deliberately, `floor: 0` is an explicit no-op reservation), no
/// duplicated key, and no unknown key — unknown keys are never ignored.
fn parse_budget_policy_row(entries: &[(Value, Value)]) -> Option<BudgetPolicyRow> {
    let mut purpose = None;
    let mut actor = None;
    let mut floor_units = None;
    let mut cap_units = None;
    let mut purpose_seen = false;
    let mut actor_seen = false;
    let mut floor_seen = false;
    let mut cap_seen = false;

    for (key, value) in entries {
        match key.as_str()? {
            BUDGET_POLICY_PURPOSE_KEY => {
                if purpose_seen {
                    return None;
                }
                purpose_seen = true;
                purpose = Some(parse_budget_purpose(value)?);
            }
            BUDGET_POLICY_ACTOR_KEY => {
                if actor_seen {
                    return None;
                }
                actor_seen = true;
                actor = Some(parse_budget_actor(value)?);
            }
            BUDGET_POLICY_FLOOR_KEY => {
                if floor_seen {
                    return None;
                }
                floor_seen = true;
                floor_units = Some(value.as_u64()?);
            }
            BUDGET_POLICY_CAP_KEY => {
                if cap_seen {
                    return None;
                }
                cap_seen = true;
                cap_units = Some(value.as_u64()?);
            }
            _ => return None,
        }
    }

    let selector = match (purpose, actor) {
        (Some(purpose), None) => BudgetPolicySelector::Purpose(purpose),
        (None, Some(actor)) => BudgetPolicySelector::Actor(actor),
        _ => return None,
    };
    if !floor_seen && !cap_seen {
        return None;
    }
    Some(BudgetPolicyRow::new(selector, floor_units, cap_units))
}

/// Built-in names map to their pinned `CallPurpose` variants; any other
/// non-empty string is an exact-name `Other`. An `Other` name that happens
/// to equal a built-in's snake-case name parses to the built-in variant, so
/// it can never spell a wildcard.
fn parse_budget_purpose(value: &Value) -> Option<CallPurpose> {
    let name = value.as_str()?;
    if name.is_empty() {
        return None;
    }
    Some(match name {
        "extraction" => CallPurpose::Extraction,
        "consolidation" => CallPurpose::Consolidation,
        "answer_gen" => CallPurpose::AnswerGen,
        "auto_check" => CallPurpose::AutoCheck,
        "tool_routing" => CallPurpose::ToolRouting,
        "voice" => CallPurpose::Voice,
        "eval" => CallPurpose::Eval,
        _ => CallPurpose::Other {
            name: name.to_owned(),
        },
    })
}

/// Actor rows name the canonical lowercase 32-hex `EntityId` form that
/// `WriteActor::entity_ref().to_hex()` produces; any other spelling (wrong
/// length, non-hex, uppercase) rejects the row.
fn parse_budget_actor(value: &Value) -> Option<EntityId> {
    let text = value.as_str()?;
    let id = EntityId::from_hex(text).ok()?;
    if id.to_hex() != text {
        return None;
    }
    Some(id)
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
        if !is_supported_policy_floor_action(&action) {
            return None;
        }
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
        if action
            .as_deref()
            .is_some_and(|action| !is_supported_owner_policy_action(action))
        {
            return None;
        }
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

fn is_supported_policy_floor_action(action: &str) -> bool {
    matches!(
        action,
        "block" | "route_to_help" | "route-to-help" | "reword_retry" | "reword-retry"
    )
}

fn is_supported_owner_policy_action(action: &str) -> bool {
    matches!(action, "block" | "reword_retry" | "reword-retry")
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
mod tests;
