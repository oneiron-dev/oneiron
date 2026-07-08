//! Outbound action capability manifests and dispatch spine for OF-327.
//!
//! Capability discovery is the O1 field contract. The O2 dispatcher below is
//! intentionally connector-agnostic: concrete adapters plug in through
//! [`OutboundExecutionSink`], while delivery-window policy is evaluated as a
//! delivery-time request stage.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Vault;
use crate::claim::{ClaimBody, ClaimSubject};
use crate::delivery_window::{
    DeliveryWindowApnsInterruptionLevel, DeliveryWindowContextCondition,
    DeliveryWindowEvaluationContext, DeliveryWindowEvaluator, DeliveryWindowPolicyClaim,
    DeliveryWindowVerbClass, is_delivery_window_claim_predicate,
};
use crate::error::Error;
use crate::gate::{
    self, ExternalEffectGateInput, ExternalEffectPolicyRisk, GateActor, GateOutcome,
    GateProvenanceHandles,
};
use crate::linkedin_connector::{LinkedInSeatPolicyAction, LinkedInSeatSandboxPolicy};
use crate::receipt::{ContextReceiptFields, ReceiptRecord, outbound_intent_receipt};
use crate::types::EntityId;

pub use crate::delivery_window::DeliveryWindowDecision as OutboundDeliveryWindowDecision;

/// Stable manifest shape advertised to agents.
pub const OUTBOUND_CAPABILITY_MANIFEST_VERSION: &str = "outbound.capability_manifest.v1";

/// Closed field names every outbound verb contract carries.
pub const OUTBOUND_VERB_FIELD_CONTRACT: &[&str] = &[
    "kind",
    "channel_call",
    "params",
    "interruption_class",
    "delivery_semantics",
    "retry_class",
    "capability_vs_permission",
];

/// Common outbound vocabulary connectors map onto where supported.
///
/// The verb kind remains data in each connector manifest so connector-specific
/// verbs can coexist with the common vocabulary without changing engine core.
pub const COMMON_OUTBOUND_VERB_KINDS: &[&str] = &[
    "send",
    "send_media",
    "react",
    "edit",
    "retract",
    "replace",
    "mark_read",
    "presence",
    "push",
    "call",
    "schedule_native",
];

/// Version for the intent field contract consumed by the later dispatcher.
pub const OUTBOUND_INTENT_SCHEMA_VERSION: &str = "outbound.intent.v1";

/// Outbound intent spine shared by OF-327 dispatch and receipt projection.
///
/// `job_ref` is optional so older ad-hoc or commitment-triggered intents remain
/// valid. Brief-rooted runs stamp it to make receipt rollups an indexed lookup
/// instead of a render-time chain walk.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OutboundIntent {
    pub actor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    pub verb: String,
    pub channel: String,
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedupe_key: Option<String>,
    pub intent_source: String,
    pub trigger_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_ref: Option<String>,
}

impl OutboundIntent {
    /// Builds an intent from one of the three O2 trigger doors.
    #[must_use]
    pub fn from_trigger(draft: OutboundIntentDraft, trigger: OutboundIntentTrigger) -> Self {
        Self {
            actor: draft.actor,
            on_behalf_of: draft.on_behalf_of,
            verb: draft.verb,
            channel: draft.channel,
            target: draft.target,
            content_ref: draft.content_ref,
            idempotency_key: draft.idempotency_key,
            dedupe_key: draft.dedupe_key,
            intent_source: trigger.source.as_str().to_owned(),
            trigger_ref: trigger.trigger_ref,
            job_ref: trigger.job_ref,
        }
    }
}

/// Intent fields shared by all trigger sources.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundIntentDraft {
    pub actor: String,
    pub on_behalf_of: Option<String>,
    pub verb: String,
    pub channel: String,
    pub target: String,
    pub content_ref: Option<String>,
    pub idempotency_key: Option<String>,
    pub dedupe_key: Option<String>,
}

impl OutboundIntentDraft {
    #[must_use]
    pub fn new(
        actor: impl Into<String>,
        verb: impl Into<String>,
        channel: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            actor: actor.into(),
            on_behalf_of: None,
            verb: verb.into(),
            channel: channel.into(),
            target: target.into(),
            content_ref: None,
            idempotency_key: None,
            dedupe_key: None,
        }
    }

    #[must_use]
    pub fn on_behalf_of(mut self, principal: impl Into<String>) -> Self {
        self.on_behalf_of = Some(principal.into());
        self
    }

    #[must_use]
    pub fn content_ref(mut self, content_ref: impl Into<String>) -> Self {
        self.content_ref = Some(content_ref.into());
        self
    }

    #[must_use]
    pub fn idempotency_key(mut self, idempotency_key: impl Into<String>) -> Self {
        self.idempotency_key = Some(idempotency_key.into());
        self
    }

    #[must_use]
    pub fn dedupe_key(mut self, dedupe_key: impl Into<String>) -> Self {
        self.dedupe_key = Some(dedupe_key.into());
        self
    }
}

/// O2 trigger source. All variants converge into [`OutboundIntent`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundIntentSource {
    /// OF-187 timer wake.
    Commitment,
    /// Dreamer gap queue.
    GapQueue,
    /// In-session agent action.
    AgentImmediate,
}

impl OutboundIntentSource {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Commitment => "commitment",
            Self::GapQueue => "gap_queue",
            Self::AgentImmediate => "agent_immediate",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "commitment" | "commitment_timer_wake" => Some(Self::Commitment),
            "gap_queue" => Some(Self::GapQueue),
            "agent_immediate" => Some(Self::AgentImmediate),
            _ => None,
        }
    }
}

/// Source-specific trigger envelope for an outbound intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundIntentTrigger {
    pub source: OutboundIntentSource,
    pub trigger_ref: String,
    pub job_ref: Option<String>,
}

impl OutboundIntentTrigger {
    #[must_use]
    pub fn commitment_timer_wake(trigger_ref: impl Into<String>) -> Self {
        Self {
            source: OutboundIntentSource::Commitment,
            trigger_ref: trigger_ref.into(),
            job_ref: None,
        }
    }

    #[must_use]
    pub fn gap_queue(trigger_ref: impl Into<String>) -> Self {
        Self {
            source: OutboundIntentSource::GapQueue,
            trigger_ref: trigger_ref.into(),
            job_ref: None,
        }
    }

    #[must_use]
    pub fn agent_immediate(trigger_ref: impl Into<String>) -> Self {
        Self {
            source: OutboundIntentSource::AgentImmediate,
            trigger_ref: trigger_ref.into(),
            job_ref: None,
        }
    }

    #[must_use]
    pub fn job_ref(mut self, job_ref: impl Into<String>) -> Self {
        self.job_ref = Some(job_ref.into());
        self
    }
}

/// Actor context supplied to the outbound dispatch gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundDispatchActor {
    pub actor_class: String,
    pub actor_ref: Option<String>,
    pub actor_entity_ref: Option<EntityId>,
}

impl OutboundDispatchActor {
    #[must_use]
    pub fn agent(agent_ref: EntityId) -> Self {
        Self {
            actor_class: "agent".to_owned(),
            actor_ref: Some(agent_ref.to_hex()),
            actor_entity_ref: Some(agent_ref),
        }
    }

    fn gate_actor(&self) -> GateActor {
        GateActor {
            actor_class: self.actor_class.clone(),
            actor_ref: self.actor_ref.clone(),
        }
    }

    fn provenance(&self) -> GateProvenanceHandles {
        GateProvenanceHandles {
            actor_entity_ref: self.actor_entity_ref,
            ..GateProvenanceHandles::default()
        }
    }
}

/// ExternalEffect policy-risk dial for outbound dispatch.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum OutboundDispatchPolicyRisk {
    #[default]
    Normal,
    HoldToProposal,
}

impl OutboundDispatchPolicyRisk {
    const fn to_gate(self) -> ExternalEffectPolicyRisk {
        match self {
            Self::Normal => ExternalEffectPolicyRisk::Normal,
            Self::HoldToProposal => ExternalEffectPolicyRisk::HoldToProposal,
        }
    }
}

/// Gate facts supplied by the trigger source or caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct OutboundDispatchGate {
    pub has_opted_in: bool,
    pub has_permission: bool,
    pub policy_risk: OutboundDispatchPolicyRisk,
}

impl OutboundDispatchGate {
    #[must_use]
    pub const fn allow_when_policy_grants() -> Self {
        Self {
            has_opted_in: true,
            has_permission: true,
            policy_risk: OutboundDispatchPolicyRisk::Normal,
        }
    }
}

/// Request envelope for one O2 dispatch pipeline run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundDispatchRequest {
    pub receipt_id: String,
    pub intent_ref: String,
    pub intent: OutboundIntent,
    pub actor: OutboundDispatchActor,
    pub gate: OutboundDispatchGate,
    pub occurred_at: u64,
    pub channel_identity_ref: Option<EntityId>,
    pub counterparty_ref: Option<String>,
    pub window_decision: OutboundDeliveryWindowDecision,
    /// Session ref of the in-session trigger, when known. OF-326 talk-only:
    /// dispatch rejects the intent with [`Error::OffRecordTalkOnly`] while
    /// the referenced session is in off-record mode.
    pub originating_session_ref: Option<String>,
    /// Granted ambient conditions active at the send-time door, such as a
    /// calendar busy signal. Producers live outside this dispatch primitive.
    pub active_delivery_contexts: Vec<DeliveryWindowContextCondition>,
    pub delivery_window_subject_ref: Option<EntityId>,
    pub delivery_window_local_minute_of_day: Option<u16>,
    pub delivery_window_channel: Option<String>,
    pub delivery_window_interrupt_surface: Option<String>,
    pub delivery_window_degrade_to: Option<String>,
    pub delivery_window_apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
    /// OF-369/RS9 context field-set captured at the context-assembly seam;
    /// recorded onto the emit receipt for every dispatch outcome.
    /// Optional by design: RS9 pins one hook at the assembly seam, not a
    /// wall at dispatch — emits that never ride a context assembly
    /// (commitment-timer and gap-queue wakes, pre-field-set callers) have
    /// no board or persona compile to record and dispatch unstamped.
    pub context_receipt: Option<ContextReceiptFields>,
    /// Per-seat LinkedIn host/account-risk policy supplied by the host. The
    /// dispatch engine consumes it before connector execution so caps,
    /// cadence, sweep bans, and kill-switch state cannot be bypassed by an
    /// adapter.
    pub linkedin_sandbox_policy: Option<LinkedInSeatSandboxPolicy>,
}

impl OutboundDispatchRequest {
    #[must_use]
    pub fn new(
        receipt_id: impl Into<String>,
        intent_ref: impl Into<String>,
        intent: OutboundIntent,
        actor: OutboundDispatchActor,
        gate: OutboundDispatchGate,
        occurred_at: u64,
        window_decision: OutboundDeliveryWindowDecision,
    ) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            intent_ref: intent_ref.into(),
            intent,
            actor,
            gate,
            occurred_at,
            channel_identity_ref: None,
            counterparty_ref: None,
            window_decision,
            originating_session_ref: None,
            active_delivery_contexts: Vec::new(),
            delivery_window_subject_ref: None,
            delivery_window_local_minute_of_day: None,
            delivery_window_channel: None,
            delivery_window_interrupt_surface: None,
            delivery_window_degrade_to: None,
            delivery_window_apns_interruption_level: None,
            context_receipt: None,
            linkedin_sandbox_policy: None,
        }
    }

    #[must_use]
    pub fn originating_session(mut self, session_ref: impl Into<String>) -> Self {
        self.originating_session_ref = Some(session_ref.into());
        self
    }

    #[must_use]
    pub fn channel_identity_ref(mut self, identity_ref: EntityId) -> Self {
        self.channel_identity_ref = Some(identity_ref);
        self
    }

    #[must_use]
    pub fn counterparty_ref(mut self, counterparty_ref: impl Into<String>) -> Self {
        self.counterparty_ref = Some(counterparty_ref.into());
        self
    }

    #[must_use]
    pub fn window_decision(mut self, decision: OutboundDeliveryWindowDecision) -> Self {
        self.window_decision = decision;
        self
    }

    #[must_use]
    pub fn context_receipt(mut self, context: ContextReceiptFields) -> Self {
        self.context_receipt = Some(context);
        self
    }

    #[must_use]
    pub fn delivery_window_policy(
        mut self,
        context: &DeliveryWindowEvaluationContext,
        claims: &[DeliveryWindowPolicyClaim],
    ) -> Self {
        self.window_decision = DeliveryWindowEvaluator::evaluate(context, claims);
        self.delivery_window_local_minute_of_day = Some(context.local_minute_of_day());
        self.delivery_window_channel = context.channel.clone();
        self.delivery_window_interrupt_surface = context.interrupt_surface.clone();
        self.delivery_window_degrade_to = context.degrade_to.clone();
        self.delivery_window_apns_interruption_level = context.apns_interruption_level;
        for condition in &context.active_contexts {
            self = self.active_delivery_context(*condition);
        }
        self
    }

    #[must_use]
    pub fn active_delivery_context(mut self, condition: DeliveryWindowContextCondition) -> Self {
        if !self.active_delivery_contexts.contains(&condition) {
            self.active_delivery_contexts.push(condition);
        }
        self
    }

    #[must_use]
    pub fn delivery_window_subject_ref(mut self, subject_ref: EntityId) -> Self {
        self.delivery_window_subject_ref = Some(subject_ref);
        self
    }

    #[must_use]
    pub fn delivery_window_local_minute_of_day(mut self, local_minute_of_day: u16) -> Self {
        self.delivery_window_local_minute_of_day = Some(local_minute_of_day);
        self
    }

    #[must_use]
    pub fn delivery_window_channel(mut self, channel: impl Into<String>) -> Self {
        self.delivery_window_channel = Some(channel.into());
        self
    }

    #[must_use]
    pub fn delivery_window_interrupt_surface(mut self, surface: impl Into<String>) -> Self {
        self.delivery_window_interrupt_surface = Some(surface.into());
        self
    }

    #[must_use]
    pub fn delivery_window_degrade_to(mut self, surface: impl Into<String>) -> Self {
        self.delivery_window_degrade_to = Some(surface.into());
        self
    }

    #[must_use]
    pub fn delivery_window_apns_interruption_level(
        mut self,
        level: DeliveryWindowApnsInterruptionLevel,
    ) -> Self {
        self.delivery_window_apns_interruption_level = Some(level);
        self
    }

    #[must_use]
    pub fn linkedin_sandbox_policy(mut self, policy: LinkedInSeatSandboxPolicy) -> Self {
        self.linkedin_sandbox_policy = Some(policy);
        self
    }
}

/// Connector-adapter execution request after resolve, gate, and window stages.
pub struct OutboundExecutionRequest<'a> {
    pub intent_ref: &'a str,
    pub intent: &'a OutboundIntent,
    pub verb_contract: &'static OutboundVerbContract,
    pub channel_identity_ref: Option<EntityId>,
    pub counterparty_ref: Option<&'a str>,
}

/// Adapter execution outcome consumed by the common receipt emitter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundExecutionOutcome {
    pub kind: OutboundExecutionOutcomeKind,
    pub provider_ref: Option<String>,
    pub retry_state: Option<String>,
    pub receipt_fields: BTreeMap<String, String>,
}

/// Typed adapter execution result. Unknown adapter outcomes must be modeled
/// explicitly instead of being silently collapsed by the dispatcher.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OutboundExecutionOutcomeKind {
    DeliveredToChannel,
    Failed,
}

impl OutboundExecutionOutcome {
    #[must_use]
    pub fn delivered_to_channel(provider_ref: impl Into<String>) -> Self {
        Self {
            kind: OutboundExecutionOutcomeKind::DeliveredToChannel,
            provider_ref: Some(provider_ref.into()),
            retry_state: None,
            receipt_fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn failed(reason: impl Into<String>) -> Self {
        Self {
            kind: OutboundExecutionOutcomeKind::Failed,
            provider_ref: None,
            retry_state: Some(reason.into()),
            receipt_fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_receipt_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.receipt_fields.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_receipt_fields(mut self, fields: BTreeMap<String, String>) -> Self {
        self.receipt_fields.extend(fields);
        self
    }
}

/// Connector execution adapter. Per-connector transport is intentionally O6/06e.
pub trait OutboundExecutionSink {
    fn execute(&mut self, request: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome;
}

/// Coarse pipeline outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OutboundDispatchOutcome {
    DeliveredToChannel,
    Held,
    Degraded,
    Suppressed,
    LetGo,
    Failed,
}

impl OutboundDispatchOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeliveredToChannel => "delivered_to_channel",
            Self::Held => "held",
            Self::Degraded => "degraded",
            Self::Suppressed => "suppressed",
            Self::LetGo => "let_go",
            Self::Failed => "failed",
        }
    }
}

/// Result of the single dispatch pipeline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundDispatchResult {
    pub outcome: OutboundDispatchOutcome,
    pub gate_decision_id: Option<String>,
    pub gate_outcome: String,
    pub gate_reason_codes: Vec<String>,
    pub receipt: ReceiptRecord,
}

#[derive(Debug, thiserror::Error)]
pub enum OutboundDispatchError {
    #[error(transparent)]
    UnsupportedCapability(#[from] Box<UnsupportedOutboundCapability>),
    #[error(transparent)]
    Engine(#[from] Error),
}

/// Stateless O2 resolve -> gate -> window -> execute -> receipt pipeline.
#[derive(Clone, Copy, Debug, Default)]
pub struct OutboundDispatchPipeline;

/// Whether a verb may interrupt the recipient.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundInterruptionClass {
    Ambient,
    Interrupt,
}

impl From<OutboundInterruptionClass> for DeliveryWindowVerbClass {
    fn from(value: OutboundInterruptionClass) -> Self {
        match value {
            OutboundInterruptionClass::Ambient => Self::Ambient,
            OutboundInterruptionClass::Interrupt => Self::Interrupt,
        }
    }
}

/// Retry class consumed by the later dispatch/retry policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundRetryClass {
    IdempotentNative,
    IdempotentEmulated,
    NonIdempotentInterrupt,
    ReplaceIdempotent,
}

/// Delivery semantics consumed by edit/retract/dedupe routing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundDeliverySemanticsKind {
    FireAndForget,
    Editable,
    Retractable,
    Replaceable,
    ReactionTarget,
    Ephemeral,
}

/// Delivery behavior for one verb.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutboundDeliverySemantics {
    pub kind: OutboundDeliverySemanticsKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<&'static str>,
}

/// Platform permission status for a capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundPermissionState {
    Allowed,
    Conditional,
    ProviderReview,
}

/// The OF-327 capability-vs-permission split for one verb.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OutboundCapabilityPermission {
    pub capability: bool,
    pub permission: OutboundPermissionState,
    pub policy_risk: bool,
    pub verified_at: &'static str,
    pub note: &'static str,
}

/// Seven-field outbound verb contract.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OutboundVerbContract {
    pub kind: String,
    pub channel_call: String,
    pub params: Value,
    pub interruption_class: OutboundInterruptionClass,
    pub delivery_semantics: OutboundDeliverySemantics,
    pub retry_class: OutboundRetryClass,
    #[serde(rename = "capability_vs_permission")]
    pub capability_vs_permission: OutboundCapabilityPermission,
}

/// Per-connector capability manifest.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OutboundCapabilityManifest {
    pub manifest_version: &'static str,
    pub connector: String,
    pub connector_family: String,
    pub verified_at: &'static str,
    pub schema_on_demand: String,
    pub foreign_content_posture: &'static str,
    pub verbs: Vec<OutboundVerbContract>,
}

/// Typed unsupported-capability error. Callers must surface this instead of
/// treating unsupported connector verbs as successful no-ops.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsupportedOutboundCapability {
    connector: String,
    verb: Option<String>,
    connector_known: bool,
    supported_connectors: Vec<String>,
    supported_verbs: Vec<String>,
    recovery_suggestions: Vec<String>,
}

impl UnsupportedOutboundCapability {
    #[must_use]
    pub fn connector(&self) -> &str {
        &self.connector
    }

    #[must_use]
    pub fn verb(&self) -> Option<&str> {
        self.verb.as_deref()
    }

    #[must_use]
    pub fn connector_known(&self) -> bool {
        self.connector_known
    }

    #[must_use]
    pub fn supported_connectors(&self) -> &[String] {
        &self.supported_connectors
    }

    #[must_use]
    pub fn supported_verbs(&self) -> &[String] {
        &self.supported_verbs
    }

    #[must_use]
    pub fn recovery_suggestions(&self) -> &[String] {
        &self.recovery_suggestions
    }
}

impl std::fmt::Display for UnsupportedOutboundCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.connector_known, self.verb.as_deref()) {
            (true, Some(verb)) => write!(
                f,
                "outbound verb {verb:?} is not supported by connector {:?}",
                self.connector
            ),
            (false, Some(verb)) => write!(
                f,
                "outbound connector {:?} is not registered for verb {verb:?}",
                self.connector
            ),
            (_, None) => {
                write!(
                    f,
                    "outbound connector {:?} is not registered",
                    self.connector
                )
            }
        }
    }
}

impl std::error::Error for UnsupportedOutboundCapability {}

/// Returns the built-in outbound capability manifest registry.
#[must_use]
pub fn outbound_capability_manifests() -> &'static [OutboundCapabilityManifest] {
    static MANIFESTS: OnceLock<Vec<OutboundCapabilityManifest>> = OnceLock::new();
    MANIFESTS.get_or_init(build_outbound_capability_manifests)
}

/// Returns one connector manifest by stable connector key.
#[must_use]
pub fn outbound_capability_manifest(
    connector: &str,
) -> Option<&'static OutboundCapabilityManifest> {
    let connector = normalize_key(connector);
    outbound_capability_manifests()
        .iter()
        .find(|manifest| manifest.connector == connector)
}

/// Resolves one verb contract or returns a typed unsupported-capability error.
pub fn outbound_verb_contract(
    connector: &str,
    verb: &str,
) -> Result<&'static OutboundVerbContract, Box<UnsupportedOutboundCapability>> {
    let connector_key = normalize_key(connector);
    let verb_key = normalize_key(verb);
    let Some(manifest) = outbound_capability_manifest(&connector_key) else {
        return Err(Box::new(unsupported_outbound_capability(
            connector_key,
            Some(verb_key),
            None,
        )));
    };

    manifest
        .verbs
        .iter()
        .find(|entry| entry.kind == verb_key)
        .ok_or_else(|| {
            Box::new(unsupported_outbound_capability(
                connector_key,
                Some(verb_key),
                Some(manifest),
            ))
        })
}

/// Returns a typed unsupported-capability error for connector-only discovery.
#[must_use]
pub fn unsupported_outbound_connector(connector: &str) -> UnsupportedOutboundCapability {
    unsupported_outbound_capability(normalize_key(connector), None, None)
}

impl OutboundDispatchPipeline {
    pub fn dispatch<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        // OF-326 talk-only (ONE-1546): an intent originating from a session
        // currently in off-record mode is rejected before verb resolution —
        // the typed error carries the exit-prompt semantics. Intents from a
        // session flipped back on-record dispatch normally, and the OF-333
        // floor below still classifies every real egress.
        if let Some(session_ref) = request.originating_session_ref.as_deref()
            && let Some(session) = vault.off_record_session(session_ref)?
            && session.mode == crate::off_record::OffRecordMode::OffRecord
        {
            return Err(OutboundDispatchError::Engine(Error::OffRecordTalkOnly {
                session_ref: session_ref.to_owned(),
            }));
        }

        let verb_contract = outbound_verb_contract(&request.intent.channel, &request.intent.verb)?;
        let policy_risk = outbound_dispatch_policy_risk(request.gate, verb_contract);
        let window_decision =
            outbound_delivery_window_decision_at_door(vault, &request, verb_contract)?;
        let effect = ExternalEffectGateInput {
            actor: request.actor.gate_actor(),
            provenance: request.actor.provenance(),
            verb: verb_contract.kind.clone(),
            channel: request.intent.channel.clone(),
            channel_identity_ref: request.channel_identity_ref,
            counterparty: request
                .counterparty_ref
                .clone()
                .or_else(|| Some(request.intent.target.clone())),
            brief_ref: request.intent.job_ref.clone(),
            send_ref: Some(request.intent_ref.clone()),
            standing_grant_ref: None,
            counterparty_first_touch: None,
            counterparty_opted_out: false,
            counterparty_opt_out_receipt_reason: None,
            has_opted_in: request.gate.has_opted_in,
            has_permission: request.gate.has_permission,
            policy_risk,
        };

        let mut wtxn = vault.store.env.write_txn().map_err(Error::from)?;
        let policy = gate::resolve_policy_manifest(&vault.store, &wtxn)?;
        let (gate_decision_id, gate_decision) =
            gate::check_external_effect_policy(&vault.store, &mut wtxn, &effect, &policy)?;
        wtxn.commit().map_err(Error::from)?;

        let gate_outcome_kind = gate_decision.outcome();
        let gate_outcome = gate_outcome_kind.as_str().to_owned();
        let gate_reason_codes = gate_decision
            .reason_codes()
            .iter()
            .map(|reason| reason.as_str().to_owned())
            .collect::<Vec<_>>();
        let gate_receipt_reasons = gate_decision
            .receipt_reasons()
            .iter()
            .map(|reason| (*reason).to_owned())
            .collect::<Vec<_>>();
        let mut engine_receipt_fields = BTreeMap::new();
        let mut engine_policy_trace = Vec::new();

        let (outcome, execution) = match gate_outcome_kind {
            GateOutcome::Allow => match &window_decision {
                OutboundDeliveryWindowDecision::DeliverNow
                | OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { .. } => {
                    if let Some(policy) = request.linkedin_sandbox_policy.as_ref() {
                        let decision = policy.evaluate_outbound(
                            &request.intent.channel,
                            &verb_contract.kind,
                            request.occurred_at,
                        );
                        engine_receipt_fields.extend(decision.receipt_fields);
                        engine_policy_trace.extend(decision.policy_trace);
                        match decision.action {
                            LinkedInSeatPolicyAction::Allow => {
                                let (outcome, execution) =
                                    execute_outbound_request(&request, verb_contract, sink);
                                (outcome, Some(execution))
                            }
                            LinkedInSeatPolicyAction::Hold => (OutboundDispatchOutcome::Held, None),
                            LinkedInSeatPolicyAction::Suppress => {
                                (OutboundDispatchOutcome::Suppressed, None)
                            }
                        }
                    } else {
                        let (outcome, execution) =
                            execute_outbound_request(&request, verb_contract, sink);
                        (outcome, Some(execution))
                    }
                }
                OutboundDeliveryWindowDecision::Hold { .. } => {
                    (OutboundDispatchOutcome::Held, None)
                }
                OutboundDeliveryWindowDecision::Degrade { .. } => {
                    (OutboundDispatchOutcome::Degraded, None)
                }
                OutboundDeliveryWindowDecision::LetGo { .. } => {
                    (OutboundDispatchOutcome::LetGo, None)
                }
            },
            GateOutcome::Pending => (OutboundDispatchOutcome::Held, None),
            GateOutcome::Deny => (OutboundDispatchOutcome::Suppressed, None),
        };

        let mut receipt = outbound_intent_receipt(
            request.receipt_id,
            request.intent_ref.clone(),
            &request.intent,
            request.occurred_at,
            outcome.as_str(),
        );
        receipt
            .policy_trace
            .extend(gate_reason_codes.iter().cloned());
        receipt
            .policy_trace
            .extend(gate_receipt_reasons.iter().cloned());
        receipt.policy_trace.push(window_decision.policy_trace());
        receipt.policy_trace.extend(engine_policy_trace);
        let gate_decision_ref = format!("gate:{}", gate_decision_id.to_hex());
        receipt
            .fields
            .insert("gate_decision_ref".to_owned(), gate_decision_ref.clone());
        receipt
            .fields
            .insert("gate_outcome".to_owned(), gate_outcome.clone());
        receipt
            .fields
            .insert("gate_reason_codes".to_owned(), gate_reason_codes.join(","));
        if !gate_receipt_reasons.is_empty() {
            receipt.fields.insert(
                "gate_receipt_reasons".to_owned(),
                gate_receipt_reasons.join(","),
            );
        }
        receipt.fields.insert(
            "channel_call".to_owned(),
            verb_contract.channel_call.clone(),
        );
        receipt.fields.insert(
            "interruption_class".to_owned(),
            serde_json::to_value(&verb_contract.interruption_class)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned()),
        );
        receipt.fields.insert(
            "retry_class".to_owned(),
            serde_json::to_value(&verb_contract.retry_class)
                .ok()
                .and_then(|value| value.as_str().map(str::to_owned))
                .unwrap_or_else(|| "unknown".to_owned()),
        );
        receipt.fields.insert(
            "policy_risk".to_owned(),
            match policy_risk {
                ExternalEffectPolicyRisk::Normal => "normal",
                ExternalEffectPolicyRisk::HoldToProposal => "hold_to_proposal",
            }
            .to_owned(),
        );
        for (key, value) in engine_receipt_fields {
            receipt.fields.insert(key, value);
        }
        append_optional_receipt_field(
            &mut receipt,
            "content_ref",
            request.intent.content_ref.as_deref(),
        );
        append_optional_receipt_field(
            &mut receipt,
            "idempotency_key",
            request.intent.idempotency_key.as_deref(),
        );
        append_optional_receipt_field(
            &mut receipt,
            "dedupe_key",
            request.intent.dedupe_key.as_deref(),
        );
        append_optional_receipt_field(
            &mut receipt,
            "channel_identity_ref",
            request
                .channel_identity_ref
                .map(|identity_ref| identity_ref.to_hex())
                .as_deref(),
        );
        append_optional_receipt_field(
            &mut receipt,
            "counterparty_ref",
            request.counterparty_ref.as_deref(),
        );
        if let Some(execution) = execution {
            append_optional_receipt_field(
                &mut receipt,
                "provider_ref",
                execution.provider_ref.as_deref(),
            );
            append_optional_receipt_field(
                &mut receipt,
                "retry_state",
                execution.retry_state.as_deref(),
            );
            append_execution_receipt_fields(&mut receipt, &execution.receipt_fields);
        }
        append_dispatch_outcome_receipt_fields(
            &mut receipt,
            outcome,
            gate_outcome_kind,
            &gate_reason_codes,
            &gate_receipt_reasons,
        );
        append_window_receipt_fields(&mut receipt, &window_decision);
        if let Some(context) = request.context_receipt.as_ref() {
            context.append_to_fields(&mut receipt.fields);
        }

        Ok(OutboundDispatchResult {
            outcome,
            gate_decision_id: Some(gate_decision_ref),
            gate_outcome,
            gate_reason_codes,
            receipt,
        })
    }
}

impl Vault {
    pub fn dispatch_outbound_intent<S: OutboundExecutionSink>(
        &self,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        OutboundDispatchPipeline.dispatch(self, request, sink)
    }
}

fn execute_outbound_request<S: OutboundExecutionSink>(
    request: &OutboundDispatchRequest,
    verb_contract: &'static OutboundVerbContract,
    sink: &mut S,
) -> (OutboundDispatchOutcome, OutboundExecutionOutcome) {
    let execution_request = OutboundExecutionRequest {
        intent_ref: &request.intent_ref,
        intent: &request.intent,
        verb_contract,
        channel_identity_ref: request.channel_identity_ref,
        counterparty_ref: request.counterparty_ref.as_deref(),
    };
    let execution = sink.execute(&execution_request);
    let outcome = match execution.kind {
        OutboundExecutionOutcomeKind::DeliveredToChannel => {
            OutboundDispatchOutcome::DeliveredToChannel
        }
        OutboundExecutionOutcomeKind::Failed => OutboundDispatchOutcome::Failed,
    };
    (outcome, execution)
}

fn outbound_dispatch_policy_risk(
    gate: OutboundDispatchGate,
    verb_contract: &OutboundVerbContract,
) -> ExternalEffectPolicyRisk {
    if gate.policy_risk == OutboundDispatchPolicyRisk::HoldToProposal
        || verb_contract.capability_vs_permission.policy_risk
    {
        ExternalEffectPolicyRisk::HoldToProposal
    } else {
        gate.policy_risk.to_gate()
    }
}

fn outbound_delivery_window_decision_at_door(
    vault: &Vault,
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
) -> crate::Result<OutboundDeliveryWindowDecision> {
    let subjects = outbound_delivery_window_subjects(request);
    let stored_claims = stored_delivery_window_policy_claims(vault, &subjects)?;
    if stored_claims.is_empty() {
        return Ok(request.window_decision.clone());
    }

    let verb_class = outbound_delivery_window_verb_class(&request.intent, verb_contract);
    if verb_class == DeliveryWindowVerbClass::Interrupt
        && request.delivery_window_local_minute_of_day.is_none()
        && stored_claims.iter().any(|claim| claim.window.is_some())
    {
        return Ok(most_restrictive_delivery_window_decision(
            request.window_decision.clone(),
            OutboundDeliveryWindowDecision::Hold {
                reason: "local_minute_unavailable".to_owned(),
                retry_at: None,
            },
        ));
    }

    let context = outbound_delivery_window_context(request, verb_contract, verb_class)?;
    let stored_decision = DeliveryWindowEvaluator::evaluate(&context, &stored_claims);
    Ok(most_restrictive_delivery_window_decision(
        request.window_decision.clone(),
        stored_decision,
    ))
}

fn stored_delivery_window_policy_claims(
    vault: &Vault,
    subjects: &[EntityId],
) -> crate::Result<Vec<DeliveryWindowPolicyClaim>> {
    let mut claims = Vec::new();
    for body in
        vault.claim_bodies_for_subjects_matching(subjects, delivery_window_claim_for_subject)?
    {
        claims.push(DeliveryWindowPolicyClaim::from_claim_body(&body)?);
    }
    Ok(claims)
}

fn delivery_window_claim_for_subject(body: &ClaimBody, subject: &EntityId) -> bool {
    is_delivery_window_claim_predicate(&body.predicate)
        && body.subject == ClaimSubject::Entity(*subject)
}

fn outbound_delivery_window_subjects(request: &OutboundDispatchRequest) -> Vec<EntityId> {
    let mut subjects = Vec::new();
    push_delivery_window_subject(&mut subjects, request.delivery_window_subject_ref);
    push_delivery_window_subject(&mut subjects, request.actor.actor_entity_ref);
    push_delivery_window_subject(&mut subjects, request.channel_identity_ref);
    push_delivery_window_subject(
        &mut subjects,
        EntityId::from_hex(&request.intent.target).ok(),
    );
    subjects
}

fn push_delivery_window_subject(subjects: &mut Vec<EntityId>, subject: Option<EntityId>) {
    if let Some(subject) = subject
        && !subjects.contains(&subject)
    {
        subjects.push(subject);
    }
}

fn outbound_delivery_window_context(
    request: &OutboundDispatchRequest,
    verb_contract: &OutboundVerbContract,
    verb_class: DeliveryWindowVerbClass,
) -> crate::Result<DeliveryWindowEvaluationContext> {
    let local_minute_of_day = request.delivery_window_local_minute_of_day.unwrap_or(0);
    let channel = request
        .delivery_window_channel
        .clone()
        .unwrap_or_else(|| outbound_delivery_window_channel(&request.intent));
    let interrupt_surface = request
        .delivery_window_interrupt_surface
        .clone()
        .unwrap_or_else(|| {
            format!(
                "{}:{}",
                normalize_key(&request.intent.channel),
                verb_contract.kind
            )
        });
    let mut context =
        DeliveryWindowEvaluationContext::new(request.occurred_at, local_minute_of_day, verb_class)?
            .channel(channel)
            .interrupt_surface(interrupt_surface);
    if let Some(surface) = request.delivery_window_degrade_to.as_ref() {
        context = context.degrade_to(surface.clone());
    }
    if let Some(level) = request.delivery_window_apns_interruption_level {
        context = context.apns_interruption_level(level);
    }
    for condition in &request.active_delivery_contexts {
        context = context.active_context(*condition);
    }
    Ok(context)
}

fn outbound_delivery_window_verb_class(
    intent: &OutboundIntent,
    verb_contract: &OutboundVerbContract,
) -> DeliveryWindowVerbClass {
    if outbound_delivery_window_is_chat_like_ambient(intent, verb_contract) {
        DeliveryWindowVerbClass::Ambient
    } else {
        DeliveryWindowVerbClass::from(verb_contract.interruption_class.clone())
    }
}

fn outbound_delivery_window_channel(intent: &OutboundIntent) -> String {
    normalize_key(&intent.channel)
}

fn outbound_delivery_window_is_chat_like_ambient(
    intent: &OutboundIntent,
    verb_contract: &OutboundVerbContract,
) -> bool {
    let connector = normalize_key(&intent.channel);
    matches!(connector.as_str(), "slack" | "discord")
        && matches!(verb_contract.kind.as_str(), "send" | "send_media")
}

fn most_restrictive_delivery_window_decision(
    current: OutboundDeliveryWindowDecision,
    candidate: OutboundDeliveryWindowDecision,
) -> OutboundDeliveryWindowDecision {
    let current_rank = delivery_window_decision_rank(&current);
    let candidate_rank = delivery_window_decision_rank(&candidate);
    if candidate_rank > current_rank
        || (candidate_rank == current_rank
            && same_rank_candidate_is_more_restrictive(&current, &candidate))
    {
        candidate
    } else {
        current
    }
}

fn same_rank_candidate_is_more_restrictive(
    current: &OutboundDeliveryWindowDecision,
    candidate: &OutboundDeliveryWindowDecision,
) -> bool {
    match (current, candidate) {
        (
            OutboundDeliveryWindowDecision::Hold {
                retry_at: current_retry_at,
                ..
            },
            OutboundDeliveryWindowDecision::Hold {
                retry_at: candidate_retry_at,
                ..
            },
        ) => hold_retry_rank(candidate_retry_at) > hold_retry_rank(current_retry_at),
        _ => false,
    }
}

fn hold_retry_rank(retry_at: &Option<u64>) -> (bool, u64) {
    (retry_at.is_none(), retry_at.unwrap_or(0))
}

fn delivery_window_decision_rank(decision: &OutboundDeliveryWindowDecision) -> u8 {
    match decision {
        OutboundDeliveryWindowDecision::DeliverNow => 0,
        OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { .. } => 1,
        OutboundDeliveryWindowDecision::Degrade { .. } => 2,
        OutboundDeliveryWindowDecision::Hold { .. } => 3,
        OutboundDeliveryWindowDecision::LetGo { .. } => 4,
    }
}

fn append_optional_receipt_field(
    receipt: &mut ReceiptRecord,
    key: &'static str,
    value: Option<&str>,
) {
    if let Some(value) = value
        && !value.trim().is_empty()
    {
        receipt.fields.insert(key.to_owned(), value.to_owned());
    }
}

fn append_execution_receipt_fields(receipt: &mut ReceiptRecord, fields: &BTreeMap<String, String>) {
    for (key, value) in fields {
        if key.trim().is_empty() || value.trim().is_empty() {
            continue;
        }
        receipt
            .fields
            .entry(key.clone())
            .or_insert_with(|| value.clone());
    }
}

fn append_dispatch_outcome_receipt_fields(
    receipt: &mut ReceiptRecord,
    outcome: OutboundDispatchOutcome,
    gate_outcome: GateOutcome,
    gate_reason_codes: &[String],
    gate_receipt_reasons: &[String],
) {
    let gate_reason = gate_reason_codes
        .iter()
        .find(|reason| !reason.trim().is_empty())
        .map(String::as_str);
    let gate_receipt_reason = gate_receipt_reasons
        .iter()
        .find(|reason| !reason.trim().is_empty())
        .map(String::as_str);

    match (outcome, gate_outcome) {
        (OutboundDispatchOutcome::Held, GateOutcome::Pending) => {
            append_optional_receipt_field(receipt, "hold_reason", gate_reason);
        }
        (OutboundDispatchOutcome::Suppressed, GateOutcome::Deny) => {
            let suppression = if gate_reason_codes
                .iter()
                .any(|reason| reason == "gate.deny.counterparty_opt_out")
            {
                "counterparty_opt_out"
            } else {
                "gate_denied"
            };
            receipt
                .fields
                .insert("suppression".to_owned(), suppression.to_owned());
            append_optional_receipt_field(
                receipt,
                "suppression_reason",
                gate_receipt_reason.or(gate_reason),
            );
        }
        _ => {}
    }
}

fn append_window_receipt_fields(
    receipt: &mut ReceiptRecord,
    decision: &OutboundDeliveryWindowDecision,
) {
    match decision {
        OutboundDeliveryWindowDecision::DeliverNow => {
            receipt
                .fields
                .insert("window_action".to_owned(), "deliver_now".to_owned());
        }
        OutboundDeliveryWindowDecision::DeliverNowWithApnsCap { reason, from, to } => {
            receipt
                .fields
                .insert("window_action".to_owned(), "deliver_now".to_owned());
            receipt
                .fields
                .insert("window_reason".to_owned(), reason.clone());
            receipt
                .fields
                .insert("degraded_from".to_owned(), from.clone());
            receipt.fields.insert("degraded_to".to_owned(), to.clone());
        }
        OutboundDeliveryWindowDecision::Hold { reason, retry_at } => {
            receipt
                .fields
                .insert("window_action".to_owned(), "hold".to_owned());
            receipt
                .fields
                .insert("window_reason".to_owned(), reason.clone());
            receipt
                .fields
                .entry("hold_reason".to_owned())
                .or_insert_with(|| reason.clone());
            if let Some(retry_at) = retry_at {
                receipt
                    .fields
                    .insert("retry_at".to_owned(), retry_at.to_string());
            }
        }
        OutboundDeliveryWindowDecision::Degrade { reason, from, to } => {
            receipt
                .fields
                .insert("window_action".to_owned(), "degrade".to_owned());
            receipt
                .fields
                .insert("window_reason".to_owned(), reason.clone());
            receipt
                .fields
                .insert("degraded_from".to_owned(), from.clone());
            receipt.fields.insert("degraded_to".to_owned(), to.clone());
        }
        OutboundDeliveryWindowDecision::LetGo { reason } => {
            receipt
                .fields
                .insert("window_action".to_owned(), "let_go".to_owned());
            receipt
                .fields
                .insert("window_reason".to_owned(), reason.clone());
            receipt
                .fields
                .insert("let_go_reason".to_owned(), reason.clone());
        }
    }
}

fn unsupported_outbound_capability(
    connector: String,
    verb: Option<String>,
    manifest: Option<&OutboundCapabilityManifest>,
) -> UnsupportedOutboundCapability {
    let supported_connectors = outbound_capability_manifests()
        .iter()
        .map(|manifest| manifest.connector.clone())
        .collect::<Vec<_>>();
    let supported_verbs = manifest
        .map(|manifest| {
            manifest
                .verbs
                .iter()
                .map(|entry| entry.kind.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let recovery_suggestions = if manifest.is_some() {
        vec![
            format!(
                "Use one of {connector}'s supported outbound verbs: {}.",
                supported_verbs.join(", ")
            ),
            format!(
                "Fetch /v1/core/outbound/capabilities/{connector} before planning connector-specific actions."
            ),
        ]
    } else {
        vec![
            format!(
                "Choose a registered outbound connector: {}.",
                supported_connectors.join(", ")
            ),
            "Fetch /v1/core/outbound/capabilities before selecting a connector.".to_owned(),
        ]
    };

    UnsupportedOutboundCapability {
        connector,
        verb,
        connector_known: manifest.is_some(),
        supported_connectors,
        supported_verbs,
        recovery_suggestions,
    }
}

fn line_reply_quota() -> Value {
    json!({
        "plan_tier": "all",
        "metered": false,
        "quota_debit": false,
        "notes": "Reactive replies are free and require a live reply-token handle."
    })
}

fn line_push_quota() -> Value {
    json!({
        "plan_tier": "free_or_paid",
        "metered": true,
        "quota_debit": true,
        "free_monthly_allowance": crate::channel_identity_provider::DEFAULT_LINE_PUSH_MONTHLY_ALLOWANCE,
        "overage_policy": "requires_metered_plan"
    })
}

fn build_outbound_capability_manifests() -> Vec<OutboundCapabilityManifest> {
    vec![
        manifest(
            "line",
            "chat",
            "LINE Messaging API outbound schema; adapter may require channel review for narrowcast.",
            vec![
                verb(
                    "reply",
                    "reply_message",
                    json!({
                        "reply_token_ref": "payload_ref host-local reply token handle",
                        "messages": [{"type": "text", "text": "string"}],
                        "quota": line_reply_quota()
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Allowed,
                    false,
                    "LINE reply messages are reactive, free, and bounded by reply-token validity.",
                ),
                verb(
                    "push",
                    "push_message",
                    json!({
                        "to": "line_user_id | line_group_id",
                        "messages": [{"type": "text", "text": "string"}],
                        "quota": line_push_quota()
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    false,
                    "LINE push messages debit the monthly push quota and require plan-tier checks before dispatch.",
                ),
                verb(
                    "send",
                    "reply_message | push_message",
                    json!({
                        "mode": "reply | push",
                        "messages": [{"type": "text", "text": "string"}],
                        "reply": {
                            "reply_token_ref": "payload_ref host-local reply token handle",
                            "quota": line_reply_quota()
                        },
                        "push": {
                            "to": "line_user_id | line_group_id",
                            "quota": line_push_quota()
                        }
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    false,
                    "Compatibility send requires callers to choose reply or push; push-mode sends debit monthly quota and require plan-tier checks.",
                ),
                verb(
                    "send_media",
                    "reply_message | push_message",
                    json!({
                        "mode": "reply | push",
                        "messages": [{"type": "image|video|audio|file", "originalContentUrl": "https://..."}],
                        "reply": {
                            "reply_token_ref": "payload_ref host-local reply token handle",
                            "quota": line_reply_quota()
                        },
                        "push": {
                            "to": "line_user_id | line_group_id",
                            "quota": line_push_quota()
                        }
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Compatibility media sends require callers to choose reply or push; push-mode sends debit monthly quota and require plan-tier checks.",
                ),
                verb(
                    "narrowcast",
                    "narrowcast",
                    json!({
                        "messages": [{"type": "text", "text": "string"}],
                        "recipient": {"type": "operator", "and": []}
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::ProviderReview,
                    true,
                    "LINE narrowcast is a connector-specific capability and can require plan/review constraints.",
                ),
            ],
        ),
        manifest(
            "telegram",
            "chat",
            "Telegram Bot API outbound schema; permissions depend on bot membership and chat policies.",
            vec![
                verb(
                    "send",
                    "sendMessage",
                    json!({"chat_id": "integer|string", "text": "string", "parse_mode": "optional string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Allowed,
                    false,
                    "Bot sends are supported when the bot may message the target chat.",
                ),
                verb(
                    "send_media",
                    "sendPhoto | sendVideo | sendAudio | sendDocument",
                    json!({"chat_id": "integer|string", "media": "file_id|URL|multipart", "caption": "optional string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Allowed,
                    true,
                    "Media calls require a supported media transport and target chat permission.",
                ),
                verb(
                    "react",
                    "setMessageReaction",
                    json!({"chat_id": "integer|string", "message_id": "integer", "reaction": [{"type": "emoji", "emoji": "string"}]}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::ReactionTarget,
                    Some("provider-defined message reaction window"),
                    OutboundRetryClass::IdempotentNative,
                    OutboundPermissionState::Conditional,
                    false,
                    "Reaction availability depends on chat type and bot permissions.",
                ),
                verb(
                    "edit",
                    "editMessageText | editMessageCaption | editMessageMedia",
                    json!({"chat_id": "integer|string", "message_id": "integer", "text": "string"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::Editable,
                    Some("provider-defined edit window"),
                    OutboundRetryClass::ReplaceIdempotent,
                    OutboundPermissionState::Conditional,
                    false,
                    "Edits are supported for editable bot-originated messages.",
                ),
            ],
        ),
        manifest(
            "slack",
            "workspace_chat",
            "Slack Web API outbound schema; OAuth scopes and workspace policies are distinct from capability.",
            vec![
                verb(
                    "send",
                    "chat.postMessage",
                    json!({"channel": "channel_id", "text": "string", "blocks": "optional block kit array", "thread_ts": "optional string", "username": "persona display name", "icon_url": "optional persona avatar URL", "icon_emoji": "optional persona emoji", "metadata": "optional app-level-token identity metadata"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    false,
                    "Requires chat:write, chat:write.customize for persona attribution, and channel posting permission; Slack message metadata is app-level-token only.",
                ),
                verb(
                    "react",
                    "reactions.add",
                    json!({"channel": "channel_id", "timestamp": "message_ts", "name": "emoji_name"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::ReactionTarget,
                    None,
                    OutboundRetryClass::IdempotentNative,
                    OutboundPermissionState::Conditional,
                    false,
                    "Requires reactions:write and visibility to the message.",
                ),
                verb(
                    "edit",
                    "chat.update",
                    json!({"channel": "channel_id", "ts": "message_ts", "text": "string", "blocks": "optional block kit array"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::Editable,
                    None,
                    OutboundRetryClass::ReplaceIdempotent,
                    OutboundPermissionState::Conditional,
                    false,
                    "Updates are limited to messages the app can edit.",
                ),
                verb(
                    "retract",
                    "chat.delete",
                    json!({"channel": "channel_id", "ts": "message_ts"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::Retractable,
                    None,
                    OutboundRetryClass::IdempotentEmulated,
                    OutboundPermissionState::Conditional,
                    false,
                    "Deletes require permission over the target message.",
                ),
            ],
        ),
        manifest(
            "discord",
            "community_chat",
            "Discord Bot API outbound schema; guild/channel permissions control usable capability.",
            vec![
                verb(
                    "send",
                    "create_message",
                    json!({"channel_id": "snowflake", "content": "string", "embeds": "optional array", "message_reference": "optional reply"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    false,
                    "Requires Send Messages in the target channel.",
                ),
                verb(
                    "react",
                    "create_reaction",
                    json!({"channel_id": "snowflake", "message_id": "snowflake", "emoji": "unicode|custom"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::ReactionTarget,
                    None,
                    OutboundRetryClass::IdempotentNative,
                    OutboundPermissionState::Conditional,
                    false,
                    "Requires message visibility and reaction permission.",
                ),
                verb(
                    "edit",
                    "edit_message",
                    json!({"channel_id": "snowflake", "message_id": "snowflake", "content": "string", "embeds": "optional array"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::Editable,
                    None,
                    OutboundRetryClass::ReplaceIdempotent,
                    OutboundPermissionState::Conditional,
                    false,
                    "Bots can edit messages they authored.",
                ),
                verb(
                    "retract",
                    "delete_message",
                    json!({"channel_id": "snowflake", "message_id": "snowflake"}),
                    OutboundInterruptionClass::Ambient,
                    OutboundDeliverySemanticsKind::Retractable,
                    None,
                    OutboundRetryClass::IdempotentEmulated,
                    OutboundPermissionState::Conditional,
                    false,
                    "Deletes depend on channel moderation permissions or authorship.",
                ),
            ],
        ),
        manifest(
            "apns",
            "push",
            "Apple Push Notification service schema; device tokens and entitlements are permission data.",
            vec![verb(
                "push",
                "apns_push",
                json!({"device_token": "hex", "topic": "bundle id", "aps": {"alert": "string|object", "badge": "optional integer", "sound": "optional string"}}),
                OutboundInterruptionClass::Interrupt,
                OutboundDeliverySemanticsKind::FireAndForget,
                None,
                OutboundRetryClass::NonIdempotentInterrupt,
                OutboundPermissionState::Conditional,
                true,
                "APNs can interrupt users and depends on app entitlement, token validity, and user notification permission.",
            )],
        ),
        manifest(
            "imessage_mfb",
            "apple_messages_for_business",
            "Apple Messages for Business schema; capability is distinct from brand approval and conversation state.",
            vec![
                verb(
                    "send",
                    "messages_for_business_send",
                    json!({"conversation_id": "string", "text": "string", "rich_link": "optional object"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::ProviderReview,
                    true,
                    "Messages for Business requires brand/channel approval and an active conversation.",
                ),
                verb(
                    "invite",
                    "messages_for_business_invite",
                    json!({"recipient": "phone|apple_business_chat_id", "intent": "string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::ProviderReview,
                    true,
                    "Invite is connector-specific and gated by Apple approval and recipient eligibility.",
                ),
            ],
        ),
        manifest(
            "imessage_bridge",
            "local_bridge",
            "Local iMessage bridge schema; capability is local and should be treated as permission-sensitive.",
            vec![
                verb(
                    "send",
                    "local_messages_send",
                    json!({"chat_id": "string", "text": "string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Local bridge sends require host-device consent and OS-level Messages availability.",
                ),
                verb(
                    "send_media",
                    "local_messages_send_attachment",
                    json!({"chat_id": "string", "attachment_path": "string", "caption": "optional string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Media sends require explicit file access and host-device consent.",
                ),
            ],
        ),
        manifest(
            "linkedin",
            "professional_network",
            "LinkedIn session content is foreign platform content; normalize inbound text through the LinkedIn connector before claims are proposed.",
            vec![
                verb(
                    "send_dm",
                    "send_message",
                    json!({
                        "linkedin_username": "recipient vanity name or profile key",
                        "profile_urn": "optional fsd_profile URN handle from get_person_profile",
                        "message": "string resolved from content_ref",
                        "confirm_send": "true only after OF-327 grant/gate approval",
                        "verify_after_send": "send_message return is never trusted; re-read get_conversation and content-match before delivered receipt",
                        "engine_side_safety": "per-seat sandbox policy enforces kill-switch, <=15/day default cap, active-session cadence, and no sweeps before connector transport"
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Wraps stickerdaniel/linkedin-mcp-server send_message with verify-after-send; account-risk and principal-session consent remain permission gates.",
                ),
                verb(
                    "connect_request",
                    "connect_with_person",
                    json!({
                        "linkedin_username": "recipient vanity name or profile key",
                        "note": "optional connection note resolved from content_ref",
                        "engine_side_safety": "per-seat sandbox policy revokes this verb when the kill switch is engaged"
                    }),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Wraps stickerdaniel/linkedin-mcp-server connect_with_person with optional note; cold outreach and account-risk walls remain permission gates.",
                ),
            ],
        ),
        manifest(
            "email",
            "email",
            "SMTP/provider email schema; deliverability and recipient consent are permissions, not raw capability.",
            vec![
                verb(
                    "send",
                    "send_email",
                    json!({"to": ["addr@example.com"], "subject": "string", "body": "text/html|string", "headers": "optional object"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::FireAndForget,
                    None,
                    OutboundRetryClass::NonIdempotentInterrupt,
                    OutboundPermissionState::Conditional,
                    true,
                    "Email sends require verified sender, deliverability policy, and recipient consent checks.",
                ),
                verb(
                    "replace",
                    "send_correction_or_superseding_email",
                    json!({"original_message_id": "optional string", "to": ["addr@example.com"], "subject": "string", "body": "string"}),
                    OutboundInterruptionClass::Interrupt,
                    OutboundDeliverySemanticsKind::Replaceable,
                    None,
                    OutboundRetryClass::ReplaceIdempotent,
                    OutboundPermissionState::Conditional,
                    true,
                    "Email cannot edit in place; replace means sending a superseding message.",
                ),
            ],
        ),
        manifest(
            "voice",
            "voice_call",
            "Voice call schema; dialing is interruption-heavy and permission-sensitive.",
            vec![verb(
                "call",
                "start_voice_call",
                json!({"to": "e164", "script_ref": "optional string", "recording_disclosure": "required string"}),
                OutboundInterruptionClass::Interrupt,
                OutboundDeliverySemanticsKind::FireAndForget,
                None,
                OutboundRetryClass::NonIdempotentInterrupt,
                OutboundPermissionState::ProviderReview,
                true,
                "Voice calls require recipient consent, jurisdictional compliance, and provider approval.",
            )],
        ),
    ]
}

fn manifest(
    connector: &'static str,
    connector_family: &'static str,
    foreign_content_posture: &'static str,
    verbs: Vec<OutboundVerbContract>,
) -> OutboundCapabilityManifest {
    OutboundCapabilityManifest {
        manifest_version: OUTBOUND_CAPABILITY_MANIFEST_VERSION,
        connector: connector.to_owned(),
        connector_family: connector_family.to_owned(),
        verified_at: "2026-07-06",
        schema_on_demand: format!("/v1/core/outbound/capabilities/{connector}"),
        foreign_content_posture,
        verbs,
    }
}

#[allow(clippy::too_many_arguments)]
fn verb(
    kind: &'static str,
    channel_call: &'static str,
    params: Value,
    interruption_class: OutboundInterruptionClass,
    delivery_kind: OutboundDeliverySemanticsKind,
    delivery_window: Option<&'static str>,
    retry_class: OutboundRetryClass,
    permission: OutboundPermissionState,
    policy_risk: bool,
    note: &'static str,
) -> OutboundVerbContract {
    OutboundVerbContract {
        kind: kind.to_owned(),
        channel_call: channel_call.to_owned(),
        params,
        interruption_class,
        delivery_semantics: OutboundDeliverySemantics {
            kind: delivery_kind,
            window: delivery_window,
        },
        retry_class,
        capability_vs_permission: OutboundCapabilityPermission {
            capability: true,
            permission,
            policy_risk,
            verified_at: "2026-07-06",
            note,
        },
    }
}

fn normalize_key(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

#[cfg(test)]
mod tests;
