use std::collections::BTreeMap;

use super::OutboundDeliveryWindowDecision;
use super::capability::{OutboundVerbContract, UnsupportedOutboundCapability};
use super::intent::OutboundIntent;
use crate::campaign::send_hygiene::ListUnsubscribeTarget;
use crate::connector_key::EffectorBudgetRead;
use crate::delivery_window::{
    DeliveryWindowApnsInterruptionLevel, DeliveryWindowContextCondition,
    DeliveryWindowEvaluationContext, DeliveryWindowEvaluator, DeliveryWindowPolicyClaim,
    DeliveryWindowResolvedLevel,
};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{ExternalEffectPolicyRisk, GateActor, GateProvenanceHandles};
use crate::linkedin_connector::LinkedInSeatSandboxPolicy;
use crate::llm::BudgetLadderEvent;
use crate::receipt::{ContextReceiptFields, ReceiptRecord};

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

    pub(super) fn gate_actor(&self) -> GateActor {
        GateActor {
            actor_class: self.actor_class.clone(),
            actor_ref: self.actor_ref.clone(),
            delegation_grant_ref: None,
        }
    }

    pub(super) fn provenance(&self) -> GateProvenanceHandles {
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
    pub(super) const fn to_gate(self) -> ExternalEffectPolicyRisk {
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
    /// Optional in-memory override for the replay-first ledger/charge identity.
    /// When set, the chokepoint intent id is derived from this stable
    /// logical-send ref while `intent_ref` stays the caller-facing/scheduled ref
    /// that sinks key their per-send plan by. Never persisted; defaults to
    /// deriving the ledger identity from `intent_ref`.
    pub ledger_identity_ref: Option<String>,
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
    /// Non-APNs resolved delivery level for compatibility verbs. The only
    /// carrier that can promote a `telegram|line|imessage_mfb|imessage_bridge`
    /// `send` to ambient; absent, the manifest's interrupt class stands.
    pub delivery_window_resolved_level: Option<DeliveryWindowResolvedLevel>,
    /// A human selected this exact instant; policy is observed but cannot park it.
    pub delivery_window_human_explicit_instant: bool,
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
    /// CA-05 unsubscribe target for a campaign email send, frozen with the
    /// intent. Absent for every send that is not campaign email; present, it
    /// produces the `List-Unsubscribe` / `List-Unsubscribe-Post` headers that
    /// ride the frozen payload to the connector.
    pub campaign_unsubscribe: Option<ListUnsubscribeTarget>,
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
            ledger_identity_ref: None,
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
            delivery_window_resolved_level: None,
            delivery_window_human_explicit_instant: false,
            context_receipt: None,
            linkedin_sandbox_policy: None,
            campaign_unsubscribe: None,
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

    /// Freezes the host-resolved delivery level for a compatibility verb.
    #[must_use]
    pub fn delivery_window_resolved_level(mut self, level: DeliveryWindowResolvedLevel) -> Self {
        self.delivery_window_resolved_level = Some(level);
        self
    }

    #[must_use]
    pub fn delivery_window_human_explicit_instant(mut self) -> Self {
        self.delivery_window_human_explicit_instant = true;
        self
    }

    #[must_use]
    pub fn linkedin_sandbox_policy(mut self, policy: LinkedInSeatSandboxPolicy) -> Self {
        self.linkedin_sandbox_policy = Some(policy);
        self
    }

    /// Freezes the CA-05 unsubscribe target for a campaign email send.
    #[must_use]
    pub fn campaign_unsubscribe(mut self, target: ListUnsubscribeTarget) -> Self {
        self.campaign_unsubscribe = Some(target);
        self
    }
}

/// Connector-adapter execution request after resolve, gate, and window stages.
pub struct OutboundExecutionRequest<'a> {
    pub intent_ref: &'a str,
    pub intent: &'a OutboundIntent,
    /// Provider idempotency closes the wire-before-receipt crash window; raw
    /// transports without it remain at-least-once.
    pub idempotency_key: Option<&'a str>,
    pub verb_contract: &'static OutboundVerbContract,
    pub channel_identity_ref: Option<EntityId>,
    pub counterparty_ref: Option<&'a str>,
    /// CA-05 send-hygiene headers, replayed from the FROZEN payload rather than
    /// re-derived, so an adapter cannot invent a different unsubscribe target
    /// per attempt. Empty for every send that froze none.
    pub hygiene_headers: BTreeMap<String, String>,
    /// Effective APNs level after execute-time delivery-window policy.
    pub apns_interruption_level: Option<DeliveryWindowApnsInterruptionLevel>,
}

/// Adapter execution outcome consumed by the common receipt emitter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundExecutionOutcome {
    pub kind: OutboundExecutionOutcomeKind,
    pub delivery_may_have_occurred: bool,
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
            delivery_may_have_occurred: true,
            provider_ref: Some(provider_ref.into()),
            retry_state: None,
            receipt_fields: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn failed(reason: impl Into<String>) -> Self {
        Self {
            kind: OutboundExecutionOutcomeKind::Failed,
            delivery_may_have_occurred: false,
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

    #[must_use]
    pub const fn with_possible_delivery(mut self) -> Self {
        self.delivery_may_have_occurred = true;
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
    /// Echo of the post-debit effector meter when a connector key governed
    /// this dispatch (GOV-02, ONE-1418; A3: a host-call response may ECHO
    /// `self.budget()` — this is an echo of the meter read, not a second
    /// delivery lane).
    pub effector_budget: Option<EffectorBudgetRead>,
    /// Effector-meter ladder events fired by this dispatch, for the host's
    /// one steering queue (same contract as `BudgetAdmission.ladder_events`).
    pub budget_ladder_events: Vec<BudgetLadderEvent>,
}

#[derive(Debug, thiserror::Error)]
pub enum OutboundDispatchError {
    #[error(transparent)]
    UnsupportedCapability(#[from] Box<UnsupportedOutboundCapability>),
    #[error("the facade-bound actor is no longer valid")]
    InvalidBoundActor,
    #[error(transparent)]
    Engine(#[from] Error),
    #[error(transparent)]
    Chokepoint(#[from] crate::outbound_intent_ledger::IntentLedgerError),
}
