//! Scoped-call execution, post-effect decision, and result transport.

use std::fmt;

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::outbound_grant::StandingOutboundGrant;
use crate::outbound_intent_ledger::{
    FrozenOutboundCall, IntentDispatchResult, IntentLedgerError, IntentState, OutboundCallClass,
    OutboundSendOutcome, OutboundToolDescriptor, classify_outbound_tool,
};

use super::authority::{FrozenMcpPayload, OutboundBindingAuthority, observed_freeze_events_since};
use super::result_scrub::{OutboundResultSender, scrub_outbound_result};
use super::scope::{
    ScopedMcpCallContext, ScopedMcpConsentDecision, ScopedMcpEscalationReason,
    evaluate_scoped_mcp_call,
};

/// Counted output of one consent-bound durable dispatch.
#[derive(Clone, PartialEq, Eq)]
pub struct ScopedMcpDispatchResult {
    pub decision: ScopedMcpConsentDecision,
    pub dispatch: Option<IntentDispatchResult>,
    pub freeze_events: usize,
    pub effectful_sends: usize,
    pub authorization_rejections: usize,
    pub scrubbable_result_fields: usize,
    pub scrubbed_result_fields: usize,
    checked_bytes: Vec<u8>,
}

impl fmt::Debug for ScopedMcpDispatchResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedMcpDispatchResult")
            .field("decision", &self.decision)
            .field("dispatch", &self.dispatch)
            .field("freeze_events", &self.freeze_events)
            .field("effectful_sends", &self.effectful_sends)
            .field("authorization_rejections", &self.authorization_rejections)
            .field("scrubbable_result_fields", &self.scrubbable_result_fields)
            .field("scrubbed_result_fields", &self.scrubbed_result_fields)
            .field(
                "checked_bytes",
                &format_args!("[{} bytes redacted]", self.checked_bytes.len()),
            )
            .finish()
    }
}

/// Runs one scoped call through the intent ledger and authenticated result
/// sender. Scope-exceeds return without constructing a ledger request.
#[expect(clippy::too_many_arguments)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn execute_scoped_mcp_outbound_call<S: OutboundResultSender>(
    vault: &Vault,
    authority: &OutboundBindingAuthority,
    grant_id: EntityId,
    grant: &StandingOutboundGrant,
    principal_ref: &str,
    descriptor: OutboundToolDescriptor,
    attempt_id: AttemptId,
    call_seq: u64,
    call: ScopedMcpCallContext,
    payload: FrozenMcpPayload,
    now_ms: u64,
    sender: &mut S,
) -> std::result::Result<ScopedMcpDispatchResult, IntentLedgerError> {
    #[cfg(test)]
    let freeze_event_baseline = payload.freeze_event_baseline;
    #[cfg(not(test))]
    let freeze_event_baseline = ();
    let _ = grant;
    let actor_entity_ref = Some(EntityId::from_hex(principal_ref).unwrap_or(grant_id));
    let gate = crate::gate::ExternalEffectGateInput {
        actor: crate::gate::GateActor {
            actor_class: "first_party".to_owned(),
            actor_ref: Some(principal_ref.to_owned()),
            delegation_grant_ref: None,
        },
        provenance: crate::gate::GateProvenanceHandles {
            actor_entity_ref,
            ..crate::gate::GateProvenanceHandles::default()
        },
        verb: "send".to_owned(),
        channel: format!("mcp:{}", call.server),
        channel_identity_ref: None,
        counterparty: None,
        brief_ref: None,
        send_ref: None,
        standing_grant_ref: None,
        scoped_mcp_call: Some(call.clone()),
        counterparty_first_touch: None,
        counterparty_opted_out: false,
        counterparty_opt_out_receipt_reason: None,
        has_opted_in: false,
        has_permission: false,
        policy_risk: crate::gate::ExternalEffectPolicyRisk::Normal,
    };
    let idempotency_supported = descriptor.idempotency_supported()
        || classify_outbound_tool(descriptor) == OutboundCallClass::ReadOnly;
    let prepared = crate::outbound_chokepoint::PreparedEffect {
        attempt_id,
        call_seq,
        server: call.server.clone(),
        tool: call.tool.clone(),
        payload: payload.bytes,
        idempotency_supported,
        resolved_endpoint: Some(call.resolved_endpoint.clone()),
        gate,
        budget_class: crate::outbound_intent_ledger::BudgetClass::Send,
        authorization: crate::outbound_chokepoint::PreparedAuthorization::ScopedMcp {
            grant_id,
            principal_ref: principal_ref.to_owned(),
            call: call.clone(),
        },
        verified_actor: None,
    };
    let mut transport = ScopedResultTransport::new(sender);
    let effect = crate::outbound_chokepoint::execute_outbound_effect(
        vault,
        authority,
        crate::outbound_chokepoint::OutboundEffectCommand::New(prepared),
        now_ms,
        &mut transport,
    )?;
    let decision = scoped_decision_after_effect(vault, grant_id, principal_ref, &call, &effect)?;
    let authorization_rejections = usize::from(
        effect.dispatch.state == Some(IntentState::Abandoned)
            || (effect.dispatch.state == Some(IntentState::Pending)
                && effect.dispatch.send_outcome.is_none()
                && effect.dispatch.replayed),
    );
    let dispatch = (effect.dispatch.state.is_some()
        || effect.dispatch.send_outcome.is_some()
        || effect.dispatch.replayed)
        .then_some(effect.dispatch);
    Ok(ScopedMcpDispatchResult {
        decision,
        dispatch,
        freeze_events: observed_freeze_events_since(freeze_event_baseline),
        effectful_sends: transport.effectful_sends,
        authorization_rejections,
        scrubbable_result_fields: transport.scrubbable_result_fields,
        scrubbed_result_fields: transport.scrubbed_result_fields,
        checked_bytes: transport.checked_bytes,
    })
}

fn scoped_decision_after_effect(
    vault: &Vault,
    grant_id: EntityId,
    principal_ref: &str,
    call: &ScopedMcpCallContext,
    effect: &crate::outbound_chokepoint::OutboundEffectResult,
) -> std::result::Result<ScopedMcpConsentDecision, IntentLedgerError> {
    let connector_reason =
        effect
            .gate_receipt_reasons
            .iter()
            .find_map(|reason| match reason.as_str() {
                "connector_key_unregistered" => {
                    Some(ScopedMcpEscalationReason::ConnectorKeyUnregistered)
                }
                "connector_key_pending" => Some(ScopedMcpEscalationReason::ConnectorKeyPending),
                "connector_key_suspended" => Some(ScopedMcpEscalationReason::ConnectorKeySuspended),
                "connector_key_revoked" => Some(ScopedMcpEscalationReason::ConnectorKeyRevoked),
                "charter_drift" => Some(ScopedMcpEscalationReason::ConnectorKeyCharterDrift),
                "charter_never_list" => {
                    Some(ScopedMcpEscalationReason::ConnectorKeyCharterNeverList)
                }
                "effector_budget_exhausted" => {
                    Some(ScopedMcpEscalationReason::ConnectorKeyBudgetExhausted)
                }
                _ => None,
            });
    if let Some(reason) = connector_reason {
        return Ok(ScopedMcpConsentDecision::Escalate(reason));
    }
    if effect
        .dispatch
        .escalation
        .as_ref()
        .is_some_and(|escalation| {
            escalation.reason
                == crate::outbound_intent_ledger::IntentEscalationReason::ConnectorRevoked
        })
    {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::ConnectorKeyRevoked,
        ));
    }
    if effect
        .dispatch
        .escalation
        .as_ref()
        .is_some_and(|escalation| {
            escalation.reason
                == crate::outbound_intent_ledger::IntentEscalationReason::BindingInvalid
        })
    {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::InvalidGrant,
        ));
    }
    if effect
        .gate_outcome
        .as_deref()
        .is_none_or(|outcome| outcome == "allow")
    {
        return Ok(ScopedMcpConsentDecision::AutoFire);
    }
    let Some(grant) = vault.get_standing_outbound_grant(&grant_id)? else {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::InvalidGrant,
        ));
    };
    if grant.principal_ref != principal_ref {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::WrongPrincipal,
        ));
    }
    let current_policy_floor = {
        let rtxn = vault.store.env.read_txn().map_err(Error::from)?;
        crate::gate::resolve_policy_manifest(&vault.store, &rtxn)?.read_frontier_hash()?
    };
    if !grant.is_active_under_policy(&current_policy_floor) {
        return Ok(ScopedMcpConsentDecision::Escalate(
            ScopedMcpEscalationReason::InvalidGrant,
        ));
    }
    Ok(grant.scope.scoped_mcp_grant().map_or(
        ScopedMcpConsentDecision::Escalate(ScopedMcpEscalationReason::InvalidGrant),
        |scope| evaluate_scoped_mcp_call(scope, call.as_call()),
    ))
}

pub(super) struct ScopedResultTransport<'a, S> {
    pub(super) inner: &'a mut S,
    pub(super) effectful_sends: usize,
    pub(super) scrubbable_result_fields: usize,
    pub(super) scrubbed_result_fields: usize,
    pub(super) checked_bytes: Vec<u8>,
}

impl<'a, S> ScopedResultTransport<'a, S> {
    pub(super) fn new(inner: &'a mut S) -> Self {
        Self {
            inner,
            effectful_sends: 0,
            scrubbable_result_fields: 0,
            scrubbed_result_fields: 0,
            checked_bytes: Vec::new(),
        }
    }
}

impl<S: OutboundResultSender> crate::outbound_chokepoint::OutboundTransport
    for ScopedResultTransport<'_, S>
{
    fn send(&mut self, call: &FrozenOutboundCall) -> OutboundSendOutcome {
        self.checked_bytes = call.payload().to_vec();
        let transport = self.inner.send(call);
        self.effectful_sends = self.effectful_sends.saturating_add(1);
        let scrubbable = transport.raw_result.scrubbable_field_count();
        let scrubbed = scrub_outbound_result(transport.raw_result).scrubbed_field_count();
        self.scrubbable_result_fields = self.scrubbable_result_fields.saturating_add(scrubbable);
        self.scrubbed_result_fields = self.scrubbed_result_fields.saturating_add(scrubbed);
        transport.outcome
    }
}
