//! Admitted effect: only this lane enters the replay-first chokepoint.
use super::transport::DispatchChokepointTransport;
use super::verdict::DispatchVerdict;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::gate::{ExternalEffectGateInput, GateOutcome};
use crate::outbound::capability::OutboundVerbContract;
use crate::outbound::dispatch_types::{
    OutboundDispatchError, OutboundDispatchOutcome, OutboundDispatchRequest,
    OutboundExecutionOutcome, OutboundExecutionOutcomeKind, OutboundExecutionSink,
};
use crate::outbound_intent_ledger::{IntentResolution, UnconfirmedDelivery};
use crate::receipt::ReceiptRecord;

pub(super) struct EffectInput<'a, S> {
    pub(super) vault: &'a Vault,
    pub(super) request: &'a OutboundDispatchRequest,
    pub(super) sink: &'a mut S,
    pub(super) verb_contract: &'static OutboundVerbContract,
    pub(super) effect: ExternalEffectGateInput,
    pub(super) payload: Vec<u8>,
    pub(super) attempt_id: AttemptId,
    pub(super) idempotency_supported: bool,
    pub(super) verified_actor: Option<(EntityId, EdgeActorClass)>,
    pub(super) suppression_receipt: Option<ReceiptRecord>,
}

pub(super) fn execute_admitted<S: OutboundExecutionSink>(
    input: EffectInput<'_, S>,
) -> Result<DispatchVerdict, OutboundDispatchError> {
    let EffectInput {
        vault,
        request,
        sink,
        verb_contract,
        effect,
        payload,
        attempt_id,
        idempotency_supported,
        verified_actor,
        suppression_receipt,
    } = input;
    let prepared = crate::outbound_chokepoint::PreparedEffect {
        attempt_id,
        call_seq: 0,
        server: request.intent.channel.clone(),
        tool: verb_contract.kind.clone(),
        payload,
        idempotency_supported,
        resolved_endpoint: None,
        gate: effect,
        budget_class: crate::outbound_intent_ledger::BudgetClass::Send,
        authorization: crate::outbound_chokepoint::PreparedAuthorization::None,
        verified_actor,
        dedupe_key: request.intent.dedupe_key.clone(),
        suppression_receipt,
    };
    let authority = crate::outbound_consent::OutboundBindingAuthority::for_vault(vault)?;
    let mut transport = DispatchChokepointTransport::new(vault, request, verb_contract, sink);
    let effect_result = crate::outbound_chokepoint::execute_outbound_effect(
        vault,
        &authority,
        crate::outbound_chokepoint::OutboundEffectCommand::New(prepared),
        request.occurred_at,
        &mut transport,
    )
    .map_err(|error| match error {
        crate::outbound_intent_ledger::IntentLedgerError::InvalidBoundActor => {
            OutboundDispatchError::InvalidBoundActor
        }
        error => OutboundDispatchError::Chokepoint(error),
    })?;
    let gate_outcome = effect_result
        .gate_outcome
        .clone()
        .unwrap_or_else(|| "allow".to_owned());
    let gate_outcome_kind = match gate_outcome.as_str() {
        "allow" => GateOutcome::Allow,
        "pending" => GateOutcome::Pending,
        "deny" => GateOutcome::Deny,
        _ => {
            return Err(OutboundDispatchError::Engine(Error::InvariantViolation(
                "invalid chokepoint gate outcome",
            )));
        }
    };
    let resolution = effect_result.resolution;
    let outcome = if effect_result.dedupe_suppressed {
        OutboundDispatchOutcome::Suppressed
    } else {
        outbound_effect_outcome(resolution, transport.execution.as_ref(), gate_outcome_kind)
    };
    // A replay has no new decision id; never invent a non-queryable gate ref.
    Ok(DispatchVerdict {
        gate_decision_ref: effect_result.gate_decision_id,
        gate_outcome: gate_outcome_kind,
        gate_reason_codes: effect_result.gate_reason_codes,
        gate_receipt_reasons: effect_result.gate_receipt_reasons,
        effector_charge: effect_result.budget_charge,
        effect_state: effect_result.dispatch.state,
        resolution,
        outcome,
        execution: transport.execution,
        suppression_receipt: effect_result.suppression_receipt,
    })
}

/// Outcome naming consumes one ledger resolution. The execution result is
/// evidence about THIS attempt only while the logical send remains Pending.
fn outbound_effect_outcome(
    resolution: Option<IntentResolution>,
    execution: Option<&OutboundExecutionOutcome>,
    gate_outcome_kind: GateOutcome,
) -> OutboundDispatchOutcome {
    match resolution {
        Some(IntentResolution::Delivered) => OutboundDispatchOutcome::DeliveredToChannel,
        Some(IntentResolution::Stopped {
            delivery: UnconfirmedDelivery::Unresolved,
            ..
        }) => OutboundDispatchOutcome::Ambiguous,
        Some(IntentResolution::Stopped { .. }) => OutboundDispatchOutcome::Failed,
        Some(IntentResolution::Pending { .. }) => match execution {
            Some(execution) if execution.kind == OutboundExecutionOutcomeKind::Failed => {
                if execution.delivery_may_have_occurred {
                    OutboundDispatchOutcome::Ambiguous
                } else {
                    OutboundDispatchOutcome::Failed
                }
            }
            _ => OutboundDispatchOutcome::Held,
        },
        None if gate_outcome_kind == GateOutcome::Pending => OutboundDispatchOutcome::Held,
        None => OutboundDispatchOutcome::Suppressed,
    }
}
