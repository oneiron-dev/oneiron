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
    pub(super) owner_proof: Option<crate::consent::AuthenticatedOwner>,
    pub(super) parked: Option<OutboundDispatchOutcome>,
    /// The instant the seat's window reopens, when the seat's own policy
    /// parked this send (FIX 8813).
    pub(super) seat_held_until: Option<u64>,
    /// The seat's count bound, rechecked under the admission writer lock.
    pub(super) admission_ceiling: Option<crate::outbound_chokepoint::AdmissionCeiling>,
    pub(super) suppression_receipt: Option<ReceiptRecord>,
    /// The booking-page grant calendar admission bound to this invite, if any.
    pub(super) authorization: crate::outbound_chokepoint::PreparedAuthorization,
    /// A second actor the mutation speaks for (OF-427).
    pub(super) co_actor: Option<crate::outbound_chokepoint::CoActorAdmission>,
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
        owner_proof,
        parked,
        seat_held_until,
        admission_ceiling,
        suppression_receipt,
        authorization,
        co_actor,
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
        authorization,
        verified_actor,
        owner_proof,
        dedupe_key: request.intent.dedupe_key.clone(),
        suppression_receipt,
        admission_ceiling: if parked.is_none() {
            admission_ceiling
        } else {
            None
        },
        co_actor,
    };
    let authority = crate::outbound_consent::OutboundBindingAuthority::for_vault(vault)?;
    let mut transport = DispatchChokepointTransport::new(vault, request, verb_contract, sink);
    let effect_result = crate::outbound_chokepoint::execute_outbound_effect(
        vault,
        &authority,
        match parked {
            Some(_) => crate::outbound_chokepoint::OutboundEffectCommand::Park(prepared),
            None => crate::outbound_chokepoint::OutboundEffectCommand::New(prepared),
        },
        request.occurred_at,
        &mut transport,
    )
    .map_err(|error| match error {
        crate::outbound_intent_ledger::IntentLedgerError::InvalidBoundActor => {
            OutboundDispatchError::InvalidBoundActor
        }
        crate::outbound_intent_ledger::IntentLedgerError::FailureResultIneligible => {
            OutboundDispatchError::FailureResultIneligible
        }
        crate::outbound_intent_ledger::IntentLedgerError::Step(error) => {
            OutboundDispatchError::Step(error)
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
    // FIX 7964, 8818: what the ledger keeps beside this send's row. A read
    // that fails after a send never fails the dispatch: the receipt then
    // carries neither field, as before them.
    let settlement = match effect_result.dispatch.intent_id {
        Some(id) if effect_result.dispatch.state.is_some() => {
            crate::outbound_intent_ledger::intent_settlement(vault, &id).unwrap_or_else(|error| {
                tracing::warn!(
                    reason = "outbound_settlement_unread",
                    %error,
                    "an outbound send's settlement row did not read; its receipt omits it"
                );
                Default::default()
            })
        }
        _ => Default::default(),
    };
    let held_by_provider_wait = effect_result
        .gate_receipt_reasons
        .iter()
        .any(|reason| reason == crate::outbound_chokepoint::PROVIDER_WAIT_REASON);
    let provider_wait_held_until = settlement
        .provider_wait
        .and_then(|wait| wait.not_before)
        .filter(|_| held_by_provider_wait);
    // A ceiling reached under the writer lock parks the send as Held, and so
    // does a full window that paces it (FIX 7948).
    let parked = parked.or(effect_result
        .ceiling_count
        .map(|_| OutboundDispatchOutcome::Held)
        .or(effect_result
            .paced_until
            .map(|_| OutboundDispatchOutcome::Held)));
    let outcome = if effect_result.dedupe_suppressed {
        OutboundDispatchOutcome::Suppressed
    } else {
        outbound_effect_outcome(
            resolution,
            transport.execution.as_ref(),
            gate_outcome_kind,
            parked,
        )
    };
    // FIX 8813: a send its seat's own policy parked waits for the seat's
    // window to reopen as a full window paces a send: Held, coming back at
    // that instant. FIX 8791: so does a send the connector's own seat policy
    // held before its provider call.
    let paced_until = effect_result.paced_until.or_else(|| {
        if outcome != OutboundDispatchOutcome::Held {
            return None;
        }
        seat_held_until
            .filter(|_| gate_outcome_kind == GateOutcome::Allow)
            .or_else(|| {
                transport
                    .execution
                    .as_ref()
                    .and_then(|execution| execution.hold.as_ref())
                    .and_then(|hold| hold.until)
            })
    });
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
        ceiling_count: effect_result.ceiling_count,
        held_approval_digest: effect_result.approval_digest,
        held_approval_actor: effect_result.approval_actor,
        provider_wait: settlement.provider_wait,
        provider_wait_held_until,
        paced_until,
        budget_reservation: settlement.reservation.map(|reservation| reservation.status),
    })
}

/// Outcome naming consumes one ledger resolution. The execution result is
/// evidence about THIS attempt only while the logical send remains Pending.
fn outbound_effect_outcome(
    resolution: Option<IntentResolution>,
    execution: Option<&OutboundExecutionOutcome>,
    gate_outcome_kind: GateOutcome,
    parked: Option<OutboundDispatchOutcome>,
) -> OutboundDispatchOutcome {
    match resolution {
        Some(IntentResolution::Delivered) => OutboundDispatchOutcome::DeliveredToChannel,
        Some(IntentResolution::Deferred) => OutboundDispatchOutcome::Deferred,
        Some(IntentResolution::Stopped {
            delivery: UnconfirmedDelivery::Unresolved,
            ..
        }) => OutboundDispatchOutcome::Ambiguous,
        Some(IntentResolution::Stopped { .. }) => OutboundDispatchOutcome::Failed,
        Some(IntentResolution::Pending { .. }) if parked.is_some() => parked.expect("matched Some"),
        Some(IntentResolution::Pending { .. }) => match execution {
            Some(execution) if execution.kind == OutboundExecutionOutcomeKind::Failed => {
                if execution.delivery_may_have_occurred {
                    OutboundDispatchOutcome::Ambiguous
                } else if execution.hold.is_some() {
                    // FIX 8791: the connector's own seat policy held it
                    // before any provider call; it stays queued.
                    OutboundDispatchOutcome::Held
                } else {
                    OutboundDispatchOutcome::Failed
                }
            }
            _ => OutboundDispatchOutcome::Held,
        },
        None if gate_outcome_kind == GateOutcome::Pending => OutboundDispatchOutcome::Held,
        None if gate_outcome_kind == GateOutcome::Allow && parked.is_some() => {
            parked.expect("matched Some")
        }
        None => OutboundDispatchOutcome::Suppressed,
    }
}
