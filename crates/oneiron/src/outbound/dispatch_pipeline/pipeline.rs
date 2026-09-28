//! O2 dispatch: shared request preparation, ledger replay, execution and receipts.
use super::request_binding::{FrozenDispatchIdentity, PreparedOutboundDispatch};
use crate::edge::EdgeActorClass;
use crate::error::Error;
use crate::outbound::dispatch_types::{
    OutboundDispatchError, OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionSink,
};
use crate::receipt::{DispatchObservationKey, read_dispatch_observation};
use crate::{EntityId, Vault};

#[derive(Clone, Copy, Debug, Default)]
pub struct OutboundDispatchPipeline;

pub(crate) struct RecordedDispatch {
    pub(crate) result: OutboundDispatchResult,
    pub(crate) identity: Option<FrozenDispatchIdentity>,
    pub(crate) replayed: bool,
}
impl OutboundDispatchPipeline {
    pub fn dispatch<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> Result<OutboundDispatchResult, OutboundDispatchError> {
        self.dispatch_inner(vault, request, sink, None, None)
    }
    pub(in crate::outbound) fn dispatch_from_step<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut S,
        binding: crate::llm::StepEffectBinding,
    ) -> Result<OutboundDispatchResult, OutboundDispatchError> {
        self.dispatch_inner(vault, request, sink, None, Some(binding))
    }
    pub(in crate::outbound) fn dispatch_with_verified_actor<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut S,
        actor: EntityId,
        actor_class: EdgeActorClass,
    ) -> Result<OutboundDispatchResult, OutboundDispatchError> {
        self.dispatch_inner(vault, request, sink, Some((actor, actor_class)), None)
    }
    fn dispatch_inner<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut S,
        verified_actor: Option<(EntityId, EdgeActorClass)>,
        step_binding: Option<crate::llm::StepEffectBinding>,
    ) -> Result<OutboundDispatchResult, OutboundDispatchError> {
        let prepared =
            PreparedOutboundDispatch::prepare(vault, request, verified_actor, step_binding)?;
        Ok(self.dispatch_prepared(vault, prepared, sink)?.result)
    }
    /// Observations are response evidence only. Even an exact stored success
    /// must first pass the SAME replay-aware sender/frozen-payload validator
    /// that ordinary dispatch uses. Only the OF-327 ledger's Done state may
    /// turn that evidence into a completed result.
    pub(crate) fn dispatch_with_recorded_observation<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        request: OutboundDispatchRequest,
        sink: &mut S,
        verified_actor: (EntityId, EdgeActorClass),
        key: DispatchObservationKey,
        preflight: impl FnOnce() -> Result<(), OutboundDispatchError>,
    ) -> Result<RecordedDispatch, OutboundDispatchError> {
        let mut prepared =
            PreparedOutboundDispatch::prepare(vault, request, Some(verified_actor), None)?;
        if prepared.replay_done() {
            prepared.freeze_and_validate(vault)?;
            if let Some(observation) = read_dispatch_observation(vault, key)? {
                let identity = prepared
                    .identity()
                    .ok_or(Error::InvariantViolation("missing frozen outbound replay"))?;
                if observation.identity() != Some(&identity)
                    || observation.receipt_id() != prepared.request.receipt_id
                    || observation.occurred_at() != prepared.request.occurred_at
                {
                    return Err(super::request_binding::invalid_replay());
                }
                return Ok(RecordedDispatch {
                    result: observation.result()?,
                    identity: Some(identity),
                    replayed: true,
                });
            }
        }
        if prepared.replay_done() {
            return self.dispatch_completed_effect(vault, prepared, sink);
        }
        preflight()?;
        self.dispatch_prepared(vault, prepared, sink)
    }
    /// Recovery after the effect committed but before its observation did:
    /// OF-327's validated Done record answers without consulting today's
    /// window/seat or emitting a second gate decision or sink call.
    fn dispatch_completed_effect<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        mut prepared: PreparedOutboundDispatch,
        sink: &mut S,
    ) -> Result<RecordedDispatch, OutboundDispatchError> {
        prepared.freeze_and_validate(vault)?;
        let identity = prepared.identity();
        let PreparedOutboundDispatch {
            request,
            verb_contract,
            attempt_id,
            idempotency_supported,
            verified_actor,
            space_posting,
            policy_risk,
            payload,
            ..
        } = prepared;
        let effect = super::govern::gate_input(&request, verb_contract, policy_risk);
        let verdict = super::effect::execute_admitted(super::effect::EffectInput {
            vault,
            request: &request,
            sink,
            verb_contract,
            effect,
            payload: payload.ok_or(Error::InvariantViolation("missing replay payload"))?,
            attempt_id,
            idempotency_supported,
            verified_actor,
            suppression_receipt: None,
        })?;
        let result = crate::outbound::receipt_fields::dispatch_result_receipt(
            &request,
            verb_contract,
            policy_risk,
            space_posting.as_ref(),
            None,
            verdict,
        );
        Ok(RecordedDispatch {
            result,
            identity,
            replayed: false,
        })
    }
    fn dispatch_prepared<S: OutboundExecutionSink>(
        self,
        vault: &Vault,
        mut prepared: PreparedOutboundDispatch,
        sink: &mut S,
    ) -> Result<RecordedDispatch, OutboundDispatchError> {
        let verb_contract = prepared.verb_contract;
        let window_resolution =
            crate::outbound::window_door::outbound_delivery_window_resolution_at_door(
                vault,
                &prepared.request,
                verb_contract,
            )?;
        let window_decision =
            crate::outbound::window_door::outbound_delivery_window_decision_at_door(
                &prepared.request,
                &window_resolution,
            );
        crate::outbound::window_door::apply_apns_window_cap(
            &mut prepared.request,
            &window_decision,
        );
        let admission = super::admission::AdmissionStage::evaluate(
            &prepared.request,
            verb_contract,
            window_resolution,
            window_decision,
        );
        if matches!(
            admission.decision,
            super::admission::DispatchAdmission::Execute
        ) || prepared.replay.is_some()
        {
            prepared.freeze_and_validate(vault)?;
        }
        let identity = prepared.identity();
        let PreparedOutboundDispatch {
            request,
            verb_contract,
            attempt_id,
            idempotency_supported,
            verified_actor,
            space_posting,
            policy_risk,
            payload,
            ..
        } = prepared;
        let effect = super::govern::gate_input(&request, verb_contract, policy_risk);
        let verdict = match admission.decision {
            super::admission::DispatchAdmission::Execute => {
                super::effect::execute_admitted(super::effect::EffectInput {
                    vault,
                    request: &request,
                    sink,
                    verb_contract,
                    effect,
                    payload: payload.ok_or(Error::InvariantViolation(
                        "admitted dispatch has no frozen payload",
                    ))?,
                    attempt_id,
                    idempotency_supported,
                    verified_actor,
                    suppression_receipt:
                        crate::outbound::receipt_fields::suppression_receipt_for_dispatch(
                            &request,
                            &admission.window_decision,
                            &admission.window_resolution,
                        ),
                })?
            }
            super::admission::DispatchAdmission::Park { outcome } => super::govern::govern_parked(
                vault,
                &request,
                &effect,
                verified_actor,
                space_posting.as_ref(),
                outcome,
            )?,
        };
        let result = crate::outbound::receipt_fields::dispatch_result_receipt(
            &request,
            verb_contract,
            policy_risk,
            space_posting.as_ref(),
            Some(&admission),
            verdict,
        );
        Ok(RecordedDispatch {
            result,
            identity,
            replayed: false,
        })
    }
}
