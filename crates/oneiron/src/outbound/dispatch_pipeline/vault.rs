//! Vault facade seams for dispatching outbound intents.
use super::OutboundDispatchPipeline;
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::outbound::dispatch_types::{
    OutboundDispatchError, OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionSink,
};
impl Vault {
    /// Dispatch an effect derived from a completed durable LLM step. The
    /// response is verified against the local step checkpoint and resident
    /// failure rule BEFORE outbound preparation; a permissive row still goes
    /// through the ordinary Gate, consent, budget and replay doors.
    pub fn dispatch_outbound_intent_from_step<S: OutboundExecutionSink>(
        &self,
        attempt_id: crate::attempt_queue::AttemptId,
        step_request: &crate::llm::LlmRequest,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let effect_actor = request
            .actor
            .actor_entity_ref
            .ok_or(OutboundDispatchError::InvalidBoundActor)?;
        if !crate::llm::verified_step_effector_eligible(
            self,
            attempt_id,
            step_request,
            effect_actor,
        )? {
            return Err(OutboundDispatchError::FailureResultIneligible);
        }
        self.dispatch_outbound_intent(request, sink)
    }

    pub fn dispatch_outbound_intent<S: OutboundExecutionSink>(
        &self,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        OutboundDispatchPipeline.dispatch(self, request, sink)
    }

    /// Facade-only dispatch seam: asserts the actor still resolves in the
    /// Gate transaction that persists this outbound decision.
    pub(crate) fn dispatch_outbound_intent_with_verified_actor<S: OutboundExecutionSink>(
        &self,
        request: OutboundDispatchRequest,
        sink: &mut S,
        actor: EntityId,
        actor_class: EdgeActorClass,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        OutboundDispatchPipeline.dispatch_with_verified_actor(
            self,
            request,
            sink,
            actor,
            actor_class,
        )
    }
}
