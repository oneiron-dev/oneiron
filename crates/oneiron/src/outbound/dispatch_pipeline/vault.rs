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
    /// frozen step identity follows the replay contract. New admission and
    /// Pending retry verify the step and resident restriction in the effect
    /// Gate transaction; terminal replay returns its recorded outcome first.
    pub fn dispatch_outbound_intent_from_step<S: OutboundExecutionSink>(
        &self,
        attempt_id: crate::attempt_queue::AttemptId,
        step_request: &crate::llm::LlmRequest,
        request: OutboundDispatchRequest,
        sink: &mut S,
    ) -> std::result::Result<OutboundDispatchResult, OutboundDispatchError> {
        let binding = crate::llm::StepEffectBinding::for_request(attempt_id, step_request)?;
        OutboundDispatchPipeline.dispatch_from_step(self, request, sink, binding)
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
