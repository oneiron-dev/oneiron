//! Vault facade seams for dispatching outbound intents.
use super::OutboundDispatchPipeline;
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::outbound::dispatch_types::{
    OutboundDispatchError, OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionSink,
};
impl Vault {
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
