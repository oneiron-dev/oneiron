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

    /// The same normalized replay proof as ordinary dispatch, with the
    /// originating per-try observation as return evidence only.
    pub(crate) fn dispatch_outbound_intent_with_recorded_observation<S: OutboundExecutionSink>(
        &self,
        request: OutboundDispatchRequest,
        sink: &mut S,
        verified_actor: (EntityId, EdgeActorClass),
        key: crate::receipt::DispatchObservationKey,
        preflight: impl FnOnce() -> std::result::Result<(), OutboundDispatchError>,
    ) -> std::result::Result<super::RecordedDispatch, OutboundDispatchError> {
        OutboundDispatchPipeline.dispatch_with_recorded_observation(
            self,
            request,
            sink,
            verified_actor,
            key,
            preflight,
        )
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
