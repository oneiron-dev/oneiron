//! The ambient alternative of a degraded interrupt (FIX 7962): when the
//! delivery window degrades an interrupt to the surface its host bound an
//! alternative for, that alternative goes as a send of its own, through the
//! same pipeline, Gate, budget and ledger, under its own receipt. The
//! interrupt stays parked as Degraded and its receipt names the alternative
//! and what came of it. With no bound alternative it parks as before, its
//! receipt saying the alternative is unresolved.

use super::pipeline::OutboundDispatchPipeline;
use crate::Vault;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::outbound::dispatch_types::{
    OutboundDispatchOutcome, OutboundDispatchRequest, OutboundDispatchResult, OutboundExecutionSink,
};
use crate::outbound::{OutboundAmbientAlternative, OutboundDeliveryWindowDecision};

/// Receipt field naming the surface the interrupt degraded to.
const ALTERNATIVE_SURFACE_FIELD: &str = "alternative_surface";
/// Receipt field naming the alternative's own intent ref.
const ALTERNATIVE_INTENT_REF_FIELD: &str = "alternative_intent_ref";
/// Receipt field naming the alternative's own receipt.
const ALTERNATIVE_RECEIPT_REF_FIELD: &str = "alternative_receipt_ref";
/// Receipt field naming what came of the alternative: its dispatch outcome,
/// [`ALTERNATIVE_UNRESOLVED`] or [`ALTERNATIVE_DISPATCH_ERROR`].
pub(in crate::outbound) const ALTERNATIVE_OUTCOME_FIELD: &str = "alternative_outcome";
/// The degraded interrupt has no alternative bound for its surface.
const ALTERNATIVE_UNRESOLVED: &str = "unresolved";
/// The alternative's dispatch failed before it came to an outcome.
const ALTERNATIVE_DISPATCH_ERROR: &str = "dispatch_error";
/// The segment an alternative's identities derive under, after its parent's
/// and before its surface: one alternative per interrupt and surface, the
/// same on every retry of that interrupt.
const AMBIENT_ALTERNATIVE_REF_SEGMENT: &str = "ambient";

/// The alternative's own request: its intent and counterparty, the
/// interrupt's actor, gate facts, clock and session, and identities derived
/// from the interrupt's and the surface. It binds no alternative of its own.
fn ambient_alternative_request(
    parent: &OutboundDispatchRequest,
    alternative: &OutboundAmbientAlternative,
) -> OutboundDispatchRequest {
    let derive = |id: &str| {
        format!(
            "{id}:{AMBIENT_ALTERNATIVE_REF_SEGMENT}:{}",
            alternative.surface
        )
    };
    let mut request = OutboundDispatchRequest::new(
        derive(&parent.receipt_id),
        derive(&parent.intent_ref),
        alternative.intent.clone(),
        parent.actor.clone(),
        parent.gate,
        parent.occurred_at,
        OutboundDeliveryWindowDecision::DeliverNow,
    );
    request.ledger_identity_ref = parent.ledger_identity_ref.as_deref().map(derive);
    request.counterparty_ref = alternative.counterparty_ref.clone();
    request.originating_session_ref = parent.originating_session_ref.clone();
    request.active_delivery_contexts = parent.active_delivery_contexts.clone();
    request.delivery_window_subject_ref = parent.delivery_window_subject_ref;
    request.delivery_window_local_minute_of_day = parent.delivery_window_local_minute_of_day;
    request.delivery_window_clock = parent.delivery_window_clock;
    request.delivery_window_human_explicit_instant = parent.delivery_window_human_explicit_instant;
    request
}

/// Sends a degraded interrupt's bound alternative and names it on the
/// interrupt's receipt. Runs only for a Degraded result. The alternative's
/// receipt is filed once, as a direct dispatch's; an alternative whose
/// dispatch errs leaves the interrupt parked as it would be with none.
pub(super) fn dispatch_ambient_alternative<S: OutboundExecutionSink>(
    pipeline: OutboundDispatchPipeline,
    vault: &Vault,
    parent: &OutboundDispatchRequest,
    window_decision: &OutboundDeliveryWindowDecision,
    verified_actor: Option<(EntityId, EdgeActorClass)>,
    sink: &mut S,
    result: &mut OutboundDispatchResult,
) {
    if result.outcome != OutboundDispatchOutcome::Degraded {
        return;
    }
    let fields = &mut result.receipt.fields;
    let alternative = match (window_decision, parent.ambient_alternative.as_deref()) {
        (OutboundDeliveryWindowDecision::Degrade { to, .. }, Some(alternative))
            if alternative.surface == *to =>
        {
            alternative
        }
        _ => {
            fields.insert(
                ALTERNATIVE_OUTCOME_FIELD.to_owned(),
                ALTERNATIVE_UNRESOLVED.to_owned(),
            );
            return;
        }
    };
    let request = ambient_alternative_request(parent, alternative);
    fields.insert(
        ALTERNATIVE_SURFACE_FIELD.to_owned(),
        alternative.surface.clone(),
    );
    fields.insert(
        ALTERNATIVE_INTENT_REF_FIELD.to_owned(),
        request.intent_ref.clone(),
    );
    let dispatched = pipeline
        .dispatch_inner(vault, request, sink, verified_actor, None)
        .and_then(|child| {
            crate::receipt::record_direct_dispatch_receipt(vault, child.receipt.clone())?;
            Ok(child)
        });
    match dispatched {
        Ok(child) => {
            fields.insert(
                ALTERNATIVE_RECEIPT_REF_FIELD.to_owned(),
                child.receipt.receipt_id.clone(),
            );
            fields.insert(
                ALTERNATIVE_OUTCOME_FIELD.to_owned(),
                child.outcome.as_str().to_owned(),
            );
        }
        Err(error) => {
            tracing::warn!(
                reason = "ambient_alternative_not_dispatched",
                %error,
                "a degraded interrupt's ambient alternative did not dispatch; the interrupt stays parked"
            );
            fields.insert(
                ALTERNATIVE_OUTCOME_FIELD.to_owned(),
                ALTERNATIVE_DISPATCH_ERROR.to_owned(),
            );
        }
    }
}
