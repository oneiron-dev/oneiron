//! Calendar/dispatch error mappers and outcome-name table.

use super::super::MemoryError;
use super::super::{MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE};
use crate::outbound::{OutboundDispatchError, OutboundDispatchOutcome};
/// Maps a calendar-layer verdict onto the facade error vocabulary.
///
/// A refusal is a `bad_request`, not an internal fault: the engine declining to
/// send a cold invite, an off-domain invite, or a SEQUENCE that does not
/// advance is the correct outcome, and the caller needs to see which law
/// refused. Store failures stay internal.
pub(super) fn facade_error_from_calendar(err: crate::calendar::CalendarError) -> MemoryError {
    match err {
        crate::calendar::CalendarError::InviteRefused { ref reason } => {
            MemoryError::bad_request_with(
                format!("calendar invite refused: {reason}"),
                &[
                    "Invite only after a yes: a prior thread or a confirmed booking grant.",
                    "Send from the primary calendar domain, and advance SEQUENCE on the same UID.",
                ],
            )
        }
        crate::calendar::CalendarError::ImipEmit { ref reason } => MemoryError::bad_request_with(
            format!("iMIP emit failure: {reason}"),
            &["Render the invitation with an explicit METHOD, UID, and zone label."],
        ),
        other => MemoryError::new(
            MEMORY_CODE_INTERNAL,
            format!("calendar invite failed: {other}"),
            &["Retry after checking local storage health."],
        ),
    }
}

pub(crate) fn facade_error_from_outbound_dispatch(err: OutboundDispatchError) -> MemoryError {
    match err {
        OutboundDispatchError::Engine(engine)
        | OutboundDispatchError::Chokepoint(
            crate::outbound_intent_ledger::IntentLedgerError::Engine(engine),
        ) => MemoryError::from(engine),
        OutboundDispatchError::Chokepoint(
            crate::outbound_intent_ledger::IntentLedgerError::InvalidInput(reason),
        ) => MemoryError::new(
            MEMORY_CODE_INVALID_STATE,
            reason,
            &["Refresh the current effect state before retrying."],
        ),
        OutboundDispatchError::Chokepoint(
            crate::outbound_intent_ledger::IntentLedgerError::InvalidBoundActor,
        ) => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "outbound actor is no longer authorized",
            &["Refresh the actor binding before retrying."],
        ),
        OutboundDispatchError::Chokepoint(_) => MemoryError::new(
            MEMORY_CODE_INTERNAL,
            "outbound effect durability failed",
            &["Retry after checking local storage health."],
        ),
        OutboundDispatchError::InvalidBoundActor => MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            "the bound actor is no longer authorized for outbound dispatch",
            &["Refresh the actor binding and retry."],
        ),
        OutboundDispatchError::UnsupportedCapability(capability) => MemoryError::bad_request_with(
            format!("unsupported outbound capability: {capability}"),
            &["Use a registered channel/verb pair from the connector manifest."],
        ),
    }
}

pub(super) const fn dispatch_outcome_str(outcome: &OutboundDispatchOutcome) -> &'static str {
    match outcome {
        OutboundDispatchOutcome::DeliveredToChannel => "delivered_to_channel",
        OutboundDispatchOutcome::Held => "held",
        OutboundDispatchOutcome::Degraded => "degraded",
        OutboundDispatchOutcome::Suppressed => "suppressed",
        OutboundDispatchOutcome::LetGo => "let_go",
        OutboundDispatchOutcome::Failed => "failed",
    }
}
