use oneiron::booking::agent_api::{BookingBookResult, BookingHoldInput, BookingOperationResponse};
use oneiron::booking::{ConstraintObject, SessionKey, SlotOracle, SolveRequest};
use oneiron::{EntityId, TimeRange};

use super::helpers::slot_range;
use super::lifecycle::booking_oracle;
use crate::error::ApiError;
use crate::server::SyncServer;

/// The oracle's verdict on the slot a hold names, taken before a token exists.
///
/// The hold verb records a soft hold; the re-solve that decides a CONTESTED
/// slot lives in confirm and reschedule, and stays there — a slot that was
/// offered and then went to someone else is the writer's call, not this one's.
/// But a slot the page never offered at all must not reach a lifecycle
/// credential: an invented interval would otherwise come back carrying a real
/// hold token, and the caller would learn one stage later that it was never
/// bookable.
///
/// So this asks the SAME oracle availability answers from, over exactly the
/// interval the caller selected, with this session's own live hold hidden — the
/// same exclusion the lifecycle applies — so a caller re-holding its own slot
/// is never refused by itself. Equality, not containment: the oracle's UTC
/// bounds are authoritative and nothing here rounds or widens them, and the
/// window is the caller's own slot, so this adds no window policy, no cap, and
/// no threshold of its own. It reads; it never writes and never decides what is
/// writable.
pub(super) fn unoffered_slot_answer(
    server: &SyncServer,
    page_ref: EntityId,
    input: &BookingHoldInput,
    constraint: Option<&ConstraintObject>,
    session_key: SessionKey,
    now: u64,
) -> Result<Option<BookingOperationResponse>, ApiError> {
    let slot = slot_range(input.selected_slot)?;
    let solved =
        booking_oracle(server, page_ref, Some(session_key), now)?.solve(&SolveRequest {
            event_type: input.event_type.clone(),
            window: offerability_window(slot),
            constraint: constraint.cloned(),
            visitor_tz: input.visitor_tz.clone(),
        })?;
    if solved
        .slots
        .iter()
        .any(|ranked| ranked.start_utc == slot.start && ranked.end_utc == slot.end)
    {
        return Ok(None);
    }
    // The same shape a taken slot returns from the writer, and for the same
    // reason: nothing was written, so this is a result rather than an error.
    // The alternatives are exactly what this solve saw inside the caller's own
    // interval; nothing here widens the window to look for more, because the
    // operation that answers "when else?" is availability, and there the caller
    // chooses the window itself.
    let taken = BookingBookResult::SlotTaken {
        alternatives: solved.slots,
    };
    Ok(Some(BookingOperationResponse::Book(taken)))
}

/// The inclusive solve window for one half-open slot.
///
/// [`SolveRequest::window`] is inclusive of its end instant, so the window that
/// means "exactly this slot" ends at the slot's last second. The caller's slot
/// has already passed [`slot_range`], so `end` is at least `start + 1`.
const fn offerability_window(slot: TimeRange) -> TimeRange {
    TimeRange {
        start: slot.start,
        end: slot.end.saturating_sub(1),
    }
}
