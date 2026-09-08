//! Calendar scoped-read surface (read/search/freebusy) plus the invite entry point.

use serde::{Deserialize, Serialize};

use super::super::support::{Memory, verify_actor_binding};
use super::super::{MemoryError, MemoryResult};
use super::invite::CalendarInviteSurfaceInput;
use super::types::{OutboundIntentReceipt, OutboundScheduleContext};
use crate::calendar::{
    CalendarEventView, CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest, CalendarSel,
};
use crate::temporal::TimeRange;
/// One source-redacted busy interval, half-open `[start_utc, end_utc)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarFreebusyIntervalDto {
    /// Inclusive half-open start, Unix seconds.
    pub start_utc: u64,
    /// Exclusive half-open end, Unix seconds.
    pub end_utc: u64,
}

/// External freebusy projection: occupancy only.
pub type CalendarFreebusyDto = Vec<CalendarFreebusyIntervalDto>;

/// Rejects an inverted calendar window at the surface boundary.
fn validate_calendar_range(range: Option<CalendarRangeDto>) -> MemoryResult<()> {
    match range {
        Some(range) if !range.is_ordered() => Err(MemoryError::bad_request_with(
            "calendar range start must not exceed end",
            &["Pass an inclusive range with start <= end."],
        )),
        _ => Ok(()),
    }
}

impl Memory<'_> {
    // ── calendar (CAL-09) ───────────────────────────────────────────────

    /// The bound actor's scoped-read lane.
    ///
    /// Calendar bodies are imported foreign content, so this surface reads them
    /// through the policy scoped-read lane rather than raw vault reads: an
    /// actor's calendar view is always a subset of the internal projection.
    fn calendar_read_lane(&self) -> MemoryResult<crate::claim::ScopedRead<'_>> {
        let key = crate::claim::ScopedReadActorKey::with_actor_class(
            self.actor.to_hex(),
            self.actor_class.gate_actor_class(),
        )
        .ok_or_else(|| {
            MemoryError::bad_request("bound actor cannot be used as a scoped read key")
        })?;
        Ok(self.vault.scoped_read(key))
    }

    /// Reads one calendar EVENT under the caller's read scope.
    pub fn calendar_read(
        &self,
        req: &CalendarReadRequest,
    ) -> MemoryResult<Option<CalendarEventView>> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        Ok(crate::calendar::read_event_scoped(
            &self.calendar_read_lane()?,
            req,
        )?)
    }

    /// Searches calendar EVENTs under the caller's read scope.
    pub fn calendar_search(
        &self,
        req: &CalendarSearchRequest,
    ) -> MemoryResult<Vec<CalendarEventView>> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        validate_calendar_range(req.range)?;
        Ok(crate::calendar::search_events_scoped(
            &self.calendar_read_lane()?,
            req,
        )?)
    }

    /// Projects busy-only occupancy over `range`, source-redacted.
    ///
    /// The internal `BusyInterval` keeps a representative `source` EVENT for
    /// engine consumers; this external DTO drops it, so an SDK or MCP caller
    /// receives occupancy and nothing else — no name, description, attendee,
    /// meeting link, or entity ref.
    pub fn calendar_freebusy(
        &self,
        calendars: &[CalendarSel],
        range: TimeRange,
    ) -> MemoryResult<CalendarFreebusyDto> {
        verify_actor_binding(self.vault, self.actor, self.actor_class)?;
        if range.start > range.end {
            return Err(MemoryError::bad_request_with(
                "calendar freebusy range start must not exceed end",
                &["Pass an inclusive range with start <= end."],
            ));
        }
        let union =
            crate::calendar::freebusy_scoped(&self.calendar_read_lane()?, calendars, range)?;
        Ok(union
            .into_iter()
            .map(|interval| CalendarFreebusyIntervalDto {
                start_utc: interval.start_utc,
                end_utc: interval.end_utc,
            })
            .collect())
    }

    /// Schedules one iMIP-shaped calendar invite through the ordinary outbound
    /// gate.
    ///
    /// The public input is C7's exact five-field payload, never an
    /// [`OutboundDraftInput`]: this surface owns the invite vocabulary and
    /// constructs the generic draft internally, so no caller can hand-roll a
    /// draft that bypasses the invite contract. Delivery is never performed
    /// here — the ordinary schedule path is the only route, and the invite's
    /// UID/SEQUENCE law plus its vault-only hygiene rows are checked at that
    /// chokepoint (CAL-04, ONE-1786) before the gate ever sees the send.
    ///
    /// Nothing about hygiene is an argument here: the five fields below are the
    /// whole public input, and every consent, binding, and sender-domain fact
    /// is read from the vault at the chokepoint. A caller cannot assert its way
    /// past a cold-invite refusal.
    pub fn calendar_invite(
        &self,
        input: &CalendarInviteSurfaceInput,
    ) -> MemoryResult<OutboundIntentReceipt> {
        input.validate()?;
        self.schedule_outbound_inner(
            &input.outbound_draft(),
            &OutboundScheduleContext::default(),
            Some(&input.frozen_payload()),
        )
    }
}
