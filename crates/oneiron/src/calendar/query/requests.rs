//! Dependency-free serde request/response DTOs.

use crate::temporal::TimeRange;

/// Upper bound on one `calendar.search` page, mirroring the bounded-list
/// convention the rest of the read surface uses.
pub const MAX_CALENDAR_SEARCH_LIMIT: u32 = 200;

#[doc(hidden)]
pub use oneiron_verb_wire::calendar::query::requests::{
    CalendarEventView, CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest, CalendarSel,
};
