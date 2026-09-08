//! Calendar EVENT query + projection core (CAL-09).
//!
//! There is no second calendar store: an EVENT's occurrence is the indexed UTC
//! interval already carried by its entity header (`occurred_start`/
//! `occurred_end`, the same pair `pipeline`'s temporal retrieval scores), and
//! everything calendar-specific is a `calendar.*` claim minted by CAL-00. This
//! module reads those two sources and projects them; it mints nothing.
//!
//! Read admission is the existing claim rule, not a calendar-local one. Every
//! claim this module consults passes through [`CalendarRead`], whose two arms
//! are the two lanes the engine already has:
//!
//! * [`CalendarRead::Vault`] — the internal lane. Applies
//!   `claim_surfaceable`, so proposed, rejected, superseded, retracted, and
//!   stale claims never become calendar truth.
//! * [`CalendarRead::Scoped`] — the actor lane behind [`crate::Memory`]
//!   and every foreign surface. [`ScopedRead`] applies `claim_surfaceable`
//!   *and* the policy scoped-read grants, so an actor's calendar view can only
//!   ever be a subset of the internal one.
//!
//! Deliberately deferred: `CalendarSel.system` selection waits on CAL-02's
//! passport index (ONE-1784 lands after this ticket), and recurrence expansion
//! waits on CAL-03 (ONE-1785). Both are documented at their call sites rather
//! than faked here.

mod facts;
mod requests;
mod service;

pub use self::facts::CalendarRead;
pub(crate) use self::facts::visit_calendar_events;
pub use self::requests::{
    CalendarEventView, CalendarRangeDto, CalendarReadRequest, CalendarSearchRequest, CalendarSel,
    MAX_CALENDAR_SEARCH_LIMIT,
};
pub(crate) use self::service::validate_selectors;
pub use self::service::{read_event, read_event_scoped, search_events, search_events_scoped};

#[cfg(test)]
mod tests;

// The flat query.rs module used to provide these names to the sibling test
// module through `use super::*`. The query-internal items the tests name bare
// already flow through the seam re-exports above; only the private crate/std
// import header needs re-importing here so `tests.rs` resolves as before.
#[cfg(test)]
use crate::calendar::claims::{PREDICATE_CALENDAR_STATUS, PREDICATE_CALENDAR_TIME_KIND};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::registry::ENTITY_TYPE_EVENT;
#[cfg(test)]
use crate::temporal::TimeRange;
#[cfg(test)]
use crate::vault::Vault;
#[cfg(test)]
use rmpv::Value;
