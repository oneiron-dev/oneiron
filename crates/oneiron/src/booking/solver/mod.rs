//! ONE-1823 [BK-00] availability solver and slot-mask projection.
//!
//! [`BookingSolver`] is the real [`SlotOracle`]: it binds a vault, a booking
//! page, the request-time host→calendar selector binding, and a request-time
//! `now_utc`, then runs one deterministic, side-effect-free pipeline of eight
//! pure stages, in this order:
//!
//! 1. `working_hours_mask` — host wall windows become UTC intervals.
//! 2. `attach_busy_union` — CAL's normalized busy union joins each host.
//! 3. `apply_buffers` — busy intervals grow by the required meeting gap.
//! 4. `enforce_notice_and_window` — minimum notice and booking horizon clip.
//! 5. `apply_event_type_knobs` — candidates are cut on the step grid and
//!    charged against the visitor-local daily/weekly caps.
//! 6. `subtract_live_holds` — unexpired holds remove candidates.
//! 7. `route_host_masks` — `Either` unions the hosts, `Both` intersects them.
//! 8. `rank_and_emit` — the visitor's constraint filters, the ranking orders,
//!    and the result leaves in UTC.
//!
//! Every stage is a pure function of its arguments. Storage and the network are
//! touched exactly once each, before stage 1, so the pipeline is reproducible
//! from its inputs alone.
//!
//! # Bounded work
//!
//! Stage 4's rule is settled BEFORE those reads, not only during them: the
//! caller's window is untrusted request data and may span centuries, while the
//! booking horizon is configuration and is bounded by
//! [`MAX_BOOKING_WINDOW_SECS`](crate::booking::config::MAX_BOOKING_WINDOW_SECS).
//! Clipping first is what keeps one solve's freebusy query, hold read, and
//! per-local-day walk proportional to the page's own horizon.
//!
//! # Interval convention
//!
//! [`TimeRange`] is inclusive on both ends in the engine core, and every
//! interval crossing a stage boundary HERE is half-open `[start, end)` — the
//! convention CAL's [`BusyInterval`](crate::calendar::BusyInterval) and the
//! seam's [`SlotMask`] already use. The conversion therefore happens exactly
//! twice: once when [`SolveRequest::window`] is ingested, and once when the
//! window is handed back to CAL's `freebusy`. Nothing in between mixes the two.
//!
//! # Time zones
//!
//! The core is `u64` UTC. Every IANA conversion goes through
//! [`crate::calendar::tz`], the engine's one border, so no third-party time
//! type appears in any signature here. Host wall windows convert forward
//! ([`wall_to_utc`]); visitor-local placement — caps, constraint weekdays and
//! local windows — converts backward ([`utc_to_wall`]), which is total and so
//! never invents an instant.

mod civil_date;
mod counts;
mod hold_source;
mod interval;
mod oracle;
mod stages;
#[cfg(test)]
mod tests;

pub(crate) use self::counts::load_booking_counts;
pub use self::counts::{BookingCountBucket, BookingCounts};
pub use self::hold_source::{ActiveHoldSource, NoActiveHolds};
pub use self::interval::slot_mask;
pub use self::oracle::BookingSolver;

// The inline `mod tests` used to see these names through the flat file's own
// import header plus every solver-internal item. After the directory split the
// seam re-imports both so `tests.rs` resolves exactly as it did before.
#[cfg(test)]
use self::stages::*;
#[cfg(test)]
use crate::booking::config::{EventTypeConfig, MINUTES_PER_DAY, RoutingMode};
#[cfg(test)]
use crate::booking::constraint::ConstraintWeekday;
#[cfg(test)]
use crate::booking::{
    BookingError, ConstraintObject, EventTypeKey, RankedSlot, SlotHostBinding, SolveRequest,
    SolveResult,
};
#[cfg(test)]
use crate::entity_id::EntityId;
#[cfg(test)]
use crate::temporal::TimeRange;
