//! ONE-1817 [BK-06] booking anti-abuse route guards.
//!
//! The HTTP adapter over `oneiron::booking::anti_abuse`. The later BK-04 /
//! BK-08 slot-list, hold, book, and amend handlers call `enforce_*` BEFORE
//! touching the solver or lifecycle, and use the response-cache helpers when
//! they serve a listing; enforcement never moves below the route layer. Guards
//! thread `State<Arc<SyncServer>>` and fail as `crate::error::ApiError` —
//! no invented request state and no new server field: rows, counters, and
//! the cache all persist through `server.vault` under the booking-only meta
//! prefix owned by the engine.
//!
//! Behavioural law comes from the engine:
//! - honeypot and too-fast submissions leave as `SilentOk`, an HTTP 200
//!   shape indistinguishable from ordinary success, with no booking-side
//!   write and no revealing log;
//! - rate blocks are logged with hashed request keys only and surface as
//!   `RetryAfter` so the route can emit `Retry-After`;
//! - invalid email evidence prompts a correction rather than hard-blocking;
//! - borderline traffic is quarantined into a durable pending-review record
//!   and accepted, never silently deleted.

mod cache;
mod guards;
mod support;
#[cfg(test)]
mod tests_guards;
#[cfg(test)]
mod tests_quarantine;
#[cfg(test)]
mod tests_support;

pub(crate) use self::cache::{cached_slot_list_body, remember_slot_list_body};
pub(crate) use self::guards::{
    BookingHttpDisposition, enforce_amend, enforce_book, enforce_hold, enforce_slot_list,
};
