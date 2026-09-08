//! Recurrence series machinery (CAL-03).
//!
//! A recurring meeting is one master EVENT plus a rule. This module turns that
//! pair into concrete occurrence starts for a caller-chosen window, and nothing
//! else: it stores nothing, schedules nothing, and mints no graph.
//!
//! # Series links are claims
//!
//! Master, exception and successor are all EVENTs, related through the CAL-00
//! claim values in [`super::claims`] — `calendar.series_master`,
//! `calendar.series_exception`, `calendar.successor`. No `EdgeKind` and no
//! registry byte exists for any of them. "This and all following" is a
//! truncated master rule plus a new master whose replacement EVENT carries
//! `calendar.successor`; this module never writes either side.
//!
//! # Windowed, or not at all
//!
//! [`expand_window`] is the only expansion door and it always takes the
//! caller's inclusive [`TimeRange`]. There is no unbounded variant to reach
//! for: a recurrence rule without `COUNT` or `UNTIL` names infinitely many
//! occurrences, so "expand this series" is not a question with an answer.
//!
//! # The recurrence steps a wall clock
//!
//! RFC 5545 recurrence is civil arithmetic — "every Tuesday at 09:00" is a
//! statement about a wall clock, not about a fixed number of seconds. So the
//! rule is stepped over civil fields, and the IANA zone is applied exactly once
//! per occurrence, at the [`super::tz`] border. A weekly London series keeps
//! its 09:00 local hour across the March transition and moves an hour in UTC,
//! which is what its owner meant and what adding 604800 seconds would get
//! wrong.
//!
//! Handing the recurrence engine the zone itself instead would give it that
//! second job, and it discharges it by sliding a nonexistent local time into
//! the adjacent hour — the one outcome the border exists to prevent. Stepping
//! the wall clock and letting CAL-01 decide the instant is what keeps a
//! spring-forward gap a typed [`CalendarError::NonexistentWallTime`] and a
//! fall-back fold a resolved earliest-offset `Ok`.
//!
//! # Failure is never silence
//!
//! A malformed or unsupported rule, an inverted window, an unknown zone and a
//! gap are all typed errors. None of them is an empty vector: a caller that
//! cannot tell "this series has no occurrences here" from "this series could
//! not be expanded" will happily double-book the owner.
//!
//! The `rrule` crate and every chrono type stay private to this file. The
//! public surface is engine-owned scalars.

mod expansion;
mod keys;

pub use self::expansion::{expand_master_window, expand_window};
pub use self::keys::{
    SeriesDtStart, SeriesExceptionKey, exception_identity, mask_master_exceptions,
};

#[cfg(test)]
mod tests;
