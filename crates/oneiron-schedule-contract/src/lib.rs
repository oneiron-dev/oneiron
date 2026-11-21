//! The Schedule vocabulary below the engine (DESIGN 15-setting-primitive section 1.3): a Schedule
//! is the engine's record that one job is due at one time. It holds no choice.
//!
//! This crate holds the pure part, with no store:
//! - [`Trigger`], when a job fires: once at a time, every so many seconds, or at a wall-clock
//!   time in an IANA zone on chosen days;
//! - the catch-up rule ([`Trigger::next_due`]): a schedule that is late runs once, then goes on
//!   from now, never once per missed occurrence; a one-off deadline still fires, late;
//! - [`retry_after`], the one backoff: 60 s after a failure by default, doubling with each failure
//!   in a row, capped at the smaller of the cadence and an hour;
//! - [`ZoneRules`], the wall-clock arithmetic a civil trigger needs, which the engine implements
//!   with its own time-zone database.

mod civil;
mod trigger;

pub use self::civil::{CivilDate, Weekday, ZoneRules};
pub use self::trigger::{RETRY_CAP_SECS, RETRY_FIRST_SECS, Ran, Trigger, retry_after};
