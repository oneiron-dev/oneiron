//! Shared recurrence vocabulary for commitments and ICS poll cadences.

use super::UnixTs;

use serde::{Deserialize, Serialize};

/// The window a [`Schedule::Quota`] counts its occurrences inside.
///
/// User-local by construction: a quota week is the week the OWNER lives in,
/// so the window carries its IANA zone rather than being derived from a
/// fixed 604800-second stride off the epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum QuotaWindow {
    /// The ISO-8601 week (Monday 00:00 local through the following Monday,
    /// exclusive) observed in `tz`.
    IsoWeek { tz: String },
}

/// How a commitment recurs.
///
/// `Rrule` is decodable in v1 but not evaluable: expansion belongs to the
/// calendar layer's single recurrence implementation, and a second parser
/// vendored behind this enum is exactly the fork this module exists to
/// prevent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Schedule {
    /// One occurrence at `due`, then done.
    Once { due: UnixTs },
    /// Every `period` seconds off the `anchor` grid.
    Interval { period: u64, anchor: UnixTs },
    /// `count` occurrences per `window`, no fixed instant within it.
    Quota { count: u32, window: QuotaWindow },
    /// An RFC 5545 recurrence rule, evaluated by the calendar layer.
    Rrule { rrule_string: String, tz: String },
}
