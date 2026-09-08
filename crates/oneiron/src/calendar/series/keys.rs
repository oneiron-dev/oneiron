//! Borrowed series/exception identity keys and occurrence masking.

use std::collections::BTreeSet;

use crate::calendar::claims::{CalendarSeriesExceptionValue, CalendarSeriesMasterValue};
use crate::entity_id::EntityId;

/// The two fields a recurrence needs from its master, without the claim.
///
/// Carries exactly `dtstart_utc` and the IANA zone name, borrowed, so callers
/// that hold a decoded [`CalendarSeriesMasterValue`] and callers that hold the
/// two scalars can both reach the same door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeriesDtStart<'a> {
    /// Series start instant, UTC seconds.
    pub dtstart_utc: u64,
    /// IANA zone the recurrence's wall clock belongs to.
    pub tz: &'a str,
}

impl<'a> From<&'a CalendarSeriesMasterValue> for SeriesDtStart<'a> {
    fn from(master: &'a CalendarSeriesMasterValue) -> Self {
        Self {
            dtstart_utc: master.dtstart_utc,
            tz: &master.tz,
        }
    }
}

/// The full identity of a series exception: `(uid, original_start_utc)`.
///
/// Both fields are borrowed from the [`CalendarSeriesExceptionValue`] that
/// carries them, never sourced separately. The pair is the identity because a
/// start alone is not one — two unrelated series can begin at the same instant,
/// and masking on the start would delete one series' occurrence because another
/// series had an exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SeriesExceptionKey<'a> {
    /// Series UID, as the source expressed it.
    pub uid: &'a str,
    /// The occurrence start this exception replaces.
    pub original_start_utc: u64,
}

impl<'a> From<&'a CalendarSeriesExceptionValue> for SeriesExceptionKey<'a> {
    fn from(exception: &'a CalendarSeriesExceptionValue) -> Self {
        Self {
            uid: &exception.uid,
            original_start_utc: exception.original_start_utc,
        }
    }
}

/// Borrows an exception's full identity out of the claim value carrying it.
#[must_use]
pub fn exception_identity(exception: &CalendarSeriesExceptionValue) -> SeriesExceptionKey<'_> {
    SeriesExceptionKey::from(exception)
}

/// Removes this master's overridden occurrences from a generated start stream.
///
/// Exceptions are scoped to `master_ref` first, then matched on the full
/// `(uid, original_start_utc)` key. A coincident start belonging to another
/// series survives, because only its own exception can remove it.
///
/// The removed occurrences do not vanish from the calendar: an exception is its
/// own EVENT with its own temporal rows, which ordinary event retrieval returns.
/// This only stops the master from generating a second, stale copy of it.
#[must_use]
pub fn mask_master_exceptions(
    master_ref: EntityId,
    series_uid: &str,
    starts: Vec<u64>,
    exceptions: &[CalendarSeriesExceptionValue],
) -> Vec<u64> {
    let masked: BTreeSet<SeriesExceptionKey<'_>> = exceptions
        .iter()
        .filter(|exception| exception.master_ref == master_ref)
        .map(SeriesExceptionKey::from)
        .collect();

    starts
        .into_iter()
        .filter(|start| {
            let key = SeriesExceptionKey {
                uid: series_uid,
                original_start_utc: *start,
            };
            !masked.contains(&key)
        })
        .collect()
}
