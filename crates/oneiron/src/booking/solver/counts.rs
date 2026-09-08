//! Confirmed-booking tallies per visitor-local day and week.

use serde::{Deserialize, Serialize};

use crate::booking::{BookingError, EventTypeKey};
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;
use crate::vault::Vault;

// -------------------------------------------------------------------------
// Confirmed-booking counts
// -------------------------------------------------------------------------

/// Confirmed bookings inside one visitor-local period.
///
/// The bucket's own UTC span is what a caller reads; which cap it is charged
/// against is decided from `window_start_utc`'s visitor-local day, so a table
/// built in one zone cannot be silently applied in another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingCountBucket {
    pub window_start_utc: u64,
    /// Half-open `[window_start_utc, window_end_utc)`.
    pub window_end_utc: u64,
    pub confirmed: u16,
}

/// The typed cap input. Sparse by construction: a period with no bucket has no
/// confirmed bookings, which is zero, not unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingCounts {
    pub daily: Vec<BookingCountBucket>,
    pub weekly: Vec<BookingCountBucket>,
}

/// Loads confirmed-booking counts for `(page_ref, event_type)` over `window`.
///
/// `window` is the bookable extent — the caller's window already clipped to the
/// page's horizon — so it is bounded, not caller-controlled. A cap is charged
/// over a whole visitor-local period, so layer 2 widens `window` to the periods
/// its candidates fall in rather than assuming it already covers them.
///
/// STACK SEAM. Confirmed bookings live in the session-keyed lifecycle rows
/// ONE-1813 lands in BK-A layer 2; on this layer there is no such store, so
/// there is nothing to count and the table is empty. An empty table binds no
/// cap — deliberately, because a missing bucket is zero confirmed bookings.
/// The visitor-local day/week identity that decides which bucket a candidate is
/// charged against lives in the cap stage, so layer 2 supplies `confirmed` here
/// and changes nothing else.
///
/// # Errors
///
/// [`BookingError::SlotOracle`] once layer 2 reads storage here.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the fallible signature is the ratified layer-2 contract; the lint \
              fires only while the body is storage-free, and unfulfilling it is \
              how ONE-1813 is told to delete this attribute"
)]
pub(crate) fn load_booking_counts(
    _vault: &Vault,
    _page_ref: EntityId,
    _event_type: &EventTypeKey,
    _window: TimeRange,
    _visitor_tz: &str,
) -> Result<BookingCounts, BookingError> {
    Ok(BookingCounts {
        daily: Vec::new(),
        weekly: Vec::new(),
    })
}
