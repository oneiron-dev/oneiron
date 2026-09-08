//! Claim-value decode and the booking error constructors this lane uses.

use serde::de::DeserializeOwned;

use crate::booking::constraint::BookingError;
use crate::calendar::CalendarError;
use crate::error::Error;

/// The same `rmp_serde` ↔ `rmpv` bridge the rest of the booking lane uses.
pub(super) fn decode_claim_value<T: DeserializeOwned>(
    value: &rmpv::Value,
    what: &str,
) -> Result<T, BookingError> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value).map_err(|error| {
        refused(format!(
            "stored booking {what} claim is unreadable: {error}"
        ))
    })?;
    rmp_serde::from_slice(&bytes).map_err(|error| {
        refused(format!(
            "stored booking {what} claim did not decode: {error}"
        ))
    })
}

pub(super) fn refused(detail: impl Into<String>) -> BookingError {
    BookingError::InvalidConstraint(detail.into())
}

pub(super) fn engine_failure<E: Into<Error>>(what: &str, error: E) -> BookingError {
    let error = error.into();
    BookingError::SlotOracle(format!("booking invite grant {what} failed: {error}"))
}

/// Wraps a calendar failure OPAQUELY: no `CalendarError` variant is matched
/// and none is restated in booking's taxonomy, the stance the rest of the lane
/// takes.
pub(super) fn calendar_wrap(error: CalendarError) -> BookingError {
    BookingError::InvalidConstraint(format!("booking invite calendar step refused: {error}"))
}
