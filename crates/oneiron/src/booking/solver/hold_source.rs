//! The live-hold read trait and its empty implementation.

use crate::booking::BookingError;
use crate::entity_id::EntityId;
use crate::temporal::TimeRange;

// -------------------------------------------------------------------------
// Live holds
// -------------------------------------------------------------------------

/// The narrow read the solver needs from the hold store.
///
/// Ranges are half-open `[start, end)`, matching the rest of this module.
/// `exclude_session_key` lets the session that is confirming its own hold see
/// the slot it already reserved, so a confirm never fails against itself.
///
/// `Send + Sync` for the same reason [`SlotOracle`] carries them: a
/// [`BookingSolver`] holds `&dyn ActiveHoldSource`, and a solver that is not
/// `Sync` cannot be a `SlotOracle` at all.
pub trait ActiveHoldSource: Send + Sync {
    /// Unexpired holds on `page_ref` overlapping `window` as of `now_utc`.
    ///
    /// # Errors
    ///
    /// [`BookingError::SlotOracle`] when the hold store cannot be read.
    fn active_holds(
        &self,
        page_ref: EntityId,
        window: TimeRange,
        now_utc: u64,
        exclude_session_key: Option<&[u8; 32]>,
    ) -> Result<Vec<TimeRange>, BookingError>;
}

/// A page with no hold store.
///
/// BK-A layer 1's stack scaffolding: ONE-1813 supplies the vault-meta
/// implementation in layer 2 without changing the solver contract. This is not
/// a second hold store — it holds nothing.
pub struct NoActiveHolds;

impl ActiveHoldSource for NoActiveHolds {
    fn active_holds(
        &self,
        _page_ref: EntityId,
        _window: TimeRange,
        _now_utc: u64,
        _exclude_session_key: Option<&[u8; 32]>,
    ) -> Result<Vec<TimeRange>, BookingError> {
        Ok(Vec::new())
    }
}
