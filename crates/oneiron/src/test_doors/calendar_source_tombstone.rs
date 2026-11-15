//! Door for `tests/booking_deposit_refund_rules.rs` (BK-DEPOSITS; FIX
//! [BK-DEPOSIT-TOMBSTONE-REDELIVERY-SEEN-AT]): a provider tombstone, an
//! explicit remote delete, lands as a pack calendar source's pulled delete
//! lands it. Its sweep marks the UID's passports absent under `system`, and
//! when no live source reports the EVENT any more it cancels it with basis
//! `imported_cancel`, the host's cancel a deposit refunds.

use crate::Vault;
use crate::calendar::CalendarError;
use crate::calendar::connectors::RemoteCalendarChange;

/// Lands a remote delete of `uid` under calendar `system` at `now`.
///
/// # Errors
///
/// The admission's failure, as the pull that carried the delete would see
/// it.
pub fn land_calendar_source_delete(
    vault: &Vault,
    system: &str,
    uid: &str,
    now: u64,
) -> Result<(), CalendarError> {
    crate::calendar::ingest::apply_calendar_source_change(
        vault,
        system,
        &RemoteCalendarChange::Delete {
            href: format!("{uid}.ics"),
            uid: uid.to_owned(),
        },
        now,
    )
    .map(|_| ())
}
