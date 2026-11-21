//! The booking card's calendar hold (CAL-OUTBOX-ROW-OF-REMOVED-SEAT-HOLDS-PULLS = C, the lead 21
//! Nov 09:15): the calendar changes of the booking that an outbox row holds while the seat that
//! wrote it is out of service, so the hold is never invisible. The card shows the owner's line
//! and the two acts; the inbox lists it as a row of its own
//! ([`super::BOOKING_CALENDAR_HOLD_ITEM_PREFIX`]). The words are interim: the UI owns the copy.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::calendar::connectors::door::CalendarHoldRow;
use crate::error::Result;
use crate::verbs::CALENDAR_HOLD_RELEASE_VERB;
use crate::{EntityId, Vault};

/// "Reconnect it": the owner's re-install of the seat, `vault.settings.set` of the setting
/// `calendar.connector_seat` with the seat's old configuration under a new seat ref. The same
/// configuration writes the same outbox scope, so the held rows resume.
pub const CALENDAR_HOLD_RECONNECT_VERB: &str = "vault.settings.set";

/// What a booking card says of the calendar changes of the booking that are on hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BookingOwnerCardCalendarHold {
    /// The owner's line, naming each calendar whose connection is out of service.
    pub line: String,
    /// Each held outbox row: the calendar it names, why its seat is out of service, and the row
    /// as it stands.
    pub holds: Vec<CalendarHoldRow>,
    /// The verb of "Reconnect it" ([`CALENDAR_HOLD_RECONNECT_VERB`]).
    pub reconnect_verb: String,
    /// The verb of "Release the hold", previewed through `vault.owner_confirm.preview`, input
    /// `{event_ref}` ([`CALENDAR_HOLD_RELEASE_VERB`]).
    pub release_verb: String,
}

/// The calendar hold of the booking `event_ref`, read in `rtxn`; `None` when nothing holds.
pub(super) fn calendar_hold_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    event_ref: &EntityId,
) -> Result<Option<BookingOwnerCardCalendarHold>> {
    let holds = crate::calendar::connectors::calendar_holds_in_txn(vault, rtxn, event_ref)?;
    if holds.is_empty() {
        return Ok(None);
    }
    let calendars: BTreeSet<String> = holds
        .iter()
        .map(|hold| format!("{} ({})", hold.system, hold.calendar_ref))
        .collect();
    let calendars: Vec<String> = calendars.into_iter().collect();
    let line = format!(
        "Calendar changes for this booking are on hold: the {} connection that wrote it is \
         out of service",
        calendars.join(", ")
    );
    Ok(Some(BookingOwnerCardCalendarHold {
        line,
        holds,
        reconnect_verb: CALENDAR_HOLD_RECONNECT_VERB.to_owned(),
        release_verb: CALENDAR_HOLD_RELEASE_VERB.to_owned(),
    }))
}

/// When the hold began, as the inbox row dates it: the earliest last move of a held row.
pub(super) fn calendar_hold_since(hold: &BookingOwnerCardCalendarHold) -> Option<u64> {
    hold.holds.iter().map(|row| row.updated_at).min()
}
