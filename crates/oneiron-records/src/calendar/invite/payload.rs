//! Moved from `crates/oneiron/src/calendar/invite/payload.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::register::Register;
use serde::Deserialize;
use serde::Serialize;

/// iMIP method carried by one invite.
///
/// Closed on purpose. Outlook treats a `VEVENT` with no explicit `METHOD` as a
/// brand-new event rather than an update, so a defaulted method is a duplicate
/// meeting in the recipient's calendar — the set never widens silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Register)]
#[serde(rename_all = "UPPERCASE")]
#[register("calendar.invite.method")]
pub enum CalendarInviteMethod {
    /// `METHOD:REQUEST` — create or update an invitation.
    Request,
    /// `METHOD:CANCEL` — withdraw an invitation.
    Cancel,
}

impl CalendarInviteMethod {
    /// Parses the wire token; anything outside the closed set is `None`.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        <Self as Register>::named(value)
    }
}
