//! Moved from `crates/oneiron/src/booking/lifecycle/feed_move.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The payload of one [`BOOKING_REVISION_INVITE_ATTEMPT_KIND`] row: the
/// revision whose invite is owed. The invite's recipient, organizer and
/// times are read from committed state when it is sent, never from here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BookingRevisionInvitePayload {
    /// The booking's EVENT, lowercase hex.
    pub event_ref: String,
    /// The booking's outbound UID.
    pub uid: String,
    /// The SEQUENCE the revision committed.
    pub sequence: u32,
}
