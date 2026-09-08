//! Caller-facing shapes for the booking page's standing invite grant.

use crate::entity_id::EntityId;

/// What one invite asks a booking-page grant to authorize.
///
/// Every field is a QUESTION, never an assertion: `booking_ref` names the
/// booking whose persisted claims are read, and the verb and recipient are
/// matched against those claims. Nothing here can grant anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BookingPageInviteContext<'a> {
    /// The confirmed booking (its EVENT) the invite is for.
    pub booking_ref: EntityId,
    /// The outbound verb kind being attempted.
    pub verb_kind: &'a str,
    /// The delivery target the caller wants to reach.
    pub requested_recipient: &'a str,
}

/// The page-publish action that mints the standing grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishBookingPageGrantRequest {
    /// The page being published.
    pub page_ref: EntityId,
    /// The principal publishing it; the grant's actor binding.
    pub publisher_principal: EntityId,
    /// Mint time in Unix seconds.
    pub issued_at: u64,
}

/// The revision one confirmed booking asks the calendar door to send.
///
/// `uid` and `sequence` are READ from the confirm receipt's
/// [`crate::booking::CalendarRevision`] — never re-minted here and never
/// reset. `ics_blob_ref` borrows CAL-04's string blob reference
/// (`CalendarInvitePayload::ics_blob_ref` is a `String`); the raw `.ics` bytes
/// stay in the blob store and only this reference is ever frozen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfirmedBookingInvite<'a> {
    /// The confirmed booking's EVENT.
    pub booking_ref: EntityId,
    /// The once-minted UID.
    pub uid: &'a str,
    /// The revision's current SEQUENCE.
    pub sequence: u32,
    /// Blob-artifact reference of the rendered ICS document.
    pub ics_blob_ref: &'a str,
}

/// Synced-truth field naming a comm-owned PERSON's party. Mirrors the private
/// `comm.rs` constant exactly as `campaign/claims.rs` does: booking READS it
/// and never writes it.
pub(super) const COMM_PARTY_KEY_FIELD: &str = "party_key";

/// Zone label the confirm-time invite document is rendered in.
///
/// A booking's stored occurrence is UTC and the visitor's wall zone lives on
/// the soft-hold row, which the confirm consumes and deletes. Rendering the
/// instant we actually persisted — rather than guessing a zone we no longer
/// hold — keeps the document a pure function of committed state.
pub(super) const CONFIRM_INVITE_TZ_LABEL: &str = "UTC";
