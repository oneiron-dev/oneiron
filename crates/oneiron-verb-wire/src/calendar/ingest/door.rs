//! Moved from `crates/oneiron/src/calendar/ingest/door.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// An exact uploaded version is the immutable raw archive. No URL, importer
/// actor, approval override or decoded-text assertion is accepted here.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarIcsImportRequest {
    pub system: String,
    pub source_blob_ref: String,
    pub source_version: u64,
}

/// A move imports just this detached component from an uploaded amendment,
/// never the whole feed. Unrelated components, passports and masks stay put.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CalendarInstanceMoveRequest {
    pub system: String,
    pub source_blob_ref: String,
    pub source_version: u64,
    pub uid: String,
    pub original_start_utc: u64,
    pub start_utc: u64,
    pub end_utc: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarImportClaimReceipt {
    pub claim_ref: String,
    pub predicate: String,
    pub approval: String,
    pub lifecycle: String,
}

/// References are returned even when their imported claims await consent.
/// A successful parse/import is not an approval or an admitted occurrence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarImportedEvent {
    pub event_ref: String,
    pub uid: String,
    pub original_start_utc: Option<u64>,
    pub claims: Vec<CalendarImportClaimReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CalendarIcsImportReceipt {
    pub source_blob_ref: String,
    pub source_version: u64,
    pub events: Vec<CalendarImportedEvent>,
    pub screen_verdict: String,
    /// Booking moves this upload held back because an emergency delivery for
    /// that booking is still pending (FIX 22385): the booking's EVENT and
    /// passport stay as they were, and every other item of the upload
    /// landed. Uploading the feed again once the delivery completes moves
    /// them.
    #[serde(default)]
    pub owed_booking_moves: u32,
}
