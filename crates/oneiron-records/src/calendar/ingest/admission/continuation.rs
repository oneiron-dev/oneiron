//! Moved from `crates/oneiron/src/calendar/ingest/admission/continuation.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What one queued property continuation reads again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcsPropertyContinuationPayload {
    /// The foreign system the admission ran for.
    pub system: String,
    /// The source the admission's claims cite: the archived feed version
    /// for an ICS admission, the pull record for a connector's. The claims
    /// the continuation admits cite it too, as the first pass's do.
    pub blob_ref: String,
    /// The archived version the continuation reads the event from again,
    /// `artifact#vN`: the feed version itself for an ICS admission, the
    /// pulled resource's for a connector's.
    pub source_version: String,
    /// Hex id of the EVENT the properties are claims on.
    pub event_ref: String,
    /// The event's UID.
    pub uid: String,
    /// A detached occurrence's original start; `None` for the event itself.
    pub recurrence_id_utc: Option<u64>,
}
