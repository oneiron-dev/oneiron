//! Moved from `crates/oneiron/src/calendar/connectors/remote.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::calendar::connectors::remote::CalendarSyncOutcome;
pub use oneiron_verb_wire::calendar::connectors::remote::RemoteWriteReceipt;
use serde::Deserialize;
use serde::Serialize;

/// One conditional remote write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteWriteRequest {
    /// The resource to replace; `None` creates one.
    pub href: Option<String>,
    /// The precondition: CalDAV sends it as `If-Match`.
    pub expected_etag: Option<String>,
    /// The UID this write preserves.
    pub uid: String,
    /// The SEQUENCE this write intends.
    pub sequence: u32,
    /// The complete `VCALENDAR` document to store.
    pub ics: Vec<u8>,
}
