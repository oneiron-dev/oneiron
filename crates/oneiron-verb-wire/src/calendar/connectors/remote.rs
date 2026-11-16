//! Moved from `crates/oneiron/src/calendar/connectors/remote.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What the provider stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RemoteWriteReceipt {
    /// The stored resource path.
    pub href: String,
    /// The stored resource's new ETag, when the provider sent one.
    pub etag: Option<String>,
    /// The UID that was stored.
    pub uid: String,
    /// The SEQUENCE that was stored.
    pub sequence: u32,
    /// The content hash of the stored representation.
    pub content_hash: [u8; 32],
}

/// The terminal state of one connector sync run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum CalendarSyncOutcome {
    /// The run completed and the next attempt is on the queue.
    Reenqueued {
        /// The provider cursor the next run resumes from.
        next_cursor: Option<String>,
        /// The next attempt's due instant, inside the configured jitter window.
        next_not_before: u64,
        /// Semantic applications (create/attach/update through the Gate).
        applied: u32,
        /// Echo acknowledgements that rewrote nothing.
        acknowledged: u32,
        /// Passports this run flipped to `absent` for their own source only.
        source_absences: u32,
        /// EVENTs this run cancelled under the all-live-inbound-absent law.
        status_cancellations: u32,
    },
    /// The kill switch is engaged: no transport I/O ran and nothing was
    /// enqueued. Existing calendar data is untouched.
    Killed,
}
