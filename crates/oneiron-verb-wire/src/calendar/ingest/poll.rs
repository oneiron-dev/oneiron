//! Moved from `crates/oneiron/src/calendar/ingest/poll.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;

pub const MAX_SECRET_REF_BYTES: usize = 256;

pub const MAX_SYSTEM_BYTES: usize = 128;

/// Host-visible snapshot of one feed's poll cursor. Carries the custody
/// record name and provider ETag — never the resolved URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct IcsFeedCursorSnapshot {
    /// The ETag the next poll sends as `If-None-Match`, when one is held.
    pub etag: Option<String>,
    /// When the last complete feed was applied.
    pub last_complete_at: Option<u64>,
    /// Whether the feed is paused awaiting owner input.
    pub paused: bool,
    /// The worst CAL-09 screen-verdict class the last run admitted under
    /// (`clear`, `flagged`, `indeterminate`, or `skipped`).
    pub last_screen_verdict: Option<String>,
}
