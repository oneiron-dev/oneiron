//! Moved from `crates/oneiron/src/dreamer_consolidation/resident_dream.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Which section of the cut a source came from (FIX 7753).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DreamSourceKind {
    Pad,
    Receipt,
    Inbox,
    Health,
    ForkHealth,
}

/// What a resident's dreaming has read so far. Each source keeps the time
/// and id of the last row it read, so a cut that stops inside one second
/// resumes after that row, not after the second.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentDreamProgress {
    /// The newest receipt time it read, in Unix seconds.
    pub receipts_after: u64,
    /// That receipt's `kind:id`.
    pub receipt_after_id: String,
    /// The newest INBOX row time it read.
    pub inbox_after: u64,
    /// That row's item id.
    pub inbox_after_id: String,
    /// The INBOX row past the cursor its last dreaming read only in part.
    #[serde(default)]
    pub inbox_partial: Option<ResidentDreamPartial>,
    /// The sealed pad its last dreaming read only in part.
    #[serde(default)]
    pub pad_partial: Option<ResidentDreamPartial>,
    /// The time the newest health card about it that it read was last
    /// touched (FIX 1145).
    #[serde(default)]
    pub health_after: u64,
    /// That card's `health:` handle.
    #[serde(default)]
    pub health_after_id: String,
    /// The time the newest health card about one of its forks that it read
    /// was last touched (FIX 5913): a cursor of its own, so a fork's card
    /// never moves it past a card about it unread.
    #[serde(default)]
    pub fork_health_after: u64,
    /// That card's `health:` handle.
    #[serde(default)]
    pub fork_health_after_id: String,
    pub dreamed_at: u64,
    pub entries: u64,
}

/// An input one dreaming read only in part, because it did not fit any
/// window whole: the next dreaming reads on from `read` bytes into it, so it
/// is read whole across dreamings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentDreamPartial {
    /// The row's time (an INBOX row's), or 0 for a pad.
    pub at: u64,
    /// The INBOX row's item id, or the pad's hex id.
    pub id: String,
    /// The bytes of its words (a pad's body) read so far.
    pub read: u64,
}
