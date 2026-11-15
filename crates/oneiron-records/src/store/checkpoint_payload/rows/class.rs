//! Moved from `crates/oneiron/src/store/checkpoint_payload/rows/class.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The mixed sync carriers KS7-3's port splits, with the tag a bundle's
/// binding names each by; a tag is never reused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Carrier {
    /// A sync window's document snapshot.
    WindowSnapshot,
    /// A window's pending CRDT update.
    WindowUpdate,
    /// A thin-residence item's opened blob or document.
    ResidenceItem,
    /// An unacknowledged local text-document edit.
    PendingEdit,
    /// A pending NOTE-operation request.
    PendingNoteOperation,
    /// The sync queue's update carriers and quarantine.
    SyncQueue,
}

impl Carrier {
    pub const fn tag(self) -> u8 {
        match self {
            Self::WindowSnapshot => 1,
            Self::WindowUpdate => 2,
            Self::ResidenceItem => 3,
            Self::PendingEdit => 4,
            Self::PendingNoteOperation => 5,
            Self::SyncQueue => 6,
        }
    }
}
