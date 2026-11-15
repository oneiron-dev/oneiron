//! Moved from `crates/oneiron/src/store/shared_leave_receipt.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How this member's membership ended.
// Public through `sync::shared_leave`; a build without sync names them only here.
#[cfg_attr(not(feature = "sync"), allow(unreachable_pub))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharedLeaveKind {
    /// The member left.
    Left,
    /// A holder removed the member, an Owner removed as Owner included.
    Removed,
    /// The Owner handed ownership on and kept no role.
    Transferred,
    /// Another person recovered ownership from this Owner.
    Recovered,
    /// The shared vault was deleted. Only a verified home-signed notice says
    /// so (`VerifiedLeaveNotice`).
    Deleted,
}

/// The local record that this device left a shared vault: the notice it
/// confirmed and the unsynced edits the leave discarded. Local only.
// Public through `sync::shared_leave`; a build without sync names them only here.
#[cfg_attr(not(feature = "sync"), allow(unreachable_pub))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedLeaveReceipt {
    /// The shared-act receipt the notice names.
    pub notice_receipt: String,
    pub vault_id: u64,
    /// The member (person id, hex) who left.
    pub member: String,
    pub kind: SharedLeaveKind,
    /// When the shared vault recorded the change.
    pub changed_at: u64,
    /// When this device discarded its queued edits.
    pub completed_at: u64,
    /// Queued window updates discarded (`q:` rows) plus valid run-buffer
    /// updates an explicit leave discarded unqueued (leave-only single-try
    /// Pause, published before `running=false`).
    pub discarded_window_updates: u64,
    /// Unacknowledged text frames discarded (`qd:e:` rows).
    pub discarded_text_frames: u64,
    /// Pending NOTE commands discarded (`qn:e:` rows).
    pub discarded_note_commands: u64,
    /// Every unsynced edit the leave discarded: the three counts together,
    /// the window count including discarded-unqueued updates.
    pub discarded_unsynced_edits: u64,
    /// The env's replica rows the leave purged: entity, edge, index, side and
    /// sync rows.
    pub purged_rows: u64,
    /// The entities the purge kept: authority log and machine rows, rows a
    /// legal hold names, and the pinned pack map.
    pub kept_entities: u64,
    /// Whether the purge ran to its final pass. Every pass persists its own
    /// state, so a crash between passes leaves this false and the next
    /// confirmation resumes.
    pub purge_complete: bool,
}
