//! Moved from `crates/oneiron/src/store/backup_change.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use heed::RoTxn;
use heed::RwTxn;
use serde::Deserialize;
use serde::Serialize;

/// What a write changes for the backup watermark.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupWriteClass {
    /// Anything an owner backs up: every write that names no other class.
    #[default]
    Content,
    /// A host's own counters and questions, which no restore needs.
    Telemetry,
    /// A backup's own bookkeeping: its chain advance and its incarnation.
    BackupMetadata,
}

impl BackupWriteClass {
    /// The class of one commit holding writes of `self` and `other`: content
    /// wins a mixed commit.
    fn merge(self, other: Self) -> Self {
        if self == Self::Content || other == Self::Content {
            Self::Content
        } else {
            self
        }
    }
}
