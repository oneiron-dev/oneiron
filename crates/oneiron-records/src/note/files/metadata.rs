//! Moved from `crates/oneiron/src/note/files/metadata.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::note::files::metadata::FileReadiness;
pub use oneiron_verb_wire::note::files::metadata::NameOnlyReason;
use serde::Deserialize;
use serde::Serialize;

/// What the host read of a file, beside its text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFacts {
    pub bytes: u64,
    /// When the file was last written (seconds).
    pub modified_at: u64,
}

/// What the ledger keeps of a Files source's file: the facts of the
/// revision it took, when it first saw the file and when it last took the
/// file's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMeta {
    pub bytes: u64,
    pub modified_at: u64,
    pub first_seen_at: u64,
    /// When the vault last took the file's text; none while it holds the
    /// file by name only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub indexed_at: Option<u64>,
}

impl FileMeta {
    /// The meta of a file first seen `at`, whose text the vault took at
    /// `indexed_at`.
    pub fn first(facts: FileFacts, at: u64, indexed_at: Option<u64>) -> Self {
        Self {
            bytes: facts.bytes,
            modified_at: facts.modified_at,
            first_seen_at: at,
            indexed_at,
        }
    }

    /// This meta on the revision `facts` names, whose text the vault took
    /// at `indexed_at`.
    pub fn moved(self, facts: FileFacts, indexed_at: Option<u64>) -> Self {
        Self {
            bytes: facts.bytes,
            modified_at: facts.modified_at,
            first_seen_at: self.first_seen_at,
            indexed_at,
        }
    }
}
