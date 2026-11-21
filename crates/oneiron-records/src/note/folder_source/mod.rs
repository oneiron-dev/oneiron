//! Moved from `crates/oneiron/src/note/folder_source/mod.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::note::files::metadata::FileMeta;
use oneiron_contracts::entity_id::EntityId;
use oneiron_verb_wire::note::files::metadata::FileReadiness;
use oneiron_verb_wire::note::files::metadata::NameOnlyReason;
pub use oneiron_verb_wire::note::folder_source::original::FileOriginal;
use serde::Deserialize;
use serde::Serialize;

/// Where one file of an attached folder stands in the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderFileState {
    /// The note holds the file's text, or the owner's edits of it.
    Landed,
    /// The file changed after the owner edited its note: its text waits as a
    /// fork for review (none when the edit door asked for a review instead).
    Proposed { fork: Option<EntityId> },
    /// The file left the folder; its note, if it had one, is archived.
    Retracted,
    /// A Files source holds the file by its name only: it has no text the
    /// vault takes. A note its earlier text landed is archived until its
    /// text comes back.
    NameOnly { why: NameOnlyReason },
}

/// What the ledger knows of one file of an attached folder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderSourceFile {
    /// Under the folder, `/`-separated.
    pub path: String,
    /// The note the file's text landed as; none for a file the vault only
    /// ever held by its name.
    pub note: Option<EntityId>,
    /// The hash of the file's text at the last rescan that took it.
    pub file_hash: String,
    /// The hash of the text the vault took from the file, when known.
    pub landed_hash: String,
    /// The mentions targets this file's import landed (FIX 1363): the only
    /// edges a rescan deletes for it, never one another writer added.
    pub landed_links: Vec<EntityId>,
    /// The hash of the file's bytes, when its text was extracted from them
    /// (a PDF): its revision. A change to the bytes alone moves no text.
    pub raw_hash: Option<String>,
    pub state: FolderFileState,
    /// What a Files source knows of the file itself (FIX 6942); none for a
    /// folder attached as notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<FileMeta>,
    /// The kept original of the file's bytes as its last rescan read them
    /// (FIX 7779); a continuation part names its file's. None when no
    /// original was kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original: Option<FileOriginal>,
    /// When the ledger first saw the file, kept across partial landings
    /// that hold the meta back so the row stays pending (REVIEW-4381 P1);
    /// 0 only for rows written before it.
    #[serde(default)]
    pub first_seen_at: u64,
    /// The note's indexing time, kept while the meta is cleared to force a
    /// re-read: the clear must not lose when the note was last indexed
    /// (REVIEW-4381 P1). Moved back into the meta when a whole read lands
    /// it. None when no whole read has indexed the note since the clear.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_indexed_at: Option<u64>,
}

impl FolderSourceFile {
    /// Whether the vault holds the file's text, or its name only.
    #[must_use]
    pub fn readiness(&self) -> FileReadiness {
        match self.state {
            FolderFileState::NameOnly { why } => FileReadiness::NameOnly { why },
            _ => FileReadiness::Text,
        }
    }
}
