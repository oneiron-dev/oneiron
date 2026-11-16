//! Moved from `crates/oneiron/src/office_body/fork.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_docedit::docx_body::DocxStoryScope;

/// What a side did to one block, relative to base.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Deleted,
    Moved,
    Text,
    Cells,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockChange {
    pub block: String,
    pub kind: ChangeKind,
    /// The story the block is a paragraph of; `None` for a body block.
    pub scope: Option<DocxStoryScope>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConflictKind {
    /// One side deleted the block the other edited or moved: a lost intent.
    DeleteEdit,
    /// Both sides moved the block.
    CompetingMove,
    /// Both sides edited the same text or cells; the text CRDT interleaves them.
    BothEdited,
    /// Both sides set the same workbook cell or name differently; the later
    /// write would silently replace the other.
    BothSet,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BodyConflict {
    pub block: String,
    pub kind: ConflictKind,
    /// The story the block is a paragraph of; `None` for a body block.
    pub scope: Option<DocxStoryScope>,
}

/// A fork's proposal against the live body, with the frontiers it was read at.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OfficeBodyDiff {
    pub base: Vec<u8>,
    pub head: Vec<u8>,
    /// The fork's own frontier: a merge names it with the live head, so work
    /// the opener adds after the review never lands on an earlier answer.
    pub fork_head: Vec<u8>,
    pub proposal: Vec<BlockChange>,
    pub current: Vec<BlockChange>,
    pub conflicts: Vec<BodyConflict>,
}

impl OfficeBodyDiff {
    /// Whether a merge must wait: any conflict but a shared text edit, which the
    /// review shows and the CRDT merges.
    #[must_use]
    pub fn blocking(&self) -> bool {
        self.conflicts
            .iter()
            .any(|conflict| conflict.kind != ConflictKind::BothEdited)
    }
}
