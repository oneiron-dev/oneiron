//! Moved from `crates/oneiron/src/compaction/folds.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_verb_wire::compaction::fold_kinds::FoldKind;
pub use oneiron_verb_wire::compaction::folds::FoldCompactInput;
pub use oneiron_verb_wire::compaction::folds::FoldDescription;
pub use oneiron_verb_wire::compaction::folds::FoldList;
pub use oneiron_verb_wire::compaction::folds::FoldMarkInput;
pub use oneiron_verb_wire::compaction::folds::FoldPending;
pub use oneiron_verb_wire::compaction::folds::FoldReply;
pub use oneiron_verb_wire::compaction::folds::FoldSpan;
pub use oneiron_verb_wire::compaction::folds::FoldUnfold;
pub use oneiron_verb_wire::compaction::folds::FoldUnfoldInput;
pub use oneiron_verb_wire::compaction::folds::FoldsInput;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;

/// One fold verb call. Run and step come from the host binding, never from
/// the guest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verb", rename_all = "snake_case")]
pub enum SelfFoldCall {
    Mark {
        from: u64,
        through: u64,
        note: Option<String>,
        /// A fold by kind; absent on a whole-step fold.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<FoldKind>,
    },
    Compact {
        note: Option<String>,
    },
    Unfold {
        fold: u64,
    },
    List,
    /// `describe({fold})`.
    Describe {
        fold: u64,
    },
}

/// `self.fold`'s answer: the pending mark it made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldMarked {
    pub fold: String,
    pub from: u64,
    pub through: u64,
    /// Always true: the log does not change until a pass folds it.
    pub pending: bool,
    /// The kind it folds; absent on a whole-step fold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FoldKind>,
}

/// `self.compact`'s answer: the marks its batch folds, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldCompactAsked {
    pub pending: Vec<String>,
    pub applies: String,
}

/// `self.unfold`'s answer: the fold whose raw turns come back after this
/// step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldUnfolded {
    pub fold: String,
    pub from: u64,
    pub through: u64,
    pub unfolded_after_step: u64,
}

impl SelfFoldCall {
    /// Whether the call changes the run's ledger.
    #[must_use]
    pub const fn writes(&self) -> bool {
        matches!(
            self,
            Self::Mark { .. } | Self::Compact { .. } | Self::Unfold { .. }
        )
    }
}

/// A fold's handle as the agent reads it: `f1`.
#[must_use]
pub fn fold_handle(fold: u64) -> String {
    format!("f{fold}")
}

/// The fold a handle names: `f1`, or a bare `1`.
pub fn parse_fold_handle(handle: &str) -> oneiron_base::error::Result<u64> {
    let digits = handle.trim().strip_prefix('f').unwrap_or(handle.trim());
    digits
        .parse::<u64>()
        .ok()
        .filter(|fold| *fold > 0)
        .ok_or_else(|| {
            oneiron_base::error::Error::InvalidConfig(format!("`{handle}` names no fold"))
        })
}

/// A pending mark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldMark {
    pub fold: u64,
    pub from: u64,
    pub through: u64,
    pub note: Option<String>,
    /// Why its last pass did not fold it. A failed mark waits for the
    /// agent's next `self.compact`, not for the next breakpoint.
    pub failed: Option<String>,
    /// A mark by kind; `None` folds whole steps.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<FoldKind>,
    /// The step the agent marked it at: how old its span was then, which
    /// the Coach reads to suggest a fold default per agent type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marked_at: Option<u64>,
}

/// `self.compact`'s ask, until a pass takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FoldCompactAsk {
    pub note: Option<String>,
}

/// The most ids a stub lists itself; `describe({fold})` lists them all.
pub const STUB_IDS: usize = 64;

/// Frame marks a summary may not forge: the record marks and the compacted
/// frame.
pub fn escape_compacted_text(text: &str) -> String {
    text.replace("<exec>", r"<\exec>")
        .replace("</exec>", r"<\/exec>")
        .replace("<console>", r"<\console>")
        .replace("</console>", r"<\/console>")
        .replace("<compacted", r"<\compacted")
        .replace("</compacted", r"<\/compacted")
}
