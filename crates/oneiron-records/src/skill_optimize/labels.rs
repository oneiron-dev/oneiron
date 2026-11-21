//! Moved from `crates/oneiron/src/skill_optimize/labels.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use oneiron_verb_wire::skill_optimize::labels::JudgeAsk;
pub use oneiron_verb_wire::skill_optimize::labels::JudgeAskReason;
pub use oneiron_verb_wire::skill_optimize::labels::JudgeRegrade;
use serde::Deserialize;
use serde::Serialize;

/// A label's re-check after an edit of the judge's rubric. Each `rubric` is
/// the rubric text's digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgeLabelRecheck {
    /// Stamped by the edit: still in the anchor, with its freshness, until
    /// the Coach's next pass checks it.
    Pending { rubric: [u8; 32] },
    /// The Coach found it conflicting with the rubric, or could not tell: out
    /// of the anchor until its person answers `ask`, the re-grade ask (`None`
    /// when that ask could not be put to them).
    Waiting {
        rubric: [u8; 32],
        ask: Option<[u8; 32]>,
    },
    /// Its person answered `ask` that it still fits: back in the anchor, its
    /// pick time unchanged.
    Kept { rubric: [u8; 32], ask: [u8; 32] },
    /// Its person answered `ask` that it does not: out of the anchor for
    /// good; `fresh` asks the case again.
    Replaced {
        rubric: [u8; 32],
        ask: [u8; 32],
        fresh: [u8; 32],
    },
}
