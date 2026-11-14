//! Moved from `crates/oneiron/src/skill_optimize/labels.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::skill_optimize::labels::JudgeAsk;
pub use oneiron_verb_wire::skill_optimize::labels::JudgeAskReason;
pub use oneiron_verb_wire::skill_optimize::labels::JudgeRegrade;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One human pick is one immutable calibration label. No score, model output,
/// or digest delivery can mint this row. A rubric edit marks it for a
/// re-check; it never changes the pick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeLabel {
    /// The row's own id (FIX 12088), minted when the pick is recorded: the
    /// witness a re-check names beside the rubric it checks against. Labels
    /// are keyed by their ask id, a question digest, not an `EntityId`.
    #[serde(with = "oneiron_contracts::serialize::entity_ref")]
    pub row_id: EntityId,
    pub ask: JudgeAsk,
    pub chosen: String,
    pub picked_at: u64,
    pub principal_ref: String,
    /// Where an edit of the judge's rubric left this pick; `None` while no
    /// edit since it was picked or last found fitting is pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recheck: Option<JudgeLabelRecheck>,
}

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

impl JudgeLabel {
    /// Whether the pick is in its skill's anchor: every label but one a
    /// rubric edit left waiting for, or replaced by, its person's re-grade.
    fn in_anchor(&self) -> bool {
        !matches!(
            self.recheck,
            Some(JudgeLabelRecheck::Waiting { .. } | JudgeLabelRecheck::Replaced { .. })
        )
    }

    /// Whether the Coach owes the pick a check against `rubric`, the pinned
    /// one: stamped under it, or kept by its person under an earlier one.
    fn recheck_due(&self, rubric: [u8; 32]) -> bool {
        match self.recheck {
            Some(JudgeLabelRecheck::Pending { rubric: stamped }) => stamped == rubric,
            Some(JudgeLabelRecheck::Kept { rubric: kept, .. }) => kept != rubric,
            None | Some(JudgeLabelRecheck::Waiting { .. } | JudgeLabelRecheck::Replaced { .. }) => {
                false
            }
        }
    }
}
