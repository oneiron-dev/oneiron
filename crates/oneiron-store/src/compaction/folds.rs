//! Folds (ARCH-0067 §2.2): an agent marks spans of its own run's log at any
//! time, `self.compact` folds every pending mark in one batch, each fold
//! leaves one stub where its span was, and `self.unfold` appends a fold's raw
//! turns back at the end of the log. The vault keeps every turn: a fold is a
//! typed record over steps, never a rewrite of them, and no code path parses
//! a stub back.
//!
//! One ledger per run holds its marks, the agent's compact ask, its folds and
//! its unfold appends. The run's own verbs write it; the executor applies the
//! marks at a step boundary, through the run's compaction seat.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use oneiron_contracts::claim::ClaimSource;
use oneiron_contracts::entity_id::EntityId;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FoldMarkOptions {
    #[serde(default)]
    pub note: Option<String>,
}

/// `self.compact`: folds every pending mark in one batch, and compacts the
/// run's settled steps, at the next step boundary.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldCompactInput {
    /// What the summaries must keep.
    #[serde(default)]
    pub note: Option<String>,
}

/// `self.unfold`: appends one fold's raw turns at the end of the log.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldUnfoldInput {
    /// The fold's handle, such as `f1`.
    pub fold: String,
}

/// `self.folds`: the run's folds and its pending marks.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FoldsInput {}

/// What a fold verb answers under `output`: its typed answer, or the
/// ledger's refusal, which changes nothing and which the agent can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum FoldReply<T> {
    Answer(T),
    Refused { error: String },
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

/// One unfold: the fold's raw turns render just before step `at`, where the
/// end of the log was when the agent unfolded it, and stay there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FoldUnfold {
    pub fold: u64,
    pub at: u64,
}
