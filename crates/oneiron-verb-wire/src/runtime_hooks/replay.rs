//! Moved from `crates/oneiron/src/runtime_hooks/replay.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How a replayed outcome stands to the one its run recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HookReplayCompare {
    /// The same outcome, as JSON.
    Same,
    /// Another outcome, or none where the run returned one.
    Differs,
    /// Nothing to compare with: the run kept no outcome, or none ran.
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HookReplayResult {
    /// The body ran on this entry. Nothing landed.
    Ran {
        outcome_json: Option<String>,
        /// The outcome kind, or `refused` / `failed`.
        outcome: String,
        reason: Option<String>,
        /// The outcome the live run recorded, when one ran.
        recorded: Option<String>,
        /// The outcome JSON the live run recorded, when it kept one.
        recorded_outcome_json: Option<String>,
        compare: HookReplayCompare,
        /// The input came from the run's saved row: its memo, or its saved
        /// verb run.
        from_memo: bool,
        /// No run pinned this entry's reads; they read current rows.
        reads_live: bool,
    },
    /// The hook's current grant no longer shows a saved dependency.
    Withheld { reason: String },
    /// The entry's inputs are gone: replay will not read newer state instead.
    MissingHistory { reason: String },
}
