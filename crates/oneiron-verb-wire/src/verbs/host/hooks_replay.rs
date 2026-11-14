//! Moved from `crates/oneiron/src/verbs/host/hooks_replay.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use serde::Deserialize;
use serde::Serialize;

/// `vault.hooks.replay`'s page size when the request names none.
pub const HOOKS_REPLAY_LIMIT_DEFAULT: usize = 64;

/// `vault.hooks.replay`'s input: the hook to replay, where a fact hook
/// starts and how many entries to return, or the cursor a page before
/// returned. A verb hook replays its newest saved runs.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HooksReplayRequest {
    /// The hook binding's 32-hex id.
    pub binding: String,
    /// The fact position a fact hook replays after (`claim_changelog:<hex32>`
    /// or `settlement:<hex16>`); every source from its start when absent. A
    /// verb hook takes none.
    #[serde(default)]
    pub since: Option<String>,
    /// Entries to return, 1 or more, [`HOOKS_REPLAY_PAGE_MAX`] a page;
    /// [`HOOKS_REPLAY_LIMIT_DEFAULT`] when absent.
    #[serde(default)]
    pub limit: Option<usize>,
    /// The `next_cursor` of the page before; the replay continues there and
    /// `since` is not read. Absent, the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

impl HooksReplayRequest {
    /// The entry count this request names; zero is refused.
    pub fn limit(&self) -> MemoryResult<usize> {
        let limit = self.limit.unwrap_or(HOOKS_REPLAY_LIMIT_DEFAULT);
        if limit == 0 {
            return Err(MemoryError::bad_request_with(
                "limit must be at least 1",
                &["Request one entry or more and continue from next_cursor."],
            ));
        }
        Ok(limit)
    }
}

/// What a replayed entry gave: the body's outcome, or the history it lacks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum HookReplayOutcome {
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
        /// How this outcome stands to the recorded one, as JSON.
        compare: crate::runtime_hooks::replay::HookReplayCompare,
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
