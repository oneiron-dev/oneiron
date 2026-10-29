//! `vault.hooks.replay`'s input, page and owner call: a dry run of a hook's
//! body over past facts or saved verb runs, a page at a time (FIX 8629).
use serde::{Deserialize, Serialize};

use crate::memory::{MemoryError, MemoryResult};

/// `vault.hooks.replay`'s page size when the request names none.
pub const HOOKS_REPLAY_LIMIT_DEFAULT: usize = 64;
/// The most entries one `vault.hooks.replay` page holds, the engine's own
/// page quantum: a larger limit is served a page at a time through
/// `next_cursor` (FIX 8629).
pub const HOOKS_REPLAY_PAGE_MAX: usize = 256;

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

/// One page of `vault.hooks.replay`: its rows, and where the next starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HooksReplayPage {
    pub rows: Vec<HookReplayRow>,
    /// The next page's `cursor`; absent once `done`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// The replay has read every entry its hook takes.
    pub done: bool,
    /// The rows this page could hold: the request's limit, or
    /// [`HOOKS_REPLAY_PAGE_MAX`] when it asked for more.
    pub effective_limit: usize,
    /// The request's limit was past [`HOOKS_REPLAY_PAGE_MAX`] and this page
    /// was served at it; `next_cursor` continues to the rest.
    #[serde(default)]
    pub limit_clamped: bool,
}

/// One past fact or saved verb run a hook takes, and what its body returns
/// for it now. Nothing landed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HookReplayRow {
    pub case: crate::runtime_hooks::HookReplayCase,
    pub result: HookReplayOutcome,
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
        compare: crate::runtime_hooks::HookReplayCompare,
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

impl From<crate::runtime_hooks::HookReplayEntry> for HookReplayRow {
    fn from(entry: crate::runtime_hooks::HookReplayEntry) -> Self {
        use crate::runtime_hooks::HookReplayResult;
        Self {
            case: entry.case,
            result: match entry.result {
                HookReplayResult::Ran {
                    outcome_json,
                    outcome,
                    reason,
                    recorded,
                    recorded_outcome_json,
                    compare,
                    from_memo,
                    reads_live,
                } => HookReplayOutcome::Ran {
                    outcome_json,
                    outcome,
                    reason,
                    recorded,
                    recorded_outcome_json,
                    compare,
                    from_memo,
                    reads_live,
                },
                HookReplayResult::Withheld { reason } => HookReplayOutcome::Withheld { reason },
                HookReplayResult::MissingHistory { reason } => {
                    HookReplayOutcome::MissingHistory { reason }
                }
            },
        }
    }
}

/// `vault.hooks.replay` under the owner's proof a host minted from the
/// request, on `runtime`, the host's own hook sandbox: a dry run of the
/// binding's body over past facts or saved verb runs, landing nothing.
/// `verdict`, the host's decision ladder, answers a generative fact hook's
/// `ai.verdict` on a fact no run pinned; a pinned run hears its own again.
pub fn replay_hooks_as_owner(
    vault: &crate::Vault,
    owner: &crate::consent::AuthenticatedOwner,
    runtime: &dyn crate::runtime_hooks::HookBodyRuntime,
    verdict: Option<std::sync::Arc<dyn crate::runtime_hooks::HookVerdict>>,
    input: &HooksReplayRequest,
) -> MemoryResult<HooksReplayPage> {
    replay_hooks_as_owner_listing(vault, owner, runtime, verdict, input).map(|(page, _)| page)
}

/// [`replay_hooks_as_owner`], beside the rows its entries stand on
/// ([`crate::Vault::hooks_replay_listing`]); `None` once an entry asked a
/// verdict.
pub fn replay_hooks_as_owner_listing(
    vault: &crate::Vault,
    _owner: &crate::consent::AuthenticatedOwner,
    runtime: &dyn crate::runtime_hooks::HookBodyRuntime,
    verdict: Option<std::sync::Arc<dyn crate::runtime_hooks::HookVerdict>>,
    input: &HooksReplayRequest,
) -> MemoryResult<(HooksReplayPage, Option<Vec<crate::EntityId>>)> {
    let asked = input.limit()?;
    let limit = asked.min(HOOKS_REPLAY_PAGE_MAX);
    let binding = crate::EntityId::from_hex(input.binding.trim())
        .map_err(|_| MemoryError::bad_request("binding is a hook binding's 32-hex id"))?;
    let since = input
        .since
        .as_ref()
        .map(|position| crate::runtime_hooks::FactPositionHex(position.trim().to_owned()));
    let cursor = input
        .cursor
        .as_deref()
        .map(crate::runtime_hooks::HookReplayCursor::parse)
        .transpose()
        .map_err(|_| MemoryError::bad_request("cursor is not a vault.hooks.replay next_cursor"))?;
    let (page, listed) = vault
        .hooks_replay_page_listing(runtime, verdict, binding, since, cursor, limit)
        .map_err(|error| match error {
            crate::Error::EntityNotFound => {
                MemoryError::not_found(format!("no hook binding {}", input.binding.trim()))
            }
            crate::Error::InvalidConfig(message) => MemoryError::bad_request(message),
            other => other.into(),
        })?;
    Ok((
        HooksReplayPage {
            rows: page.entries.into_iter().map(HookReplayRow::from).collect(),
            next_cursor: page
                .next
                .map(crate::runtime_hooks::HookReplayCursor::to_text),
            done: page.next.is_none(),
            effective_limit: limit,
            limit_clamped: asked > limit,
        },
        listed,
    ))
}
