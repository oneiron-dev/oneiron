//! E+'s call between Fold and Expire at a parked run's cache horizon (L2-37 PR-2; RESEARCH-1333,
//! the reference's `expected()` with no Keep, so its look-ahead has one step).
//!
//! At `elapsed` seconds into the wait, with the prefix alive `hold` seconds more, over the waits
//! of the wait's cell still waiting then (one that never returns costs nothing more):
//!
//! - Expire pays a warm read of the prefix for each return within the hold, and a cold write of
//!   it for each return after: `n[t, t + hold) * C * read + n[t + hold, inf) * C * write`;
//! - Fold pays a cold write of the folded prefix for every return: `n[t, inf) * (C - F) * write`.
//!   The engine's kind seal makes no model call, so the fold itself costs nothing.
//!
//! `C` is the cached prefix, `F` the prompt tokens the fold's stubs replace (at most `C`). The
//! reference also charges the stubs a run reads back after a fold; the engine has no measure of
//! that, so it is left out, which leans slightly to Fold. With no kind mark to fold, `F` is zero
//! and the call is Expire.

use super::returns::IdleReturnCell;

/// What one prompt token of the cached prefix costs to read from the cache and to write into
/// it, in the catalog's currency.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CachePrices {
    pub(crate) read_per_token: f64,
    pub(crate) write_per_token: f64,
}

impl CachePrices {
    /// The cache prices of a catalog cost, per million tokens as the catalog quotes them; `None`
    /// when either is missing or does not read as a finite rate of zero or more.
    pub(crate) fn of(cost: &crate::llm::LlmCatalogCost) -> Option<Self> {
        let per_token = |quoted: Option<&String>| {
            quoted?
                .trim()
                .parse::<f64>()
                .ok()
                .filter(|rate| rate.is_finite() && *rate >= 0.0)
                .map(|rate| rate / 1_000_000.0)
        };
        Some(Self {
            read_per_token: per_token(cost.cache_read_per_million.as_ref())?,
            write_per_token: per_token(cost.cache_write_per_million.as_ref())?,
        })
    }
}

/// The prompt as the idle call sees it: the cached prefix and what a fold would take off it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PromptAtHorizon {
    pub(crate) prefix_tokens: u64,
    pub(crate) folded_tokens: u64,
}

/// Whether Fold costs less than Expire for a wait of `cell` at `elapsed_secs` with the prefix
/// alive `hold_secs` more. A tie, or nothing to fold, is Expire.
pub(crate) fn fold_beats_expire(
    cell: &IdleReturnCell,
    elapsed_secs: u64,
    hold_secs: u64,
    prompt: PromptAtHorizon,
    prices: CachePrices,
) -> bool {
    let folded = prompt.folded_tokens.min(prompt.prefix_tokens);
    if folded == 0 {
        return false;
    }
    let returned_from = |from: u64| -> u64 {
        let at = cell
            .returned_after_secs
            .partition_point(|&gap| u64::from(gap) < from);
        u64::try_from(cell.returned_after_secs.len() - at).unwrap_or(u64::MAX)
    };
    let after_elapsed = returned_from(elapsed_secs);
    let after_hold = returned_from(elapsed_secs.saturating_add(hold_secs));
    let within_hold = after_elapsed.saturating_sub(after_hold);
    let prefix = prompt.prefix_tokens as f64;
    let expire = within_hold as f64 * prefix * prices.read_per_token
        + after_hold as f64 * prefix * prices.write_per_token;
    let fold = after_elapsed as f64 * (prefix - folded as f64) * prices.write_per_token;
    fold < expire
}

/// How many of `cell`'s waits were still waiting at `elapsed_secs`: those that returned then or
/// later, and those that never did. The cold-start floor counts these.
pub(crate) fn still_waiting(cell: &IdleReturnCell, elapsed_secs: u64) -> u64 {
    let at = cell
        .returned_after_secs
        .partition_point(|&gap| u64::from(gap) < elapsed_secs);
    u64::try_from(cell.returned_after_secs.len() - at)
        .unwrap_or(u64::MAX)
        .saturating_add(u64::from(cell.never))
}
