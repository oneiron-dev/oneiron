//! E+'s call between Keep, Fold and Expire at a parked run's cache horizon (L2-37 PR-3;
//! RESEARCH-1333, the reference's S-arm `expected()` on raw counts).
//!
//! At `elapsed` seconds into the wait, with the prefix alive `hold` seconds more, over the waits
//! of the wait's cell still waiting then (one that never returns costs nothing more), on the grid
//! of the asks left, spaced `T = lifetime - 60` seconds apart:
//!
//! - Expire pays a warm read of the prefix for each return within the hold, and a cold write of
//!   it for each return after: `r[t, t + hold) * C * read + r[t + hold, inf) * C * write`;
//! - Fold pays a cold write of the folded prefix for every return: `r[t, inf) * (C - F) * write`.
//!   The engine's kind seal makes no model call, so the fold itself costs nothing;
//! - Keep pays one refresh ping for each wait still waiting, a warm read for each return within
//!   the next lifetime, and the best later choice: `n[t] * ping + r[t, t + T) * C * read + E`.
//!   A refresh resends the cached prefix and asks one output token, so `ping` is `C * read` plus
//!   one output token; the request's uncached tail is not known here and is left out.
//!
//! `C` is the cached prefix, `F` the prompt tokens the fold's stubs replace (at most `C`). The
//! reference also charges the stubs a run reads back after a fold; the engine has no measure of
//! that, so it is left out, which leans slightly to Fold. The reference divides every term by the
//! waits alive at the ask, a common factor, so it is left out. With nothing to fold, `F` is zero
//! and Fold is never the call, but Keep may still beat Expire.

use super::returns::IdleReturnCell;

/// What one prompt token of the cached prefix costs to read from the cache and to write into
/// it, and what one output token costs, in the catalog's currency.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CachePrices {
    pub(crate) read_per_token: f64,
    pub(crate) write_per_token: f64,
    /// What one output token costs, or `None` when the catalog's output price does not read:
    /// `None` offers no Keep.
    pub(crate) output_per_token: Option<f64>,
}

impl CachePrices {
    /// The cache prices of a catalog cost, per million tokens as the catalog quotes them; `None`
    /// when either cache price is missing or does not read as a finite rate of zero or more. An
    /// unreadable output price gives `None` for the output token alone, never for the whole.
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
            output_per_token: per_token(Some(&cost.output_per_million)),
        })
    }
}

/// The prompt as the idle call sees it: the cached prefix and what a fold would take off it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PromptAtHorizon {
    pub(crate) prefix_tokens: u64,
    pub(crate) folded_tokens: u64,
}

/// E+'s call for a wait at its cache horizon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdleChoice {
    /// Send one refresh of the cached prefix and ask again before it expires.
    Keep,
    /// Seal the run's kind marks now, with no model call.
    Fold,
    /// Let the prefix go.
    Expire,
}

/// E+'s call for a wait of `cell` at `elapsed_secs` with the prefix alive `hold_secs` more, whose
/// provider keeps a prefix `lifetime_secs` from its send, with `asks_left` asks left including this
/// one. The backward DP over the ask grid: `t_j = elapsed + j * T` with `T = lifetime - 60` (at
/// least one second), `h_0 = hold` and `h_j = 60` after, `E_j` the cheapest of Expire, Fold and
/// Keep at `j`, Keep infinite at the last ask and whenever the output price does not read. With one
/// ask left the call is the PR-2 one-step call, the DP's last ask. A tie spends nothing: Expire
/// first, then Fold, then Keep.
pub(crate) fn idle_choice(
    cell: &IdleReturnCell,
    elapsed_secs: u64,
    hold_secs: u64,
    lifetime_secs: u64,
    prompt: PromptAtHorizon,
    prices: CachePrices,
    asks_left: u32,
) -> IdleChoice {
    let folded = prompt.folded_tokens.min(prompt.prefix_tokens);
    let prefix = prompt.prefix_tokens as f64;
    let period = lifetime_secs.saturating_sub(60).max(1);
    let asks = asks_left.max(1);
    let ping = prices
        .output_per_token
        .map(|output| prefix * prices.read_per_token + output);
    let returned_from = |from: u64| -> u64 {
        let at = cell
            .returned_after_secs
            .partition_point(|&gap| u64::from(gap) < from);
        u64::try_from(cell.returned_after_secs.len() - at).unwrap_or(u64::MAX)
    };
    let returned_between = |from: u64, to: u64| -> u64 {
        if to <= from {
            return 0;
        }
        let at_from = cell
            .returned_after_secs
            .partition_point(|&gap| u64::from(gap) < from);
        let at_to = cell
            .returned_after_secs
            .partition_point(|&gap| u64::from(gap) < to);
        u64::try_from(at_to.saturating_sub(at_from)).unwrap_or(u64::MAX)
    };
    let mut next_best: Option<f64> = None;
    let mut choice = IdleChoice::Expire;
    for ask in (0..asks).rev() {
        let at_secs = elapsed_secs.saturating_add(u64::from(ask).saturating_mul(period));
        let hold = if ask == 0 { hold_secs } else { 60 };
        let hold_end = at_secs.saturating_add(hold);
        let within_hold = returned_between(at_secs, hold_end);
        let after_hold = returned_from(hold_end);
        let expire = within_hold as f64 * prefix * prices.read_per_token
            + after_hold as f64 * prefix * prices.write_per_token;
        let fold = if folded == 0 {
            f64::INFINITY
        } else {
            let after_elapsed = returned_from(at_secs);
            after_elapsed as f64 * (prefix - folded as f64) * prices.write_per_token
        };
        let keep = match (ping, next_best) {
            (Some(ping), Some(next)) => {
                let waiting = still_waiting(cell, at_secs);
                let warm = returned_between(at_secs, at_secs.saturating_add(period));
                waiting as f64 * ping + warm as f64 * prefix * prices.read_per_token + next
            }
            _ => f64::INFINITY,
        };
        next_best = Some(expire.min(fold).min(keep));
        if ask == 0 {
            choice = if expire <= fold && expire <= keep {
                IdleChoice::Expire
            } else if fold <= keep {
                IdleChoice::Fold
            } else {
                IdleChoice::Keep
            };
        }
    }
    choice
}

/// The Keeps a cold start gets (rule D; RULING L2-37-COLD-START = B): enough refreshes that the
/// prefix stays warm through `keep_through_secs` from the answer that cached it. The first call
/// comes `T = lifetime - 60` (at least one second) after that answer and each Keep moves the next
/// one `T` on, so: none when `keep_through_secs` is zero, else
/// `max(1, ceil(keep_through_secs / T) - 1)`.
pub(crate) fn cold_start_keeps(keep_through_secs: u64, lifetime_secs: u64) -> u32 {
    if keep_through_secs == 0 {
        return 0;
    }
    let period = lifetime_secs.saturating_sub(60).max(1);
    let keeps = keep_through_secs.div_ceil(period).saturating_sub(1).max(1);
    u32::try_from(keeps).unwrap_or(u32::MAX)
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
