//! Durable per-pass budget-id derivation and occupied-row index scan.
use oneiron::{DreamerRunnerStore, Vault};

use super::config::PASS_BUDGET_INDEX_SCAN_BOUND;

/// Derives the durable runner-store budget id for one pass from the
/// supervisor's static base id and a monotonic pass index.
///
/// DreamerRunnerStore only initializes a budget row when it is absent, so
/// reusing `config.budget_id` across passes would leave later ticks stuck
/// on `BudgetExhausted` against a spent row. A per-pass id gives each pass
/// a fresh row without requiring this crate to renew or otherwise write
/// runner-store budget state (admission/settle stay inside `run_wake_pass`).
///
/// Trade-off: one durable budget row leaks per pass for the life of the
/// vault (no GC here). That is intentional and cheaper than a shared-row
/// spin; hosts that care about row growth can GC by base-prefix if needed.
///
/// Restart: [`next_pass_budget_index`] scans existing `:p{n}` rows at
/// `run` start so a new process under the same base does not re-enter
/// spent rows. Single-supervisor model only — two supervisors concurrently
/// sharing one base are out of scope (use [`WakeSupervisor::with_pass_gate`]
/// when co-located; do not run independent sequences on the same base).
#[must_use]
pub(super) fn durable_pass_budget_id(base: &str, pass_index: u64) -> String {
    format!("{base}:p{pass_index}")
}

/// Next free per-pass budget index under `base` for this vault:
/// **highest occupied suffix + 1**.
///
/// Dense-probes every `{base}:p{n}` for `n` in `[0, bound)` via
/// [`DreamerRunnerStore::budget`] and returns `max(occupied) + 1`, or `0`
/// when none are occupied. If the dense window is full (resume index would
/// be `bound`) and `{base}:p{bound}` (or later) is still occupied, a
/// galloping probe walks upward and binary-searches the first free suffix
/// so restart never clamps onto a spent row past the bound. Lookups stay
/// O(log n) past the dense window; the scan still runs once per `run`.
///
/// Highest-occupied (not first-absent) matters because empty passes leave
/// no runner-store budget row: a prior run may have written `:p1` after an
/// empty `:p0`, and first-absent would restart at `0`, fill `:p0`, then
/// advance into the still-occupied stale `:p1`. Scanning to the max
/// occupied suffix avoids that collision; holes below the max are skipped.
///
/// Unreadable probes count as occupied for the max (do not re-mint a row
/// we failed to confirm is free). Not progress for restart-backoff
/// purposes: pure read bookkeeping before any pass runs.
#[must_use]
pub(super) fn next_pass_budget_index(vault: &Vault, base: &str) -> u64 {
    next_pass_budget_index_with_bound(vault, base, PASS_BUDGET_INDEX_SCAN_BOUND)
}

/// Same as [`next_pass_budget_index`] with an injectable dense-scan bound
/// (tests pin a small bound; production uses [`PASS_BUDGET_INDEX_SCAN_BOUND`]).
#[must_use]
pub(super) fn next_pass_budget_index_with_bound(vault: &Vault, base: &str, bound: u64) -> u64 {
    let store = DreamerRunnerStore::new(vault);
    let mut highest_occupied: Option<u64> = None;
    // Full dense scan (not first-absent): holes below a later occupied
    // row must not become the resume index. Cost: one point-read per index
    // in [0, bound) once per supervisor run — production bound is 65_536.
    for n in 0..bound {
        if pass_budget_row_occupied(&store, base, n) {
            highest_occupied = Some(n);
        }
    }
    let start = match highest_occupied {
        None => return 0,
        Some(highest) => {
            let next = highest.saturating_add(1);
            // Free slot still inside the dense window (we scanned it).
            if next < bound {
                return next;
            }
            next
        }
    };
    // Dense window full (or highest was bound-1): find first free at/after
    // `start`, galloping upward then binary-searching so occupied rows past
    // the bound never clamp the resume index.
    first_free_pass_budget_index_from(&store, base, start)
}

/// First free suffix at or after `from`, probed per pass before minting.
/// The startup scan positions the sequence; this is the per-pass guarantee
/// that a spent row is never silently reused (the store reuses existing
/// rows rather than reinitializing them) — e.g. after resuming into an
/// empty-pass hole that sits below a still-occupied higher suffix. Cost:
/// one point-read on the free path; skips cost one read per stale row and
/// terminate because occupied rows are finite.
pub(super) fn advance_past_occupied_pass_rows(vault: &Vault, base: &str, from: u64) -> u64 {
    let store = DreamerRunnerStore::new(vault);
    let mut index = from;
    while pass_budget_row_occupied(&store, base, index) {
        index = index.saturating_add(1);
    }
    index
}

/// True when `{base}:p{n}` exists or is unreadable (treat unreadable as
/// occupied so we never re-mint a row we failed to confirm is free).
fn pass_budget_row_occupied(store: &DreamerRunnerStore<'_>, base: &str, n: u64) -> bool {
    let id = durable_pass_budget_id(base, n);
    match store.budget(&id) {
        Ok(None) => false,
        Ok(Some(_)) => true,
        Err(error) => {
            tracing::warn!(
                ?error,
                budget_id = %id,
                "pass-budget index probe failed; treating as occupied"
            );
            true
        }
    }
}

/// First free suffix at or after `start`. Gallops (doubling) to find an
/// upper free bound, then binary-searches — O(log n) probes past a dense
/// occupied prefix. If the entire remaining `u64` domain is occupied,
/// returns `u64::MAX` (last possible suffix; no further free index exists).
fn first_free_pass_budget_index_from(
    store: &DreamerRunnerStore<'_>,
    base: &str,
    start: u64,
) -> u64 {
    if !pass_budget_row_occupied(store, base, start) {
        return start;
    }
    // `lo` is occupied. Gallop until `hi` is free (or the domain ends).
    let mut lo = start;
    let mut step = 1u64;
    loop {
        let Some(hi) = lo.checked_add(step) else {
            // No free index remains in the u64 domain.
            return u64::MAX;
        };
        if !pass_budget_row_occupied(store, base, hi) {
            return binary_search_first_free_pass_budget(store, base, lo, hi);
        }
        lo = hi;
        step = step.saturating_mul(2);
    }
}

/// Least free index in `(lo, hi]` given `lo` occupied and `hi` free.
fn binary_search_first_free_pass_budget(
    store: &DreamerRunnerStore<'_>,
    base: &str,
    mut lo: u64,
    mut hi: u64,
) -> u64 {
    while lo.saturating_add(1) < hi {
        let mid = lo + (hi - lo) / 2;
        if pass_budget_row_occupied(store, base, mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    hi
}
