//! The one expiry instant (UC-12): a row or a lease that lives until `expires_at` is dead from
//! that second on (`now >= expires_at`), and an entry due at `due_at` is due from that second on
//! (`due_at <= now`). Every lease, every expiring row and every due index judges its boundary
//! second this way, as Schedule's `run_due` does, and reads it through these functions, so no two
//! doors of one row disagree at that second.
//!
//! Each function compares plain `u64`s, so `now` and the deadline must share one unit (vault
//! seconds, or milliseconds for the millisecond rows) and one clock. Each site keeps its own
//! overflow rule for computing a deadline: [`expires_at_checked`] refuses a deadline past
//! `u64::MAX`, and [`expires_at_saturating`] holds it there, so that row never expires.

/// Whether a row or lease that lives until `expires_at` is dead at `now`: from its `expires_at`
/// second on.
#[must_use]
pub const fn is_expired(now: u64, expires_at: u64) -> bool {
    now >= expires_at
}

/// Whether an entry due at `due_at` is due at `now`: from its `due_at` second on.
#[must_use]
pub const fn is_due(now: u64, due_at: u64) -> bool {
    due_at <= now
}

/// The `expires_at` of a row that lives `ttl` from `now`, or `None` when that passes `u64::MAX`,
/// for a site that refuses such a row.
#[must_use]
pub const fn expires_at_checked(now: u64, ttl: u64) -> Option<u64> {
    now.checked_add(ttl)
}

/// The `expires_at` of a row that lives `ttl` from `now`, held at `u64::MAX`, for a site whose
/// row then never expires.
#[must_use]
pub const fn expires_at_saturating(now: u64, ttl: u64) -> u64 {
    now.saturating_add(ttl)
}
