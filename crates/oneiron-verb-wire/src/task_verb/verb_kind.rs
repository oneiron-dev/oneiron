//! Moved from `crates/oneiron/src/task_verb/verb_kind.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Absolute expiry instant. A relative duration would mean a different wall
/// time on every replica, so the caller's clock is resolved once, here.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct TaskTtl {
    pub deadline_at: u64,
}

impl TaskTtl {
    /// An already-absolute deadline.
    #[must_use]
    pub const fn at(deadline_at: u64) -> Self {
        Self { deadline_at }
    }

    /// Resolves `now + duration` to the stored absolute deadline.
    #[must_use]
    pub const fn after(now: u64, duration_seconds: u64) -> Self {
        Self {
            deadline_at: now.saturating_add(duration_seconds),
        }
    }
}
