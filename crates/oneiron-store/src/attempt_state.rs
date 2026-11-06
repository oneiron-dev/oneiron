//! Persisted queued-attempt lifecycle states and their pure predicates.

use serde::{Deserialize, Serialize};

/// Durable lifecycle state persisted on each attempt row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub enum AttemptState {
    Queued,
    Leased,
    Paused,
    Completed,
    Failed,
    Cancelled,
    // Append-only: persisted unit-enum variants are encoded by index, so a new
    // variant may only be added AFTER every existing one. Reordering would
    // silently re-map already-written rows.
    /// Minted by [`crate::attempt_queue::AttemptQueue::retry`]: a fresh try
    /// waiting for its `scheduled_at` instant. Claimable only once
    /// `now >= scheduled_at`.
    Scheduled,
    /// ONE-1896: the worker accepted a stop and is finishing. It still HOLDS
    /// its lease, so it is neither queued work nor terminal work, and it is
    /// deliberately not [`Self::Completed`] — a landing is an honest,
    /// resumable stop, not a delivered result.
    Landing,
    /// The executor stopped without delivering a result and without anyone
    /// stopping it. Terminal, and deliberately not [`Self::Failed`]: nothing
    /// reported a fault, the work simply stopped being carried. Deliberately
    /// not [`Self::Cancelled`] either: no operator or authority asked for it.
    ///
    /// An abandoned row always names the last durable exhaust it produced
    /// through [`crate::attempt_queue::AttemptRecord::result_ref`], so the stop is auditable even
    /// though nothing completed.
    Abandoned,
}

impl AttemptState {
    /// Returns the stable wire string for this attempt state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Leased => "leased",
            Self::Paused => "paused",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Scheduled => "scheduled",
            Self::Landing => "landing",
            Self::Abandoned => "abandoned",
        }
    }

    /// True while the row can still reach a terminal state, so it still owns
    /// its advisory dedupe entry.
    ///
    /// [`Self::Abandoned`] is absent: it IS a terminal state, so an abandoned
    /// row keeps no dedupe claim and can never re-enter queued or leased work.
    pub const fn is_pending(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Leased | Self::Paused | Self::Scheduled | Self::Landing
        )
    }

    /// True for the two states a ready-index row may legitimately sit in.
    ///
    /// [`Self::Landing`] is deliberately absent: a landing attempt owns a live
    /// lease and is doing bounded finishing work, so handing it out as ordinary
    /// queued work would run it twice.
    pub const fn is_ready_indexed(self) -> bool {
        matches!(self, Self::Queued | Self::Scheduled)
    }

    /// True while a worker holds this row's lease and runtime.
    #[must_use]
    pub const fn is_running(self) -> bool {
        matches!(self, Self::Leased | Self::Landing)
    }

    /// True once the row can never transition again.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Abandoned
        )
    }
}
