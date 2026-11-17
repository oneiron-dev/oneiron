//! Moved from `crates/oneiron/src/calendar/connectors/outbound.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// What a local write intends to do to the remote calendar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarWriteAction {
    /// Create or replace one resource.
    Upsert,
    /// Remove one resource.
    Delete,
}

impl CalendarWriteAction {
    /// Wire token for this action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }
}

/// The four states one durable write-outbox row moves through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalendarWriteOutboxState {
    /// Staged and durable; the provider has not been called yet.
    Prepared,
    /// The provider accepted the write; the local commit has not landed.
    RemoteApplied,
    /// The precondition failed: resume by reconciling, never by rewriting.
    ReconcileRequired,
    /// The passport and cursor caught up; the row is closed.
    Committed,
}

impl oneiron_contracts::lifecycle::Lifecycle for CalendarWriteOutboxState {
    type Kind = Self;

    fn kind(&self) -> Self::Kind {
        *self
    }

    fn next_kinds(kind: Self::Kind) -> &'static [Self::Kind] {
        match kind {
            Self::Prepared => &[Self::RemoteApplied, Self::ReconcileRequired],
            Self::RemoteApplied => &[Self::Committed],
            // A closed row restages the next owner mutation under its stable key (outbound.rs restage comment).
            Self::Committed => &[Self::Prepared],
            Self::ReconcileRequired => &[],
        }
    }
}
