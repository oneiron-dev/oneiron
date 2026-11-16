//! Moved from `crates/oneiron/src/edit_distance/compile.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// What a revision changes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActingTarget {
    /// The generating actor's standing instructions.
    Charter { actor: EntityId },
    /// The brief the generator's reviewed work was written to, named by the
    /// review scope.
    Brief { actor: EntityId, scope: String },
}

/// Where a revision stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RevisionStatus {
    /// Waiting for the responsible role.
    Pending,
    /// Accepted by `by`: the published revision its target's owner applies.
    Accepted { by: EntityId, at: u64 },
    /// Declined by `by`, with the reason as written.
    Declined {
        by: EntityId,
        at: u64,
        reason: String,
    },
    /// Replaced, before an answer, by a newer compilation.
    Superseded { by_revision: String, at: u64 },
    /// Accepted, then applied by `by` at `at`: `version` of its target is
    /// the first that carries its text.
    Applied {
        accepted_by: EntityId,
        accepted_at: u64,
        by: EntityId,
        at: u64,
        version: String,
    },
}
