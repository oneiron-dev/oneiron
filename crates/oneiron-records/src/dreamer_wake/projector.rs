//! Moved from `crates/oneiron/src/dreamer_wake/projector.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// A TURN's own temporal key, `(learned_at, id)`.
pub type TurnKey = (u64, EntityId);

/// The projector's policy row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectorPolicy {
    /// New statements a due window needs before its wake writes. Zero writes
    /// on every due wake. Above one, a window with fewer is consumed unread.
    pub min_new_statements: u32,
}
