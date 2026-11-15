//! Moved from `crates/oneiron/src/sync/home_handoff/mod.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

/// A handoff's id: the hash of its signed header.
pub type HandoffId = [u8; 32];

/// Where one handoff stands on this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandoffStatus {
    /// The source froze its rows and sealed them; no ack yet.
    Frozen,
    /// The target acked; the source keeps its rows as history.
    Acked,
    /// The target adopted every section.
    Adopted,
    /// No carrier moved the state (CALLS: no carrier).
    Incomplete(IncompleteReason),
    /// The source froze it, its target provably never adopted it, and the
    /// source took its state back (FIX 5931). Kept as history.
    Cancelled,
}

/// Why a home move carried nothing. The new home keeps today's local
/// opening; nothing refuses for it (CALLS: no carrier).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum IncompleteReason {
    /// The old home was gone before it exported.
    SourceGone,
    /// The move's lineage does not chain to one this node knows.
    UnknownLineage,
    /// Rows or a handoff here conflict with the move.
    Conflict,
    /// The move's target has no machine or endpoint known here.
    NoRoute,
    /// The target's persisted answer could not be read: out of reach,
    /// refused, or another machine on its socket. Not a proof either way.
    Unresolved,
    /// The new home opened with no usable handoff for its move staged
    /// (FIX 6457): what it opens locally is not the lineage's state.
    NotArrived,
}

pub fn refused(reason: &'static str) -> Error {
    Error::InvalidConfig(format!("home handoff refused: {reason}"))
}
pub mod envelope;
pub mod store;
