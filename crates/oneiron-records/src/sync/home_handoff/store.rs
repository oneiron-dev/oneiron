//! Moved from `crates/oneiron/src/sync/home_handoff/store.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// Which end of a handoff this node was.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HandoffRole {
    Source,
    Target,
}
