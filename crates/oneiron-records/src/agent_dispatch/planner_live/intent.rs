//! Moved from `crates/oneiron/src/agent_dispatch/planner_live/intent.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Domain of an intent's ask digest.
pub const ASK_DIGEST_CONTEXT: &str = "oneiron spawn planned intent ask v1";

pub const CUSTODY_LOST: &str = "another call took custody of this planned spawn before it settled; \
     ask again under the same intent key to read where it stands";
pub mod child;
