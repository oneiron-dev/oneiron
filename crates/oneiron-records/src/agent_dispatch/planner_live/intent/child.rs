//! Moved from `crates/oneiron/src/agent_dispatch/planner_live/intent/child.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Serialize;
use std::collections::HashSet;

/// Domain of a leased intent's request digest.
pub const LEASED_ASK_DIGEST_CONTEXT: &str = "oneiron spawn leased intent ask v1";
