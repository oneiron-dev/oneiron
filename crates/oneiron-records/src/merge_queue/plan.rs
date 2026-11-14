//! Moved from `crates/oneiron/src/merge_queue/plan.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;

/// Where a repository keeps its check plan, relative to its root.
pub const REPO_CHECK_PLAN_PATH: &str = ".oneiron/checks.json";

/// The only plan schema this engine reads.
pub const REPO_CHECK_PLAN_SCHEMA: u8 = 1;
