//! Moved from `crates/oneiron/src/task_type/placement.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// The routed skill that owns placement.
pub const PLACEMENT_SKILL_ID: &str = "task_type.placement";
