//! Moved from `crates/oneiron/src/skill_reliability/projector.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;

/// The existing attempt success lane measures this axis unless explicitly stamped.
pub const SKILL_OUTCOME_AXIS: &str = "quality";
