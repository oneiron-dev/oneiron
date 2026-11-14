//! Moved from `crates/oneiron/src/learning/project.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The fitted value of one setting, as of its last projection.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SettingFit {
    pub value: f64,
    pub runs: f64,
    pub at: u64,
}

pub const VALUE_KIND: &str = "estimate";
