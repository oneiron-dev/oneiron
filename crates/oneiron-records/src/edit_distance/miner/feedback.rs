//! Moved from `crates/oneiron/src/edit_distance/miner/feedback.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use rmpv::Value;
use serde::Deserialize;
use serde::Serialize;

pub const LABEL: &str = "principal-bound inbox decision";
