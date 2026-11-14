//! Moved from `crates/oneiron/src/training_pack/detector_corpus.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// The one label unit a head trains on; a window label never becomes a
/// target label.
pub const TARGET_UNIT: &str = "target";
