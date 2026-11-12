//! Moved from `crates/oneiron/src/embed/space_probe.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// Longest probe query, in bytes.
pub const SPACE_PROBE_QUERY_MAX_LEN: usize = 2048;
