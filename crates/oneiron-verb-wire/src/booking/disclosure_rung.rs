//! Moved from `crates/oneiron/src/booking/disclosure_rung.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// A `Busy`-rung row: an opaque interval carrying no event material at all.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct BusyBlockRow {
    pub start_utc: u64,
    pub end_utc: u64,
}
