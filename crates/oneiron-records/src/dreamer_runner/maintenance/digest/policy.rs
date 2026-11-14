//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/digest/policy.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The cadence row's name in a revert's settings list.
pub const CADENCE_ROW: &str = "cadence";

/// The presentation row's name in a revert's settings list.
pub const PRESENTATION_ROW: &str = "presentation";
