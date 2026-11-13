//! Moved from `crates/oneiron/src/memory/shape_doors.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The refusal of an `after` that names no handle to poll.
pub const AFTER_NEEDS_HANDLE: &str = "describe(after) polls a handle: name the handle it observed";
