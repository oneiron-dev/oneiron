//! Moved from `crates/oneiron/src/edit_distance/publisher/interview.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

pub fn interview_corrupt() -> Error {
    Error::CorruptedIndex("interview session record")
}
