//! Moved from `crates/oneiron/src/store/known_value_index.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::store::known_history::KNOWN_TAG_BYTES;

/// How many bytes of a value's first window its tag keeps.
pub const TAG_BYTES: usize = KNOWN_TAG_BYTES;
