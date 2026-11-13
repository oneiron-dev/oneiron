//! Moved from `crates/oneiron/src/llm/decision/questions/criteria.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The most bytes one criteria line holds.
pub const MAX_CRITERION_BYTES: usize = 512;
