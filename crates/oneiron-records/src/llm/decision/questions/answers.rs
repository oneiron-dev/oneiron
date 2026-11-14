//! Moved from `crates/oneiron/src/llm/decision/questions/answers.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine;
use serde::Deserialize;
use serde::Serialize;
use std::ops::Bound;

/// The cursor's wire version.
pub const CURSOR_VERSION: u8 = 1;
