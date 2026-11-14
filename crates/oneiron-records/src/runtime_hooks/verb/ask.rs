//! Moved from `crates/oneiron/src/runtime_hooks/verb/ask.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub(super) use crate::runtime_hooks::verb::ask::outcome::SavedOutcome;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

/// The most bytes of a drained call's saved error message.
pub const MAX_SAVED_VERB_ERROR_BYTES: usize = 4_096;

/// `text`, cut to `max` bytes on a character boundary.
pub fn cut(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
pub mod outcome;
