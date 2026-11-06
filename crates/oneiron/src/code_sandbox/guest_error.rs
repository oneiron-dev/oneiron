//! A guest program's own error text, as the model reads it.

use super::source::{PreparedSource, split_guest_error};
use crate::Error;

/// Characters of a guest's error text a failed step keeps. A program can
/// throw text of any size; its head says why.
const GUEST_ERROR_CHARS: usize = 2048;

/// The guest's own error text for a failed step, so the model learns why its
/// program stopped. The guest's position header never reaches it; a
/// TypeScript program's error ends with where it threw in the TypeScript
/// source, past the text's cut, and a JavaScript program's is as it was.
pub(crate) fn guest_failure(message: &str, prepared: &PreparedSource<'_>) -> Error {
    let (message, at) = split_guest_error(message);
    let mut text: String = message.chars().take(GUEST_ERROR_CHARS).collect();
    if text.len() < message.len() {
        text.push_str(&format!(" … ({} bytes in all)", message.len()));
    }
    if let Some(position) = prepared.failure_position(at) {
        text.push_str(&position);
    }
    Error::InvalidConfig(format!("guest reported step failure: {text}"))
}
