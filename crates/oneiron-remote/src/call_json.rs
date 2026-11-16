//! The one language boundary every binding crosses (UC-02 B0; fable/20 §1.1).
//!
//! Data crosses as the engine's JSON text: a verb's input goes in as the
//! serde form of the input type its row names, and its output comes back as
//! the serde form of the output type. A binding hands the text over without
//! reading a field, so every input that does not fit its type is refused in
//! one place, the engine's input decode: `BAD_REQUEST` "invalid SDK request"
//! with the path of the field, the same answer HTTP and MCP give.
//!
//! The error crosses the same way: [`error_json`] is the whole engine error,
//! all of its fields, as the JSON text each binding throws.
//!
//! This module makes only two errors of its own: input text that is not one
//! JSON document is `BAD_REQUEST`, and an answer that cannot be written as
//! text is `INTERNAL_SERVER_ERROR`. Every other refusal is the engine's, or
//! the transport's on a connected handle, and crosses unchanged.

use oneiron::memory::{MEMORY_CODE_INTERNAL, MemoryError};

use crate::OneironClient;
use crate::error::{bad_request, sdk_error};

impl OneironClient {
    /// One verb: its engine input as JSON text in, its engine output as JSON
    /// text out.
    ///
    /// The text is parsed with `serde_json`'s default nesting limit (128), as
    /// the HTTP door parses a request body, and then runs through
    /// [`OneironClient::agent_verb`]: the same verb check, input check and
    /// backend dispatch every generated method uses.
    ///
    /// # Errors
    ///
    /// `BAD_REQUEST` when `input_json` is not exactly one JSON document; the
    /// engine's or the server's refusal of the verb, unchanged; and
    /// `INTERNAL_SERVER_ERROR` when the answer cannot be written as text.
    pub fn call_json(&self, verb: &str, input_json: &str) -> Result<String, MemoryError> {
        let input: serde_json::Value = serde_json::from_str(input_json).map_err(|error| {
            bad_request(
                format!("invalid SDK request: the input is not one JSON document: {error}"),
                &["Send the verb's input as one JSON object, as its row's input type spells it."],
            )
        })?;
        let output = self.agent_verb(verb, input)?;
        serde_json::to_string(&output).map_err(|error| {
            sdk_error(
                MEMORY_CODE_INTERNAL,
                format!("the {verb} answer could not be written as JSON text: {error}"),
                &["Report this answer as an SDK bug; the verb itself ran."],
            )
        })
    }
}

/// The engine error as the JSON text every binding throws: the serde form of
/// [`MemoryError`], whole, with every field it carries.
///
/// Writing a `MemoryError` as text does not fail for any value the engine
/// makes. Should it ever fail, the text is still one JSON document: the
/// error's `code`, `message` and `suggestions`, which are plain strings.
#[must_use]
pub fn error_json(error: &MemoryError) -> String {
    serde_json::to_string(error).unwrap_or_else(|_| {
        serde_json::json!({
            "code": error.code,
            "message": error.message,
            "suggestions": error.suggestions,
        })
        .to_string()
    })
}
