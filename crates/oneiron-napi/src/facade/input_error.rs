//! Typed input refusals for the scoped SDK client, not the legacy bridge.

use oneiron::MemoryError;

use super::facade_error;

/// Only use for caller-input conversion, never engine or output failures.
pub(super) fn witness_input_error(reason: String) -> napi::Error {
    facade_error(MemoryError {
        code: oneiron::memory::MEMORY_CODE_BAD_REQUEST.to_owned(),
        message: reason,
        suggestions: vec![
            "Set messages[].author to user, companion, or system.".to_owned(),
            "Set messages[].metadata to a JSON object, or omit metadata.".to_owned(),
        ],
        successor_short_id: None,
        gate_denial: None,
        read_receipt: None,
        policy_denial: None,
    })
}
