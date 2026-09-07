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
    })
}

#[cfg(test)]
mod tests {
    use super::{MemoryError, witness_input_error};

    #[test]
    fn witness_input_error_serializes_the_typed_contract() {
        let reason = r#"author must be one of user, companion, system; got "assistant""#;
        let error = witness_input_error(reason.to_owned());
        let payload: MemoryError =
            serde_json::from_str(&error.reason).expect("serialized MemoryError");
        assert_eq!(payload.code, "BAD_REQUEST");
        assert_eq!(payload.message, reason);
        assert_eq!(
            payload.suggestions,
            [
                "Set messages[].author to user, companion, or system.",
                "Set messages[].metadata to a JSON object, or omit metadata.",
            ]
        );
        assert!(payload.successor_short_id.is_none());
        assert!(payload.gate_denial.is_none());
    }
}
