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
        wrong_root: None,
        hook: None,
        retry_after: None,
        resets_at: Vec::new(),
        reason_codes: Vec::new(),
    })
}

/// Any caller-input conversion's refusal (FIX 8116): the typed
/// `BAD_REQUEST` the facade's other doors raise for bad input, its
/// suggestion naming the field the reason leads with. Engine refusals keep
/// their own code, and an output or invariant failure keeps the plain
/// `boundary_error`: only the caller's own input is blamed here.
pub(super) fn caller_input_error(reason: String) -> napi::Error {
    let field = reason
        .split_whitespace()
        .next()
        .unwrap_or("the input")
        .trim_end_matches([':', ',', ';']);
    let suggestion = format!("Correct {field} as the message says, then call again.");
    facade_error(MemoryError::bad_request_with(
        reason,
        &[suggestion.as_str()],
    ))
}
