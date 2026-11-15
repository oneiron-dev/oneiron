//! Doors for `oneiron-server`'s `tests/rest_snake_case_verb_grammar.rs`
//! (UC02-GUEST-REFUSAL-GRAMMAR = A): the refusal objects a guest's result
//! call throws, and the result search input's decode.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use serde_json::Value;

/// The refusal a result call throws for `code`.
pub fn result_refusal(code: &str) -> Value {
    crate::code_run::result_read_grammar_door::refusal(code)
}

/// The unknown-handle refusal when the run holds no live result.
pub fn unknown_handle_refusal() -> Value {
    crate::code_run::result_read_grammar_door::unknown_handle()
}

/// Whether `input` decodes as a result search's input; the refusal otherwise.
pub fn decode_result_search_input(input: Value) -> Result<(), Value> {
    crate::code_run::result_read_grammar_door::decode_search_input(input)
}
