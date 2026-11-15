//! Door for `tests/api_refusal_answers.rs` (UC-11): what five core routes'
//! refusal maps answer an engine refusal code with, the whole error as the
//! envelope carries it, so one test pins status, code, words and
//! suggestions per route and code without a fixture that makes the engine
//! refuse.

/// What the run control, booking boundary, transcript, scratchpad and
/// message result maps answer a refusal whose code is `code` with, in that
/// order, each as its `Debug` form.
#[must_use]
pub fn api_plane_answers(code: &str) -> [String; 5] {
    crate::api::memory_code_answers_for_test(code).map(|answer| format!("{answer:?}"))
}
