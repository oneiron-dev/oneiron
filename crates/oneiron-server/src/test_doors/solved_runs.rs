//! Doors for `tests/library_draft_task_type.rs` (FIX 10508): what a
//! `self.browser.library.draft` call names for its solved-run capture.

use oneiron::browser_library::SolvedSource;
use oneiron::learning::TypeRef;
use serde_json::Value;

/// What a capture reads on the page and keeps for a call: its subgoal, how
/// many checks it names, its task type, its source, where its span starts
/// and the entry it ends with when the call names one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedSpanView {
    pub subgoal: String,
    pub checks: usize,
    pub type_ref: TypeRef,
    pub source: SolvedSource,
    pub after_seq: Option<u64>,
    pub through_seq: Option<u64>,
}

/// What the call's capture names for a `self.browser.library.draft` call
/// with `input`, its answer `output` and the history mark `mark` before it:
/// `Ok(None)` for no capture; `Err` with the cause the call logs.
///
/// # Errors
///
/// The cause a capture is not made, as the call logs it.
pub fn draft_checked_span(
    vault: &oneiron::Vault,
    input: &Value,
    output: &Value,
    mark: Option<u64>,
) -> Result<Option<CheckedSpanView>, String> {
    crate::api::draft_checked_span(vault, input, output, mark)
}
