//! Door for `tests/dreamer_extraction_answer_schema.rs` (HOUSE-SCHEMA): the shipped
//! TURN extraction answer schema, the params a TURN extraction request carries
//! and those a NOTE review request carries, and `check_extraction_reply` over
//! a reply text with finish Stop.

use std::collections::BTreeMap;

use crate::dreamer_consolidation::{
    check_extraction_reply_for_test, extraction_answer_schema_for_test,
    extraction_request_params_for_test,
};
use crate::error::Result;

/// The shipped TURN extraction answer schema, parsed.
///
/// # Errors
///
/// The shipped schema file does not parse.
pub fn answer_schema() -> Result<serde_json::Value> {
    extraction_answer_schema_for_test()
}

/// The params a TURN extraction request carries (with the answer schema).
///
/// # Errors
///
/// The shipped schema file does not parse.
pub fn turn_params() -> Result<BTreeMap<String, serde_json::Value>> {
    extraction_request_params_for_test(true)
}

/// The params a NOTE review request carries (no schema).
///
/// # Errors
///
/// Never fails today; kept fallible to match [`turn_params`].
pub fn note_params() -> Result<BTreeMap<String, serde_json::Value>> {
    extraction_request_params_for_test(false)
}

/// `check_extraction_reply` over `text` with finish Stop: `Ok(())` or the
/// first contract fault, as the extraction step reports it.
#[must_use]
pub fn check_reply(text: &str) -> std::result::Result<(), String> {
    check_extraction_reply_for_test(text)
}
