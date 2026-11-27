//! The TURN extraction answer's JSON Schema (HOUSE-SCHEMA): the own-server body field that
//! carries it, the shipped `extraction_answer_schema.json`, and what the schema door reads.

#[cfg(oneiron_test_support)]
use std::collections::BTreeMap;

use serde_json::Value as JsonValue;

#[cfg(oneiron_test_support)]
use super::{check_extraction_reply, extraction_request_params};
use crate::dreamer_consolidation::support::invalid_consolidation;
use crate::error::Result;

/// The own-server body field that carries a TURN extraction answer's JSON
/// Schema (HOUSE-SCHEMA). The house EXL3 server holds the answer, never the
/// thought, to it; a server that does not read it ignores it, and a hosted
/// rung is sent none. It is not `response_format`, so a provider set to
/// `response_format = "none"` (the house deploy) still sends it, and no rung
/// needs `JsonResponse` for it.
pub(in crate::dreamer_consolidation) const ANSWER_SCHEMA_PARAM: &str = "answer_schema";

/// The TURN extraction answer's JSON Schema, the shipped
/// `extraction_answer_schema.json`, read as the shipped extraction prompt is.
pub(super) fn extraction_answer_schema() -> Result<JsonValue> {
    serde_json::from_str(include_str!("../extraction_answer_schema.json"))
        .map_err(|_| invalid_consolidation("shipped extraction answer schema is not readable"))
}

/// The shipped answer schema, parsed, for `test_doors::dreamer_extraction_schema`.
#[cfg(oneiron_test_support)]
pub(crate) fn extraction_answer_schema_for_test() -> Result<JsonValue> {
    extraction_answer_schema()
}

/// [`extraction_request_params`] for `test_doors::dreamer_extraction_schema`.
#[cfg(oneiron_test_support)]
pub(crate) fn extraction_request_params_for_test(
    answer_schema: bool,
) -> Result<BTreeMap<String, JsonValue>> {
    extraction_request_params(answer_schema)
}

/// [`check_extraction_reply`] over `text` with finish Stop, for the schema door.
#[cfg(oneiron_test_support)]
pub(crate) fn check_extraction_reply_for_test(text: &str) -> std::result::Result<(), String> {
    let response = oneiron_model::llm::LlmResponse {
        message: oneiron_model::llm::LlmMessage {
            role: oneiron_model::llm::LlmMessageRole::Assistant,
            content: vec![oneiron_model::llm::ContentPart::Text {
                text: text.to_owned(),
                signature: None,
            }],
        },
        usage: oneiron_model::llm::LlmUsage::zero(),
        finish_reason: oneiron_model::llm::FinishReason::Stop,
        reply_assertions: Default::default(),
        token_scores: None,
    };
    check_extraction_reply(&response)
}
