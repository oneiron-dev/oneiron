//! Response output parsing and socket event inspection.
//! Entry: parse_openai_responses_output.
//! Private decode helpers stay in the parent; the parent re-exports the moved functions.

use super::{
    ContentPart, FatalLlmError, FinishReason, JsonValue, LlmMessage, LlmMessageRole, LlmResponse,
    LlmResult, LlmUsage, parse_function_call, parse_responses_usage, reasoning_signature,
    reasoning_text, responses_finish_reason,
};

/// The `type` of one socket event.
#[must_use]
pub fn responses_event_type(event: &JsonValue) -> &str {
    event.get("type").and_then(JsonValue::as_str).unwrap_or("")
}

/// Whether `event` ends its turn: completed, incomplete, failed, or an error.
#[must_use]
pub fn responses_event_is_terminal(event: &JsonValue) -> bool {
    matches!(
        responses_event_type(event),
        "response.completed" | "response.incomplete" | "response.failed" | "error"
    )
}

/// The `error.code` of an `error` event.
#[must_use]
pub fn responses_error_code(event: &JsonValue) -> Option<&str> {
    (responses_event_type(event) == "error")
        .then(|| event.get("error")?.get("code")?.as_str())
        .flatten()
}

/// A finished response object as one reply: its output items in order, its
/// usage, and the finish its status names.
pub fn parse_openai_responses_output(response: &JsonValue) -> LlmResult<LlmResponse> {
    let output = response
        .get("output")
        .and_then(JsonValue::as_array)
        .ok_or(FatalLlmError::EmptyResponse)?;
    let model = response
        .get("model")
        .and_then(JsonValue::as_str)
        .unwrap_or_default();
    let mut content = Vec::new();
    for item in output {
        match item.get("type").and_then(JsonValue::as_str) {
            Some("message") => {
                for part in item
                    .get("content")
                    .and_then(JsonValue::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(text) = part
                        .get("text")
                        .or_else(|| part.get("refusal"))
                        .and_then(JsonValue::as_str)
                        && !text.is_empty()
                    {
                        content.push(ContentPart::Text {
                            text: text.to_owned(),
                        });
                    }
                }
            }
            Some("reasoning") => {
                let text = reasoning_text(item);
                let signature = reasoning_signature(item, model);
                if !text.is_empty() || signature.is_some() {
                    content.push(ContentPart::Reasoning { text, signature });
                }
            }
            Some("function_call") => {
                content.push(parse_function_call(item).ok_or(FatalLlmError::InvalidRequest)?);
            }
            // A built-in tool this adapter never offers could stand behind the
            // text: the decode fails rather than read tool-free.
            Some(other) if other.ends_with("_call") => {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            _ => {}
        }
    }
    let finish_reason = responses_finish_reason(response, &content);
    if content.is_empty() {
        return Err(if matches!(finish_reason, FinishReason::ContentFiltered) {
            FatalLlmError::ContentFiltered.into()
        } else {
            FatalLlmError::EmptyResponse.into()
        });
    }
    Ok(LlmResponse {
        message: LlmMessage {
            role: LlmMessageRole::Assistant,
            content,
        },
        usage: response
            .get("usage")
            .map_or_else(LlmUsage::zero, parse_responses_usage),
        finish_reason,
        // A provider's reply asserts no record: its host alone does (FIX 3416).
        reply_assertions: Default::default(),
        token_scores: None,
    })
}
