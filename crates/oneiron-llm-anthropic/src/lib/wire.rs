//! Anthropic Messages protocol mapping: request build, response parse, message/part/tool codecs, usage, status classification.

use std::collections::BTreeMap;

use oneiron::{
    ContentPart, FatalLlmError, FinishReason, ImageContent, LlmError, LlmInputUsage, LlmMessage,
    LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmResult, LlmToolSpec, LlmUsage,
    ResponseFormat, RetryableLlmError,
};
use serde_json::{Map as JsonMap, Value as JsonValue, json};

use super::backend::validate_capabilities;
use super::{AnthropicMessagesConfig, AnthropicMessagesHttpRequest, AnthropicProviderOptions};

pub fn build_anthropic_messages_request(
    config: &AnthropicMessagesConfig,
    request: &LlmRequest,
    stream: bool,
) -> LlmResult<AnthropicMessagesHttpRequest> {
    let catalog = config.catalog_entry(&request.model)?;
    let provider_options = AnthropicProviderOptions::from_request(request)?;
    validate_capabilities(catalog, request, &provider_options, stream)?;

    let mut body = JsonMap::new();
    for (key, value) in &request.params {
        body.insert(key.clone(), value.clone());
    }
    for (key, value) in provider_options.to_wire_fields() {
        body.insert(key, value);
    }
    // Anthropic's /v1/messages defines no response_format parameter; strip any
    // caller-supplied copy so the OpenAI-shaped key never reaches the wire.
    body.remove("response_format");
    body.insert(
        "model".to_owned(),
        JsonValue::String(request.model.name().to_owned()),
    );
    body.insert("stream".to_owned(), JsonValue::Bool(stream));
    body.insert(
        "messages".to_owned(),
        JsonValue::Array(
            request
                .messages
                .iter()
                .filter(|message| message.role != LlmMessageRole::System)
                .map(anthropic_message)
                .collect::<Vec<_>>(),
        ),
    );

    let system = request
        .messages
        .iter()
        .filter(|message| message.role == LlmMessageRole::System)
        .flat_map(|message| message.content.iter())
        .filter_map(text_content)
        .collect::<Vec<_>>()
        .join("\n\n");
    if !system.is_empty() {
        body.insert("system".to_owned(), JsonValue::String(system));
    }

    if !request.tools.is_empty() {
        body.insert(
            "tools".to_owned(),
            JsonValue::Array(request.tools.iter().map(anthropic_tool).collect()),
        );
    }
    if let ResponseFormat::Json { schema } = &request.envelope.response_format {
        // The Anthropic Messages API expresses structured output as
        // `output_config.format`, not OpenAI's top-level `response_format`.
        // Merge into any caller-supplied output_config (e.g. effort) instead
        // of clobbering it; a non-object output_config is a caller error.
        let format = json!({ "type": "json_schema", "schema": schema });
        match body.get_mut("output_config") {
            Some(JsonValue::Object(output_config)) => {
                output_config.insert("format".to_owned(), format);
            }
            Some(_) => return Err(FatalLlmError::InvalidRequest.into()),
            None => {
                body.insert("output_config".to_owned(), json!({ "format": format }));
            }
        }
    }

    Ok(AnthropicMessagesHttpRequest {
        method: "POST",
        path: config.endpoint_path.clone(),
        headers: BTreeMap::from([
            ("content-type".to_owned(), "application/json".to_owned()),
            (
                "anthropic-version".to_owned(),
                config.anthropic_version.clone(),
            ),
        ]),
        body: JsonValue::Object(body),
    })
}

pub fn parse_anthropic_messages_response(body: &JsonValue) -> LlmResult<LlmResponse> {
    let stop_reason = body
        .get("stop_reason")
        .and_then(JsonValue::as_str)
        .map_or(FinishReason::Stop, anthropic_finish_reason);
    let content_blocks = body
        .get("content")
        .and_then(JsonValue::as_array)
        .ok_or(FatalLlmError::EmptyResponse)?;
    let mut content = Vec::new();

    for block in content_blocks {
        match block.get("type").and_then(JsonValue::as_str) {
            Some("text") => {
                if let Some(text) = block.get("text").and_then(JsonValue::as_str)
                    && !text.is_empty()
                {
                    content.push(ContentPart::Text {
                        text: text.to_owned(),
                    });
                }
            }
            Some("thinking") => {
                if let Some(text) = block
                    .get("thinking")
                    .or_else(|| block.get("text"))
                    .and_then(JsonValue::as_str)
                    && !text.is_empty()
                {
                    content.push(ContentPart::Reasoning {
                        text: text.to_owned(),
                        signature: block
                            .get("signature")
                            .and_then(JsonValue::as_str)
                            .map(str::to_owned),
                    });
                }
            }
            Some("tool_use") => {
                let call_id = block
                    .get("id")
                    .and_then(JsonValue::as_str)
                    .ok_or(FatalLlmError::InvalidRequest)?;
                let name = block
                    .get("name")
                    .and_then(JsonValue::as_str)
                    .ok_or(FatalLlmError::InvalidRequest)?;
                content.push(ContentPart::ToolCall {
                    call_id: call_id.to_owned(),
                    name: name.to_owned(),
                    input: block.get("input").cloned().unwrap_or(JsonValue::Null),
                });
            }
            _ => {}
        }
    }

    if content.is_empty() {
        return Err(if matches!(stop_reason, FinishReason::ContentFiltered) {
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
        usage: body
            .get("usage")
            .map_or_else(LlmUsage::zero, parse_anthropic_usage),
        finish_reason: stop_reason,
    })
}

fn text_content(part: &ContentPart) -> Option<String> {
    match part {
        ContentPart::Text { text } | ContentPart::Reasoning { text, .. } => Some(text.clone()),
        _ => None,
    }
}

fn anthropic_message(message: &LlmMessage) -> JsonValue {
    json!({
        "role": anthropic_role(message.role),
        "content": message
            .content
            .iter()
            .map(anthropic_content_part)
            .collect::<Vec<_>>(),
    })
}

fn anthropic_role(role: LlmMessageRole) -> &'static str {
    match role {
        LlmMessageRole::System => "user",
        LlmMessageRole::User | LlmMessageRole::Tool => "user",
        LlmMessageRole::Assistant => "assistant",
    }
}

fn anthropic_content_part(part: &ContentPart) -> JsonValue {
    match part {
        ContentPart::Text { text } => json!({ "type": "text", "text": text }),
        ContentPart::Reasoning { text, signature } => {
            let mut object = JsonMap::new();
            object.insert("type".to_owned(), JsonValue::String("thinking".to_owned()));
            object.insert("thinking".to_owned(), JsonValue::String(text.clone()));
            if let Some(signature) = signature {
                object.insert("signature".to_owned(), JsonValue::String(signature.clone()));
            }
            JsonValue::Object(object)
        }
        ContentPart::ToolCall {
            call_id,
            name,
            input,
        } => json!({
            "type": "tool_use",
            "id": call_id,
            "name": name,
            "input": input,
        }),
        ContentPart::ToolResult {
            call_id,
            output,
            is_error,
        } => json!({
            "type": "tool_result",
            "tool_use_id": call_id,
            "content": output.to_string(),
            "is_error": is_error,
        }),
        ContentPart::Image { media_type, image } => anthropic_image_part(media_type, image),
    }
}

fn anthropic_image_part(media_type: &str, image: &ImageContent) -> JsonValue {
    match image {
        ImageContent::Base64 { data } => json!({
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": media_type,
                "data": data,
            },
        }),
        ImageContent::Url { url } => json!({
            "type": "image",
            "source": {
                "type": "url",
                "url": url,
            },
        }),
    }
}

fn anthropic_tool(tool: &LlmToolSpec) -> JsonValue {
    json!({
        "name": &tool.name,
        "description": &tool.description,
        "input_schema": &tool.input_schema,
    })
}

pub(super) fn parse_anthropic_usage(usage: &JsonValue) -> LlmUsage {
    let input_tokens = u64_field(usage, "input_tokens");
    let cache_read = u64_field(usage, "cache_read_input_tokens");
    let cache_write = u64_field(usage, "cache_creation_input_tokens");
    let output_tokens = u64_field(usage, "output_tokens");
    LlmUsage {
        input: LlmInputUsage {
            total: input_tokens,
            cache_read,
            cache_write,
        },
        output: LlmOutputUsage {
            total: output_tokens,
            text: output_tokens,
            reasoning: 0,
        },
        raw_provider: usage.clone(),
    }
}

pub(super) fn anthropic_finish_reason(reason: &str) -> FinishReason {
    match reason {
        "end_turn" | "stop_sequence" => FinishReason::Stop,
        "max_tokens" => FinishReason::Length,
        "tool_use" => FinishReason::ToolCalls,
        "refusal" | "content_filter" => FinishReason::ContentFiltered,
        other => FinishReason::Other {
            name: other.to_owned(),
        },
    }
}

pub fn classify_anthropic_status(
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &JsonValue,
) -> LlmError {
    if is_content_filter_error(body) || status == 451 {
        return FatalLlmError::ContentFiltered.into();
    }

    if let Some(error_type) = body
        .get("error")
        .and_then(|error| error.get("type"))
        .and_then(JsonValue::as_str)
    {
        match error_type {
            "rate_limit_error" => {
                return RetryableLlmError::RateLimited {
                    retry_after: retry_after_seconds(headers, body),
                }
                .into();
            }
            "overloaded_error" | "api_error" => return RetryableLlmError::ServerError.into(),
            "authentication_error" | "permission_error" => return FatalLlmError::Auth.into(),
            "invalid_request_error" | "not_found_error" => {
                return FatalLlmError::InvalidRequest.into();
            }
            _ => {}
        }
    }

    match status {
        408 | 504 => RetryableLlmError::Timeout.into(),
        429 => RetryableLlmError::RateLimited {
            retry_after: retry_after_seconds(headers, body),
        }
        .into(),
        500..=599 => RetryableLlmError::ServerError.into(),
        401 | 403 => FatalLlmError::Auth.into(),
        400 | 404 | 413 | 422 => FatalLlmError::InvalidRequest.into(),
        _ if status >= 500 => RetryableLlmError::ServerError.into(),
        _ => FatalLlmError::InvalidRequest.into(),
    }
}

fn retry_after_seconds(headers: &BTreeMap<String, String>, body: &JsonValue) -> Option<u64> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.parse::<u64>().ok())
        .or_else(|| {
            body.get("error")
                .and_then(|error| error.get("retry_after"))
                .and_then(JsonValue::as_u64)
        })
}

fn is_content_filter_error(body: &JsonValue) -> bool {
    body.get("error").is_some_and(|error| {
        error
            .get("type")
            .and_then(JsonValue::as_str)
            .is_some_and(|kind| kind == "content_filter_error" || kind == "content_filtered")
    })
}

fn u64_field(value: &JsonValue, key: &str) -> u64 {
    value.get(key).and_then(JsonValue::as_u64).unwrap_or(0)
}
