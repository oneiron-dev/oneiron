//! Chat-completions protocol mapping: request build, response parse, message/tool codecs, usage, status classification.

use super::{
    OpenAiCompatConfig, OpenAiCompatHttpRequest, OpenAiProviderOptions,
    backend::validate_capabilities,
};
use oneiron::llm::{REASONING_BUDGET_PARAM, ReasoningEffort, limit};
use oneiron::{
    ContentPart, FatalLlmError, FinishReason, ImageContent, LlmError, LlmInputUsage, LlmMessage,
    LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmResult, LlmToolSpec, LlmUsage,
    ModelLocality, ResponseFormat, RetryableLlmError,
};
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use std::collections::BTreeMap;

pub fn build_openai_chat_request(
    config: &OpenAiCompatConfig,
    request: &LlmRequest,
    stream: bool,
) -> LlmResult<OpenAiCompatHttpRequest> {
    // The model id and the catalog row pick the model and the route; a param
    // or provider option never does.
    if request.route_selector_override().is_some() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let catalog = config.catalog_entry(&request.model)?;
    let provider_options = OpenAiProviderOptions::from_request(request)?;
    validate_capabilities(catalog, request, &provider_options, stream)?;

    let mut body = JsonMap::new();
    for (key, value) in &request.params {
        body.insert(key.clone(), value.clone());
    }
    for (key, value) in provider_options.to_wire_fields() {
        body.insert(key, value);
    }
    if let Some(effort) = request.envelope.seat_effort {
        // The seat pin wins after both generic params and provider fields. Keep
        // unrelated summary controls, but never a competing effort value.
        let reasoning = match body.remove("reasoning") {
            Some(JsonValue::Object(mut options)) => {
                options.remove("effort");
                Some(options)
            }
            Some(_) => return Err(FatalLlmError::InvalidRequest.into()),
            None => None,
        };
        for key in ["reasoning_effort", "thinking", "output_config"] {
            body.remove(key);
        }
        if effort != ReasoningEffort::None {
            if let Some(options) = reasoning
                && !options.is_empty()
            {
                body.insert("reasoning".into(), JsonValue::Object(options));
            }
            body.insert("reasoning_effort".into(), json!(effort));
        }
        // An own server (llama.cpp, vLLM, an exllamav3 server) also reads the
        // level through its chat template, and llama.cpp reads the thinking
        // budget per request. A hosted API takes the effort alone and refuses
        // fields it does not know, so it is sent neither.
        if request.envelope.locality == ModelLocality::OwnServer {
            let mut kwargs = match body.remove("chat_template_kwargs") {
                Some(JsonValue::Object(kwargs)) => kwargs,
                Some(_) => return Err(FatalLlmError::InvalidRequest.into()),
                None => JsonMap::new(),
            };
            kwargs.remove("reasoning_effort");
            kwargs.remove("enable_thinking");
            if effort == ReasoningEffort::None {
                kwargs.insert("enable_thinking".into(), JsonValue::Bool(false));
                body.remove(REASONING_BUDGET_PARAM);
            } else {
                kwargs.insert("reasoning_effort".into(), json!(effort));
            }
            body.insert("chat_template_kwargs".into(), JsonValue::Object(kwargs));
        } else {
            body.remove(REASONING_BUDGET_PARAM);
        }
    }
    body.insert(
        "model".to_owned(),
        JsonValue::String(
            catalog
                .metadata
                .get("wire_model")
                .and_then(JsonValue::as_str)
                .unwrap_or_else(|| request.model.name())
                .to_owned(),
        ),
    );
    body.insert(
        "messages".to_owned(),
        JsonValue::Array(
            request
                .messages
                .iter()
                .map(openai_message)
                .collect::<Vec<_>>(),
        ),
    );
    body.insert("stream".to_owned(), JsonValue::Bool(stream));
    if stream {
        body.insert("stream_options".into(), json!({"include_usage":true}));
    }

    if !request.tools.is_empty() {
        body.insert(
            "tools".to_owned(),
            JsonValue::Array(request.tools.iter().map(openai_tool).collect()),
        );
    }
    if let ResponseFormat::Json { schema } = &request.envelope.response_format {
        body.insert(
            "response_format".to_owned(),
            json!({
                "type": "json_schema",
                "json_schema": {
                    "name": "oneiron_response",
                    "schema": schema,
                },
            }),
        );
    }

    Ok(OpenAiCompatHttpRequest {
        method: "POST",
        path: config.endpoint_path.clone(),
        headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        body: JsonValue::Object(body),
    })
}

pub fn parse_openai_chat_response(body: &JsonValue) -> LlmResult<LlmResponse> {
    let choice = body
        .get("choices")
        .and_then(JsonValue::as_array)
        .and_then(|choices| choices.first())
        .ok_or(FatalLlmError::EmptyResponse)?;
    let message = choice
        .get("message")
        .and_then(JsonValue::as_object)
        .ok_or(FatalLlmError::EmptyResponse)?;
    // `Stop` is a claim the provider makes about the reply. A body that names
    // no finish made none, so it must not read as a finished answer.
    let finish_reason = choice
        .get("finish_reason")
        .and_then(JsonValue::as_str)
        .map_or_else(unreported_finish_reason, openai_finish_reason);

    let mut content = Vec::new();
    if let Some(text) = message.get("content").and_then(JsonValue::as_str)
        && !text.is_empty()
    {
        content.push(ContentPart::Text {
            text: text.to_owned(),
        });
    }
    if let Some(reasoning) = message
        .get("reasoning_content")
        .or_else(|| message.get("reasoning"))
        .and_then(JsonValue::as_str)
        && !reasoning.is_empty()
    {
        content.push(ContentPart::Reasoning {
            text: reasoning.to_owned(),
            signature: None,
        });
    }
    // A reply that asked for a tool is no finished answer, however its text
    // reads. A tool call this decoder cannot read fails the decode rather than
    // leaving the reply looking tool-free.
    match message.get("tool_calls") {
        None | Some(JsonValue::Null) => {}
        Some(JsonValue::Array(tool_calls)) => {
            for call in tool_calls {
                content.push(parse_openai_tool_call(call).ok_or(FatalLlmError::InvalidRequest)?);
            }
        }
        Some(_) => return Err(FatalLlmError::InvalidRequest.into()),
    }
    // The legacy single-call field asks for a tool too. This adapter never
    // offers legacy functions, so it cannot read one: the decode fails.
    if message
        .get("function_call")
        .is_some_and(|call| !call.is_null())
    {
        return Err(FatalLlmError::InvalidRequest.into());
    }

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
        usage: body
            .get("usage")
            .map_or_else(LlmUsage::zero, parse_openai_usage),
        finish_reason,
    })
}

fn openai_message(message: &LlmMessage) -> JsonValue {
    if message.role == LlmMessageRole::Tool
        && let Some(ContentPart::ToolResult {
            call_id, output, ..
        }) = message.content.first()
    {
        return json!({
            "role": "tool",
            "tool_call_id": call_id,
            "content": output.to_string(),
        });
    }

    let mut object = JsonMap::new();
    object.insert(
        "role".to_owned(),
        JsonValue::String(openai_role(message.role).to_owned()),
    );

    let mut content_parts = Vec::new();
    let mut tool_calls = Vec::new();
    for part in &message.content {
        match part {
            ContentPart::Text { text } | ContentPart::Reasoning { text, .. } => {
                content_parts.push(json!({ "type": "text", "text": text }));
            }
            ContentPart::Image { media_type, image } => {
                content_parts.push(openai_image_part(media_type, image));
            }
            ContentPart::Audio { media_type, data } => {
                content_parts.push(openai_audio_part(media_type, data));
            }
            ContentPart::ToolCall {
                call_id,
                name,
                input,
            } => {
                tool_calls.push(json!({
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": input.to_string(),
                    },
                }));
            }
            ContentPart::ToolResult { output, .. } => {
                content_parts.push(json!({ "type": "text", "text": output.to_string() }));
            }
        }
    }

    if content_parts.len() == 1
        && let Some(text) = content_parts[0].get("text").and_then(JsonValue::as_str)
    {
        object.insert("content".to_owned(), JsonValue::String(text.to_owned()));
    } else {
        object.insert("content".to_owned(), JsonValue::Array(content_parts));
    }
    if !tool_calls.is_empty() {
        object.insert("tool_calls".to_owned(), JsonValue::Array(tool_calls));
    }

    JsonValue::Object(object)
}

fn openai_role(role: LlmMessageRole) -> &'static str {
    match role {
        LlmMessageRole::System => "system",
        LlmMessageRole::User => "user",
        LlmMessageRole::Assistant => "assistant",
        LlmMessageRole::Tool => "tool",
    }
}

fn openai_image_part(media_type: &str, image: &ImageContent) -> JsonValue {
    let url = match image {
        ImageContent::Base64 { data } => format!("data:{media_type};base64,{data}"),
        ImageContent::Url { url } => url.clone(),
    };
    json!({
        "type": "image_url",
        "image_url": { "url": url },
    })
}

/// An input clip as chat `input_audio`. [`validate_capabilities`] refuses a
/// clip of no format this wire names before any part is built.
fn openai_audio_part(media_type: &str, data: &str) -> JsonValue {
    json!({
        "type": "input_audio",
        "input_audio": {
            "data": data,
            "format": openai_audio_format(media_type).unwrap_or_default(),
        },
    })
}

/// The chat wire's `input_audio.format` for a clip's media type: `wav` or
/// `mp3`, the two formats the chat audio input takes.
pub(super) fn openai_audio_format(media_type: &str) -> Option<&'static str> {
    match media_type.to_ascii_lowercase().as_str() {
        "audio/wav" | "audio/x-wav" | "audio/wave" | "audio/vnd.wave" => Some("wav"),
        "audio/mpeg" | "audio/mp3" => Some("mp3"),
        _ => None,
    }
}

fn openai_tool(tool: &LlmToolSpec) -> JsonValue {
    json!({
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.input_schema,
        },
    })
}

fn parse_openai_tool_call(call: &JsonValue) -> Option<ContentPart> {
    let function = call.get("function")?;
    let call_id = call.get("id")?.as_str()?.to_owned();
    let name = function.get("name")?.as_str()?.to_owned();
    let arguments = function
        .get("arguments")
        .and_then(JsonValue::as_str)
        .unwrap_or("{}");
    let input =
        serde_json::from_str(arguments).unwrap_or_else(|_| JsonValue::String(arguments.to_owned()));

    Some(ContentPart::ToolCall {
        call_id,
        name,
        input,
    })
}

pub(crate) fn parse_openai_usage(usage: &JsonValue) -> LlmUsage {
    let prompt_tokens = u64_field(usage, "prompt_tokens");
    let completion_tokens = u64_field(usage, "completion_tokens");
    let cached_tokens = usage
        .get("prompt_tokens_details")
        .map_or(0, |details| u64_field(details, "cached_tokens"));
    let reasoning_tokens = usage
        .get("completion_tokens_details")
        .map_or(0, |details| u64_field(details, "reasoning_tokens"));
    LlmUsage {
        input: LlmInputUsage {
            total: prompt_tokens,
            cache_read: cached_tokens,
            cache_write: 0,
        },
        output: LlmOutputUsage {
            total: completion_tokens,
            text: completion_tokens.saturating_sub(reasoning_tokens),
            reasoning: reasoning_tokens,
        },
        raw_provider: usage.clone(),
    }
}

/// The finish of a reply whose provider reported none.
fn unreported_finish_reason() -> FinishReason {
    FinishReason::Other {
        name: "unreported".to_owned(),
    }
}

pub(crate) fn openai_finish_reason(reason: &str) -> FinishReason {
    match reason {
        "stop" => FinishReason::Stop,
        "length" => FinishReason::Length,
        "tool_calls" | "function_call" => FinishReason::ToolCalls,
        "content_filter" => FinishReason::ContentFiltered,
        other => FinishReason::Other {
            name: other.to_owned(),
        },
    }
}

pub fn classify_openai_status(
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &JsonValue,
) -> LlmError {
    if is_content_filter_error(body) || status == 451 {
        return FatalLlmError::ContentFiltered.into();
    }
    if limit::is_limit_status(status, body) {
        return limit::limit_refusal(status, headers, body).into();
    }

    match status {
        408 | 504 => RetryableLlmError::Timeout.into(),
        500..=599 => RetryableLlmError::ServerError.into(),
        401 | 403 => FatalLlmError::Auth.into(),
        400 | 404 | 409 | 413 | 422 => FatalLlmError::InvalidRequest.into(),
        _ if status >= 500 => RetryableLlmError::ServerError.into(),
        _ => FatalLlmError::InvalidRequest.into(),
    }
}

fn is_content_filter_error(body: &JsonValue) -> bool {
    body.get("error").is_some_and(|error| {
        error
            .get("code")
            .or_else(|| error.get("type"))
            .and_then(JsonValue::as_str)
            .is_some_and(|code| code == "content_filter" || code == "content_filtered")
    })
}

fn u64_field(value: &JsonValue, key: &str) -> u64 {
    value.get(key).and_then(JsonValue::as_u64).unwrap_or(0)
}
