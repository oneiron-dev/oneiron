//! Responses protocol mapping for held sockets: one turn's create frame, the
//! chain a socket keeps, and event decoding.
//!
//! A Responses session sends the whole conversation once, then only the items
//! past the last response it chained (`previous_response_id`; `store=false`
//! unless the owner turned it on).
//! The host holds the socket; this module says what each turn sends and how
//! its events read.

use super::{
    OpenAiCompatConfig, OpenAiCompatProviderStream, OpenAiCompatStreamFrame, OpenAiProviderOptions,
    backend::validate_capabilities, classify_openai_status,
};
use futures_core::Stream;
use oneiron::llm::{
    REASONING_BUDGET_PARAM, ReasoningEffort, StreamAssembly, returned_model_wire_id,
};
use oneiron::{
    ContentPart, FatalLlmError, FinishReason, ImageContent, LlmError, LlmInputUsage, LlmMessage,
    LlmMessageRole, LlmOutputUsage, LlmRequest, LlmResponse, LlmResult, LlmStreamEvent,
    LlmToolSpec, LlmUsage, ResponseFormat,
};
use serde_json::{Map as JsonMap, Value as JsonValue, json};
use std::collections::{BTreeMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::pin::Pin;
use std::task::{Context, Poll};

mod chain;
mod output;
mod stream;
mod turn;

pub use chain::responses_item_digests;
pub use output::{
    parse_openai_responses_output, responses_error_code, responses_event_is_terminal,
    responses_event_type,
};
pub use turn::{build_openai_responses_turn, openai_responses_items, responses_can_carry};

/// The error code a socket answers when the chained response is not in its
/// cache: the turn goes again with every item.
pub const RESPONSES_PREVIOUS_NOT_FOUND: &str = "previous_response_not_found";
/// The error code a socket sends just before it closes at its age limit.
pub const RESPONSES_SOCKET_LIMIT: &str = "websocket_connection_limit_reached";

/// One Responses turn, before the session picks what of it to send.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiResponsesTurn {
    /// Every create field but `input` and `previous_response_id`. A chained
    /// response inherits neither instructions nor tools, so this goes whole on
    /// every turn.
    pub head: JsonMap<String, JsonValue>,
    /// The whole conversation as Responses input items, oldest first.
    pub items: Vec<JsonValue>,
}

/// What a request includes to get each reasoning item's encrypted content.
const ENCRYPTED_REASONING_INCLUDE: &str = "reasoning.encrypted_content";

/// How a reasoning part this codec read carries its item, in the part's
/// signature: this prefix, then the model that answered, the item's id and
/// its encrypted content, a line each. Another provider's signature never
/// starts with it.
const ENCRYPTED_REASONING: &str = "openai-reasoning\n";

/// A reasoning item `model` returned, as its part's signature: its id and
/// encrypted content.
fn reasoning_signature(item: &JsonValue, model: &str) -> Option<String> {
    let id = item.get("id")?.as_str()?;
    let encrypted = item.get("encrypted_content")?.as_str()?;
    Some(format!("{ENCRYPTED_REASONING}{model}\n{id}\n{encrypted}"))
}

/// The reasoning item a part's signature carries, as `(model, id,
/// encrypted content)`.
fn encrypted_reasoning(signature: &str) -> Option<(&str, &str, &str)> {
    let mut lines = signature.strip_prefix(ENCRYPTED_REASONING)?.splitn(3, '\n');
    Some((lines.next()?, lines.next()?, lines.next()?))
}

/// Whether reasoning `answered` returned goes back to `wire` (the model a
/// request names): the same model, or `wire`'s dated snapshot
/// (`gpt-5` and `gpt-5-2025-08-07`). Another model's reasoning stays out. A
/// house llama.cpp launch alias stands for `wire`, the route's configured
/// wire id (FIX 7895, 8292).
fn same_model(answered: &str, wire: &str) -> bool {
    let answered = returned_model_wire_id(answered, wire);
    answered == wire
        || answered
            .strip_prefix(wire)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|date| {
                date.len() == 10
                    && date.bytes().enumerate().all(|(at, byte)| match at {
                        4 | 7 => byte == b'-',
                        _ => byte.is_ascii_digit(),
                    })
            })
}

/// [`openai_responses_items`] for a request to `wire`: a reasoning item
/// another model returned stays out. `None` keeps every one.
fn responses_items(message: &LlmMessage, wire: Option<&str>) -> Vec<JsonValue> {
    let mut items = Vec::new();
    let mut content = Vec::new();
    let text_type = if message.role == LlmMessageRole::Assistant {
        "output_text"
    } else {
        "input_text"
    };
    let role = match message.role {
        LlmMessageRole::System => "system",
        LlmMessageRole::User | LlmMessageRole::Tool => "user",
        LlmMessageRole::Assistant => "assistant",
    };
    let flush = |content: &mut Vec<JsonValue>, items: &mut Vec<JsonValue>| {
        if !content.is_empty() {
            items.push(json!({
                "type": "message",
                "role": role,
                "content": std::mem::take(content),
            }));
        }
    };
    for part in &message.content {
        match part {
            ContentPart::Text { text } => {
                content.push(json!({ "type": text_type, "text": text }));
            }
            // Its summary stays out: the encrypted content is the reasoning,
            // and a streamed summary's text is joined differently from a
            // whole one's, which would break the socket's chain.
            ContentPart::Reasoning { signature, .. } => {
                if let Some((_, id, encrypted)) = signature
                    .as_deref()
                    .and_then(encrypted_reasoning)
                    .filter(|(answered, ..)| wire.is_none_or(|wire| same_model(answered, wire)))
                {
                    flush(&mut content, &mut items);
                    items.push(json!({
                        "type": "reasoning",
                        "id": id,
                        "encrypted_content": encrypted,
                        "summary": [],
                    }));
                }
            }
            ContentPart::Audio { .. } => {}
            ContentPart::Image { media_type, image } => {
                let url = match image {
                    ImageContent::Base64 { data } => format!("data:{media_type};base64,{data}"),
                    ImageContent::Url { url } => url.clone(),
                };
                content.push(json!({ "type": "input_image", "image_url": url }));
            }
            ContentPart::ToolCall {
                call_id,
                name,
                input,
            } => {
                flush(&mut content, &mut items);
                items.push(json!({
                    "type": "function_call",
                    "call_id": call_id,
                    "name": name,
                    "arguments": input.to_string(),
                }));
            }
            ContentPart::ToolResult {
                call_id, output, ..
            } => {
                if message.role == LlmMessageRole::Tool {
                    flush(&mut content, &mut items);
                    items.push(json!({
                        "type": "function_call_output",
                        "call_id": call_id,
                        "output": output.to_string(),
                    }));
                } else {
                    content.push(json!({ "type": text_type, "text": output.to_string() }));
                }
            }
        }
    }
    flush(&mut content, &mut items);
    items
}

fn responses_tool(tool: &LlmToolSpec) -> JsonValue {
    json!({
        "type": "function",
        "name": tool.name,
        "description": tool.description,
        "parameters": tool.input_schema,
    })
}

/// The chain one socket holds: the last response it completed and a digest
/// of every item that response covers, its own output included.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenAiResponsesChain {
    response_id: Option<String>,
    digests: Vec<u64>,
}

fn item_digest(item: &JsonValue) -> u64 {
    let mut hasher = DefaultHasher::new();
    item.to_string().hash(&mut hasher);
    hasher.finish()
}

fn reasoning_text(item: &JsonValue) -> String {
    ["summary", "content"]
        .into_iter()
        .filter_map(|key| item.get(key)?.as_array())
        .flatten()
        .filter_map(|part| part.get("text")?.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

fn parse_function_call(item: &JsonValue) -> Option<ContentPart> {
    let call_id = item.get("call_id")?.as_str()?.to_owned();
    let name = item.get("name")?.as_str()?.to_owned();
    let arguments = item
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

/// A response asking for a tool is no finished answer. Otherwise its status
/// and incomplete reason name the finish.
fn responses_finish_reason(response: &JsonValue, content: &[ContentPart]) -> FinishReason {
    if content
        .iter()
        .any(|part| matches!(part, ContentPart::ToolCall { .. }))
    {
        return FinishReason::ToolCalls;
    }
    match response.get("status").and_then(JsonValue::as_str) {
        Some("completed") => FinishReason::Stop,
        Some("incomplete") => match response
            .get("incomplete_details")
            .and_then(|details| details.get("reason"))
            .and_then(JsonValue::as_str)
        {
            Some("max_output_tokens") => FinishReason::Length,
            Some("content_filter") => FinishReason::ContentFiltered,
            Some(other) => FinishReason::Other {
                name: other.to_owned(),
            },
            None => FinishReason::Length,
        },
        Some(other) => FinishReason::Other {
            name: other.to_owned(),
        },
        None => FinishReason::Other {
            name: "unreported".to_owned(),
        },
    }
}

fn parse_responses_usage(usage: &JsonValue) -> LlmUsage {
    let field =
        |value: &JsonValue, key: &str| value.get(key).and_then(JsonValue::as_u64).unwrap_or(0);
    let input = field(usage, "input_tokens");
    let output = field(usage, "output_tokens");
    let cached = usage
        .get("input_tokens_details")
        .map_or(0, |details| field(details, "cached_tokens"));
    let reasoning = usage
        .get("output_tokens_details")
        .map_or(0, |details| field(details, "reasoning_tokens"));
    LlmUsage {
        input: LlmInputUsage {
            total: input,
            cache_read: cached,
            cache_write: 0,
        },
        output: LlmOutputUsage {
            total: output,
            text: output.saturating_sub(reasoning),
            reasoning,
        },
        raw_provider: usage.clone(),
    }
}

/// An `error` event or a failed response as the error a status would be.
fn responses_error(event: &JsonValue) -> LlmError {
    let body = if responses_event_type(event) == "response.failed" {
        json!({ "error": event.get("response").and_then(|r| r.get("error")).cloned().unwrap_or(JsonValue::Null) })
    } else {
        event.clone()
    };
    let status = event
        .get("status")
        .and_then(JsonValue::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .filter(|status| (400..=599).contains(status))
        .unwrap_or_else(|| oneiron::llm::limit::stream_error_status(&body));
    classify_openai_status(status, &BTreeMap::new(), &body)
}

#[derive(Debug, Clone, Default)]
struct ToolHeader {
    call_id: String,
    name: String,
    streamed: bool,
}

/// Socket events to typed stream events, with text, reasoning and tool parts
/// keyed by output item.
#[derive(Debug, Clone, Default)]
pub struct OpenAiResponsesStreamAccumulator {
    assembly: StreamAssembly,
    tools: BTreeMap<u64, ToolHeader>,
    tool_called: bool,
    /// The model the response names, from its first event.
    model: String,
}

pub struct OpenAiResponsesLlmStream<'a> {
    provider_stream: OpenAiCompatProviderStream<'a>,
    accumulator: OpenAiResponsesStreamAccumulator,
    pending: VecDeque<LlmResult<LlmStreamEvent>>,
    ended: bool,
}
