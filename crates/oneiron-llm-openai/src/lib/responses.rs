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
use oneiron::llm::{REASONING_BUDGET_PARAM, ReasoningEffort, StreamAssembly};
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

impl OpenAiResponsesTurn {
    /// The `response.create` frame that chains `previous_response_id` and
    /// sends `input`.
    #[must_use]
    pub fn create_frame(
        &self,
        previous_response_id: Option<&str>,
        input: &[JsonValue],
    ) -> JsonValue {
        let mut frame = JsonMap::with_capacity(self.head.len() + 3);
        frame.insert("type".into(), "response.create".into());
        frame.extend(self.head.clone());
        if let Some(id) = previous_response_id {
            frame.insert("previous_response_id".into(), id.into());
        }
        frame.insert("input".into(), JsonValue::Array(input.to_vec()));
        JsonValue::Object(frame)
    }

    /// Whether this turn asks the provider to keep its response (`store`).
    #[must_use]
    pub fn stored(&self) -> bool {
        self.head.get("store") == Some(&JsonValue::Bool(true))
    }
}

/// Whether the Responses codec can carry `request`. Audio input has no
/// Responses item this codec builds, so such a request takes the chat path.
#[must_use]
pub fn responses_can_carry(request: &LlmRequest) -> bool {
    !request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .any(|part| matches!(part, ContentPart::Audio { .. }))
}

pub fn build_openai_responses_turn(
    config: &OpenAiCompatConfig,
    request: &LlmRequest,
    stream: bool,
) -> LlmResult<OpenAiResponsesTurn> {
    if request.route_selector_override().is_some() || !responses_can_carry(request) {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let catalog = config.catalog_entry(&request.model)?;
    let provider_options = OpenAiProviderOptions::from_request(request)?;
    validate_capabilities(catalog, request, &provider_options, stream)?;

    let mut head = JsonMap::new();
    for (key, value) in &request.params {
        // The chat names of the output cap are one Responses field.
        let key = match key.as_str() {
            "max_tokens" | "max_completion_tokens" => "max_output_tokens",
            other => other,
        };
        head.insert(key.to_owned(), value.clone());
    }
    for (key, value) in provider_options.to_wire_fields() {
        head.insert(key, value);
    }
    let mut reasoning = match head.remove("reasoning") {
        Some(JsonValue::Object(options)) => options,
        Some(_) => return Err(FatalLlmError::InvalidRequest.into()),
        None => JsonMap::new(),
    };
    // Chat's flat effort is `reasoning.effort` here.
    if let Some(effort) = head.remove("reasoning_effort") {
        reasoning.insert("effort".into(), effort);
    }
    for key in [
        "thinking",
        "output_config",
        "chat_template_kwargs",
        REASONING_BUDGET_PARAM,
    ] {
        head.remove(key);
    }
    if let Some(effort) = request.envelope.seat_effort {
        // The seat pin wins, as on the chat wire; no effort leaves no
        // reasoning controls at all.
        if effort == ReasoningEffort::None {
            reasoning.clear();
        } else {
            reasoning.insert("effort".into(), json!(effort));
        }
    }
    if !reasoning.is_empty() {
        head.insert("reasoning".into(), JsonValue::Object(reasoning));
    }
    head.insert(
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
    // The chain lives on the socket alone; the vault keeps the transcript.
    // The host sets `store` when its owner turned it on (OF-602).
    head.insert("store".into(), JsonValue::Bool(false));
    for key in [
        "stream",
        "stream_options",
        "background",
        "input",
        "previous_response_id",
    ] {
        head.remove(key);
    }
    if !request.tools.is_empty() {
        head.insert(
            "tools".to_owned(),
            JsonValue::Array(request.tools.iter().map(responses_tool).collect()),
        );
    }
    if let ResponseFormat::Json { schema } = &request.envelope.response_format {
        head.insert(
            "text".to_owned(),
            json!({
                "format": {
                    "type": "json_schema",
                    "name": "oneiron_response",
                    "schema": schema,
                },
            }),
        );
    }

    Ok(OpenAiResponsesTurn {
        head,
        items: request
            .messages
            .iter()
            .flat_map(openai_responses_items)
            .collect(),
    })
}

/// One message as Responses input items. Reasoning parts are left out: on a
/// chained turn the socket keeps them, and a replay has no id to name them by.
#[must_use]
pub fn openai_responses_items(message: &LlmMessage) -> Vec<JsonValue> {
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
            ContentPart::Reasoning { .. } | ContentPart::Audio { .. } => {}
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

impl OpenAiResponsesChain {
    /// What `items` sends on this socket: the chained response and only the
    /// items past it when `items` extends this chain, else no response and
    /// every item.
    #[must_use]
    pub fn plan<'t>(&self, items: &'t [JsonValue]) -> (Option<&str>, &'t [JsonValue]) {
        match &self.response_id {
            Some(id) if self.extended_by(items) => {
                (Some(id.as_str()), &items[self.digests.len()..])
            }
            _ => (None, items),
        }
    }

    /// Whether `items` is this chain plus at least one new item.
    #[must_use]
    pub fn extended_by(&self, items: &[JsonValue]) -> bool {
        self.response_id.is_some()
            && items.len() > self.digests.len()
            && items
                .iter()
                .zip(&self.digests)
                .all(|(item, digest)| item_digest(item) == *digest)
    }

    /// Records the turn that sent `items` and completed as `response` (the
    /// `response` object of `response.completed`). A response this codec
    /// cannot read leaves the chain empty, so the next turn sends everything.
    pub fn record(&mut self, items: &[JsonValue], response: &JsonValue) {
        let id = response.get("id").and_then(JsonValue::as_str);
        match (id, parse_openai_responses_output(response)) {
            (Some(id), Ok(reply)) => {
                self.response_id = Some(id.to_owned());
                self.digests = items
                    .iter()
                    .chain(&openai_responses_items(&reply.message))
                    .map(item_digest)
                    .collect();
            }
            _ => self.clear(),
        }
    }

    pub fn clear(&mut self) {
        self.response_id = None;
        self.digests.clear();
    }

    /// The response this chain ends at.
    #[must_use]
    pub fn response_id(&self) -> Option<&str> {
        self.response_id.as_deref()
    }

    /// The digest of each item the chain covers, oldest first.
    #[must_use]
    pub fn digests(&self) -> &[u64] {
        &self.digests
    }

    /// The chain that ends at `response_id` and covers `items`: a
    /// conversation's stored chain, taken up on another socket.
    #[must_use]
    pub fn resumed(items: &[JsonValue], response_id: String) -> Self {
        Self {
            response_id: Some(response_id),
            digests: responses_item_digests(items),
        }
    }
}

/// The digest of each of `items`, as a chain keeps them.
#[must_use]
pub fn responses_item_digests(items: &[JsonValue]) -> Vec<u64> {
    items.iter().map(item_digest).collect()
}

fn item_digest(item: &JsonValue) -> u64 {
    let mut hasher = DefaultHasher::new();
    item.to_string().hash(&mut hasher);
    hasher.finish()
}

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
                if !text.is_empty() {
                    content.push(ContentPart::Reasoning {
                        text,
                        signature: None,
                    });
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
    })
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
}

impl OpenAiResponsesStreamAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_event(&mut self, event: &JsonValue) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.assembly.is_done() {
            return Ok(Vec::new());
        }
        let index = || {
            event
                .get("output_index")
                .and_then(JsonValue::as_u64)
                .unwrap_or(0)
        };
        let delta = || event.get("delta").and_then(JsonValue::as_str).unwrap_or("");
        match responses_event_type(event) {
            "response.output_item.added" | "response.output_item.done" => {
                let item = event.get("item").ok_or(FatalLlmError::InvalidRequest)?;
                match item.get("type").and_then(JsonValue::as_str) {
                    Some("function_call") => {
                        let header = self.tools.entry(index()).or_default();
                        if header.call_id.is_empty() {
                            header.call_id = item
                                .get("call_id")
                                .and_then(JsonValue::as_str)
                                .unwrap_or_default()
                                .to_owned();
                            header.name = item
                                .get("name")
                                .and_then(JsonValue::as_str)
                                .unwrap_or_default()
                                .to_owned();
                        }
                        let header = header.clone();
                        self.tool_called = true;
                        let mut events = self.assembly.tool(
                            &format!("tool-{}", index()),
                            &header.call_id,
                            &header.name,
                            "",
                        )?;
                        // An item whose arguments came whole, with no deltas,
                        // carries them on its done event.
                        if responses_event_type(event) == "response.output_item.done"
                            && !header.streamed
                            && let Some(arguments) =
                                item.get("arguments").and_then(JsonValue::as_str)
                        {
                            self.tools.entry(index()).or_default().streamed = true;
                            events.extend(self.assembly.tool(
                                &format!("tool-{}", index()),
                                &header.call_id,
                                &header.name,
                                arguments,
                            )?);
                        }
                        Ok(events)
                    }
                    Some(other) if other.ends_with("_call") => {
                        Err(FatalLlmError::InvalidRequest.into())
                    }
                    _ => Ok(Vec::new()),
                }
            }
            "response.output_text.delta" | "response.refusal.delta" => {
                let content = event
                    .get("content_index")
                    .and_then(JsonValue::as_u64)
                    .unwrap_or(0);
                self.assembly
                    .text(&format!("text-{}-{content}", index()), delta())
            }
            "response.reasoning_summary_text.delta" | "response.reasoning_text.delta" => self
                .assembly
                .reasoning(&format!("reasoning-{}", index()), delta(), None),
            "response.function_call_arguments.delta" => {
                let header = self
                    .tools
                    .get_mut(&index())
                    .ok_or(FatalLlmError::InvalidRequest)?;
                header.streamed = true;
                let header = header.clone();
                self.assembly.tool(
                    &format!("tool-{}", index()),
                    &header.call_id,
                    &header.name,
                    delta(),
                )
            }
            "response.completed" | "response.incomplete" => {
                let response = event.get("response").unwrap_or(&JsonValue::Null);
                let usage = response
                    .get("usage")
                    .map_or_else(LlmUsage::zero, parse_responses_usage);
                let reason = if self.tool_called {
                    FinishReason::ToolCalls
                } else {
                    responses_finish_reason(response, &[])
                };
                self.assembly.finish(usage, reason)
            }
            "response.failed" | "error" => Err(responses_error(event)),
            _ => Ok(Vec::new()),
        }
    }

    pub fn finish_eof(&mut self) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.assembly.is_done() {
            Ok(Vec::new())
        } else {
            // A socket that ends before its terminal event cut the turn.
            Err(oneiron::RetryableLlmError::StreamCut.into())
        }
    }

    #[must_use]
    pub fn abort_with_usage(&mut self, usage: LlmUsage) -> Vec<LlmStreamEvent> {
        self.assembly.abort(usage)
    }
}

pub struct OpenAiResponsesLlmStream<'a> {
    provider_stream: OpenAiCompatProviderStream<'a>,
    accumulator: OpenAiResponsesStreamAccumulator,
    pending: VecDeque<LlmResult<LlmStreamEvent>>,
    ended: bool,
}

impl<'a> OpenAiResponsesLlmStream<'a> {
    #[must_use]
    pub fn new(provider_stream: OpenAiCompatProviderStream<'a>) -> Self {
        Self {
            provider_stream,
            accumulator: OpenAiResponsesStreamAccumulator::new(),
            pending: VecDeque::new(),
            ended: false,
        }
    }

    /// Drains the turn into one reply, for a caller that asked for no stream.
    pub async fn into_response(mut self) -> LlmResult<LlmResponse> {
        loop {
            let next = std::future::poll_fn(|cx| Pin::new(&mut self).poll_next(cx)).await;
            match next {
                Some(Ok(LlmStreamEvent::Done {
                    message,
                    usage,
                    finish_reason,
                })) => {
                    return Ok(LlmResponse {
                        message,
                        usage,
                        finish_reason,
                    });
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(error),
                None => return Err(oneiron::RetryableLlmError::StreamCut.into()),
            }
        }
    }
}

impl Stream for OpenAiResponsesLlmStream<'_> {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(event) = this.pending.pop_front() {
                return Poll::Ready(Some(event));
            }
            if this.ended {
                return Poll::Ready(None);
            }
            match this.provider_stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(OpenAiCompatStreamFrame::Chunk(event)))) => {
                    match this.accumulator.push_event(&event) {
                        Ok(events) => this.pending.extend(events.into_iter().map(Ok)),
                        Err(error) => {
                            this.ended = true;
                            return Poll::Ready(Some(Err(error)));
                        }
                    }
                }
                Poll::Ready(Some(Ok(OpenAiCompatStreamFrame::Abort { usage }))) => {
                    this.pending
                        .extend(this.accumulator.abort_with_usage(usage).into_iter().map(Ok));
                }
                Poll::Ready(Some(Ok(OpenAiCompatStreamFrame::Status(response)))) => {
                    this.ended = true;
                    return Poll::Ready(Some(Err(classify_openai_status(
                        response.status,
                        &response.headers,
                        &response.body,
                    ))));
                }
                Poll::Ready(Some(Err(error))) => {
                    this.ended = true;
                    return Poll::Ready(Some(Err(error.into())));
                }
                Poll::Ready(None) => {
                    this.ended = true;
                    match this.accumulator.finish_eof() {
                        Ok(events) => this.pending.extend(events.into_iter().map(Ok)),
                        Err(error) => return Poll::Ready(Some(Err(error))),
                    }
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
