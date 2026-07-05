//! OpenAI-compatible wire adapter for Oneiron's [`oneiron::LlmBackend`] seam.
//!
//! The crate owns protocol mapping and classification only. HTTP execution,
//! authentication, cancellation wiring, and retry policy stay host-owned.

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;
use oneiron::{
    BudgetLease, ContentPart, FatalLlmError, FinishReason, ImageContent, LlmBackend, LlmCapability,
    LlmCatalogEntry, LlmError, LlmGenerateFuture, LlmInputUsage, LlmMessage, LlmMessageRole,
    LlmOutputUsage, LlmRequest, LlmResponse, LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult,
    LlmToolSpec, LlmUsage, ModelId, ResponseFormat, RetryableLlmError, UnsupportedCapability,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue, json};

pub type OpenAiCompatFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<OpenAiCompatHttpResponse, OpenAiCompatTransportError>>
            + Send
            + 'a,
    >,
>;
pub type OpenAiCompatProviderStream<'a> = Pin<
    Box<dyn Stream<Item = Result<OpenAiCompatStreamFrame, OpenAiCompatTransportError>> + Send + 'a>,
>;

#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiCompatHttpRequest {
    pub method: &'static str,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: JsonValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiCompatHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: JsonValue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OpenAiCompatStreamFrame {
    Chunk(JsonValue),
    Abort { usage: LlmUsage },
    Status(OpenAiCompatHttpResponse),
}

pub trait OpenAiCompatTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: OpenAiCompatHttpRequest,
        lease: &'a BudgetLease,
    ) -> OpenAiCompatFuture<'a>;

    fn stream<'a>(
        &'a self,
        request: OpenAiCompatHttpRequest,
        lease: &'a BudgetLease,
    ) -> Result<OpenAiCompatProviderStream<'a>, OpenAiCompatTransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OpenAiCompatTransportError {
    #[error("OpenAI-compatible transport timed out")]
    Timeout,
    #[error("OpenAI-compatible transport stream was cut")]
    StreamCut,
    #[error("OpenAI-compatible transport server error")]
    Server,
    #[error("OpenAI-compatible transport connection failed")]
    Connection,
}

impl From<OpenAiCompatTransportError> for LlmError {
    fn from(error: OpenAiCompatTransportError) -> Self {
        match error {
            OpenAiCompatTransportError::Timeout => RetryableLlmError::Timeout.into(),
            OpenAiCompatTransportError::StreamCut | OpenAiCompatTransportError::Connection => {
                RetryableLlmError::StreamCut.into()
            }
            OpenAiCompatTransportError::Server => RetryableLlmError::ServerError.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OpenAiCompatConfig {
    pub endpoint_path: String,
    pub models: BTreeMap<ModelId, LlmCatalogEntry>,
}

impl OpenAiCompatConfig {
    #[must_use]
    pub fn new(model: LlmCatalogEntry) -> Self {
        let mut models = BTreeMap::new();
        models.insert(model.model.clone(), model);
        Self {
            endpoint_path: "/v1/chat/completions".to_owned(),
            models,
        }
    }

    #[must_use]
    pub fn with_models(models: impl IntoIterator<Item = LlmCatalogEntry>) -> Self {
        Self {
            endpoint_path: "/v1/chat/completions".to_owned(),
            models: models
                .into_iter()
                .map(|entry| (entry.model.clone(), entry))
                .collect(),
        }
    }

    #[must_use]
    pub fn with_endpoint_path(mut self, endpoint_path: impl Into<String>) -> Self {
        self.endpoint_path = endpoint_path.into();
        self
    }

    fn catalog_entry(&self, model: &ModelId) -> LlmResult<&LlmCatalogEntry> {
        self.models
            .get(model)
            .ok_or_else(|| FatalLlmError::InvalidRequest.into())
    }
}

#[derive(Debug)]
pub struct OpenAiCompatBackend<T> {
    config: OpenAiCompatConfig,
    transport: T,
}

impl<T> OpenAiCompatBackend<T> {
    #[must_use]
    pub fn new(config: OpenAiCompatConfig, transport: T) -> Self {
        Self { config, transport }
    }

    #[must_use]
    pub fn config(&self) -> &OpenAiCompatConfig {
        &self.config
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T> LlmBackend for OpenAiCompatBackend<T>
where
    T: OpenAiCompatTransport,
{
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let wire_request = build_openai_chat_request(&self.config, &request, false)?;
            let response = self.transport.execute(wire_request, lease).await?;
            if !(200..=299).contains(&response.status) {
                return Err(classify_openai_status(
                    response.status,
                    &response.headers,
                    &response.body,
                ));
            }
            parse_openai_chat_response(&response.body)
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let wire_request = build_openai_chat_request(&self.config, &request, true)?;
        let provider_stream = self.transport.stream(wire_request, lease)?;
        Ok(LlmStream::new(OpenAiCompatLlmStream::new(provider_stream)))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OpenAiProviderOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<OpenAiReasoningOptions>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub raw: BTreeMap<String, JsonValue>,
}

impl OpenAiProviderOptions {
    pub const NAMESPACE: &'static str = "openai";

    pub fn from_request(request: &LlmRequest) -> LlmResult<Self> {
        request
            .provider_options
            .get(Self::NAMESPACE)
            .map_or_else(|| Ok(Self::default()), Self::from_namespaced_value)
    }

    pub fn from_namespaced_value(value: &JsonValue) -> LlmResult<Self> {
        let object = value.as_object().ok_or(FatalLlmError::InvalidRequest)?;
        let mut options = Self::default();

        for (key, value) in object {
            match key.as_str() {
                "parallel_tool_calls" => {
                    options.parallel_tool_calls =
                        Some(value.as_bool().ok_or(FatalLlmError::InvalidRequest)?);
                }
                "reasoning" => {
                    options.reasoning = Some(
                        serde_json::from_value(value.clone())
                            .map_err(|_| FatalLlmError::InvalidRequest)?,
                    );
                }
                _ => {
                    options.raw.insert(key.clone(), value.clone());
                }
            }
        }

        Ok(options)
    }

    #[must_use]
    pub fn to_wire_fields(&self) -> BTreeMap<String, JsonValue> {
        let mut fields = self.raw.clone();
        if let Some(parallel_tool_calls) = self.parallel_tool_calls {
            fields.insert(
                "parallel_tool_calls".to_owned(),
                JsonValue::Bool(parallel_tool_calls),
            );
        }
        if let Some(reasoning) = &self.reasoning {
            fields.insert(
                "reasoning".to_owned(),
                serde_json::to_value(reasoning)
                    .expect("OpenAI reasoning options serialize without failure"),
            );
        }
        fields
    }

    #[must_use]
    pub fn requires_reasoning(&self) -> bool {
        self.reasoning.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAiReasoningOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

pub fn build_openai_chat_request(
    config: &OpenAiCompatConfig,
    request: &LlmRequest,
    stream: bool,
) -> LlmResult<OpenAiCompatHttpRequest> {
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
    body.insert(
        "model".to_owned(),
        JsonValue::String(request.model.name().to_owned()),
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
    let finish_reason = choice
        .get("finish_reason")
        .and_then(JsonValue::as_str)
        .map_or(FinishReason::Stop, openai_finish_reason);

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
    if let Some(tool_calls) = message.get("tool_calls").and_then(JsonValue::as_array) {
        for call in tool_calls {
            if let Some(part) = parse_openai_tool_call(call) {
                content.push(part);
            }
        }
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

pub fn classify_openai_status(
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &JsonValue,
) -> LlmError {
    if is_content_filter_error(body) || status == 451 {
        return FatalLlmError::ContentFiltered.into();
    }

    match status {
        408 | 504 => RetryableLlmError::Timeout.into(),
        429 => RetryableLlmError::RateLimited {
            retry_after: retry_after_seconds(headers, body),
        }
        .into(),
        500..=599 => RetryableLlmError::ServerError.into(),
        401 | 403 => FatalLlmError::Auth.into(),
        400 | 404 | 409 | 413 | 422 => FatalLlmError::InvalidRequest.into(),
        _ if status >= 500 => RetryableLlmError::ServerError.into(),
        _ => FatalLlmError::InvalidRequest.into(),
    }
}

#[derive(Debug, Clone)]
pub struct OpenAiCompatStreamAccumulator {
    text_part_id: String,
    text: String,
    text_started: bool,
    usage: Option<LlmUsage>,
    done: bool,
}

impl Default for OpenAiCompatStreamAccumulator {
    fn default() -> Self {
        Self {
            text_part_id: "text-0".to_owned(),
            text: String::new(),
            text_started: false,
            usage: None,
            done: false,
        }
    }
}

impl OpenAiCompatStreamAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_chunk(&mut self, chunk: JsonValue) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.done {
            return Ok(Vec::new());
        }

        if let Some(usage) = chunk.get("usage") {
            self.usage = Some(parse_openai_usage(usage));
        }

        let mut events = Vec::new();
        let Some(choice) = chunk
            .get("choices")
            .and_then(JsonValue::as_array)
            .and_then(|choices| choices.first())
        else {
            return Ok(events);
        };

        if let Some(text) = choice
            .get("delta")
            .and_then(|delta| delta.get("content"))
            .and_then(JsonValue::as_str)
            && !text.is_empty()
        {
            self.push_text_delta(text, &mut events);
        }

        if let Some(finish) = choice.get("finish_reason").and_then(JsonValue::as_str) {
            events.extend(self.finish(openai_finish_reason(finish))?);
        }

        Ok(events)
    }

    #[must_use]
    pub fn abort_with_usage(&mut self, usage: LlmUsage) -> Vec<LlmStreamEvent> {
        if self.done {
            return Vec::new();
        }
        self.usage = Some(usage);
        self.done = true;

        let mut events = Vec::new();
        if self.text_started {
            events.push(LlmStreamEvent::TextEnd {
                part_id: self.text_part_id.clone(),
            });
        }
        events.push(LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: self.partial_content(),
            },
            usage: self.usage.clone().unwrap_or_else(LlmUsage::zero),
            finish_reason: FinishReason::Cancelled,
        });
        events
    }

    fn push_text_delta(&mut self, text: &str, events: &mut Vec<LlmStreamEvent>) {
        if !self.text_started {
            self.text_started = true;
            events.push(LlmStreamEvent::TextStart {
                part_id: self.text_part_id.clone(),
            });
        }
        self.text.push_str(text);
        events.push(LlmStreamEvent::TextDelta {
            part_id: self.text_part_id.clone(),
            text: text.to_owned(),
        });
    }

    fn finish(&mut self, finish_reason: FinishReason) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.done {
            return Ok(Vec::new());
        }
        self.done = true;

        if self.text.is_empty() {
            return Err(if matches!(finish_reason, FinishReason::ContentFiltered) {
                FatalLlmError::ContentFiltered.into()
            } else {
                FatalLlmError::EmptyResponse.into()
            });
        }

        let mut events = Vec::new();
        if self.text_started {
            events.push(LlmStreamEvent::TextEnd {
                part_id: self.text_part_id.clone(),
            });
        }
        events.push(LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: self.partial_content(),
            },
            usage: self.usage.clone().unwrap_or_else(LlmUsage::zero),
            finish_reason,
        });
        Ok(events)
    }

    fn partial_content(&self) -> Vec<ContentPart> {
        if self.text.is_empty() {
            Vec::new()
        } else {
            vec![ContentPart::Text {
                text: self.text.clone(),
            }]
        }
    }
}

pub struct OpenAiCompatLlmStream<'a> {
    provider_stream: OpenAiCompatProviderStream<'a>,
    accumulator: OpenAiCompatStreamAccumulator,
    pending: VecDeque<LlmResult<LlmStreamEvent>>,
}

impl<'a> OpenAiCompatLlmStream<'a> {
    #[must_use]
    pub fn new(provider_stream: OpenAiCompatProviderStream<'a>) -> Self {
        Self {
            provider_stream,
            accumulator: OpenAiCompatStreamAccumulator::new(),
            pending: VecDeque::new(),
        }
    }
}

impl Stream for OpenAiCompatLlmStream<'_> {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(event) = this.pending.pop_front() {
                return Poll::Ready(Some(event));
            }

            match this.provider_stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(OpenAiCompatStreamFrame::Chunk(chunk)))) => {
                    match this.accumulator.push_chunk(chunk) {
                        Ok(events) => this.pending.extend(events.into_iter().map(Ok)),
                        Err(error) => return Poll::Ready(Some(Err(error))),
                    }
                }
                Poll::Ready(Some(Ok(OpenAiCompatStreamFrame::Abort { usage }))) => {
                    this.pending
                        .extend(this.accumulator.abort_with_usage(usage).into_iter().map(Ok));
                }
                Poll::Ready(Some(Ok(OpenAiCompatStreamFrame::Status(response)))) => {
                    return Poll::Ready(Some(Err(classify_openai_status(
                        response.status,
                        &response.headers,
                        &response.body,
                    ))));
                }
                Poll::Ready(Some(Err(error))) => return Poll::Ready(Some(Err(error.into()))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

fn validate_capabilities(
    catalog: &LlmCatalogEntry,
    request: &LlmRequest,
    provider_options: &OpenAiProviderOptions,
    stream: bool,
) -> LlmResult<()> {
    if stream {
        require(catalog, LlmCapability::Streaming, "stream() requested")?;
    }
    if !request.tools.is_empty() {
        require(
            catalog,
            LlmCapability::ToolCalling,
            "request includes tool specs",
        )?;
    }
    if request.messages.iter().any(message_has_tool_result) {
        require(
            catalog,
            LlmCapability::ToolResults,
            "request includes tool result content",
        )?;
    }
    if request.messages.iter().any(message_has_image) {
        require(
            catalog,
            LlmCapability::ImageInput,
            "request includes image content",
        )?;
    }
    if matches!(
        request.envelope.response_format,
        ResponseFormat::Json { .. }
    ) {
        require(
            catalog,
            LlmCapability::JsonResponse,
            "request asks for a JSON response",
        )?;
    }
    if provider_options.requires_reasoning() || request.params.contains_key("reasoning_effort") {
        require(
            catalog,
            LlmCapability::Reasoning,
            "request includes reasoning controls",
        )?;
    }
    Ok(())
}

fn require(
    catalog: &LlmCatalogEntry,
    capability: LlmCapability,
    reason: &'static str,
) -> LlmResult<()> {
    if catalog.supports(&capability) {
        Ok(())
    } else {
        Err(FatalLlmError::Unsupported(UnsupportedCapability {
            capability,
            model: Some(catalog.model.clone()),
            reason: Some(reason.to_owned()),
        })
        .into())
    }
}

fn message_has_image(message: &LlmMessage) -> bool {
    message
        .content
        .iter()
        .any(|part| matches!(part, ContentPart::Image { .. }))
}

fn message_has_tool_result(message: &LlmMessage) -> bool {
    message
        .content
        .iter()
        .any(|part| matches!(part, ContentPart::ToolResult { .. }))
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

fn parse_openai_usage(usage: &JsonValue) -> LlmUsage {
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

fn openai_finish_reason(reason: &str) -> FinishReason {
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
            .get("code")
            .or_else(|| error.get("type"))
            .and_then(JsonValue::as_str)
            .is_some_and(|code| code == "content_filter" || code == "content_filtered")
    })
}

fn u64_field(value: &JsonValue, key: &str) -> u64 {
    value.get(key).and_then(JsonValue::as_u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::{
        CallClass, CallEnvelope, CallPurpose, DeterministicFallback, ModelLocality, ModelTierRef,
        TierPrecedence,
    };

    #[test]
    fn status_code_table_maps_to_typed_errors() {
        let headers = BTreeMap::from([("retry-after".to_owned(), "12".to_owned())]);
        let body = json!({ "error": { "message": "rate limit" } });

        assert!(matches!(
            classify_openai_status(429, &headers, &body),
            LlmError::Retryable(RetryableLlmError::RateLimited {
                retry_after: Some(12)
            })
        ));
        assert!(matches!(
            classify_openai_status(500, &BTreeMap::new(), &body),
            LlmError::Retryable(RetryableLlmError::ServerError)
        ));
        assert!(matches!(
            classify_openai_status(408, &BTreeMap::new(), &body),
            LlmError::Retryable(RetryableLlmError::Timeout)
        ));
        assert!(matches!(
            classify_openai_status(401, &BTreeMap::new(), &body),
            LlmError::Fatal(FatalLlmError::Auth)
        ));
        assert!(matches!(
            classify_openai_status(400, &BTreeMap::new(), &body),
            LlmError::Fatal(FatalLlmError::InvalidRequest)
        ));
        assert!(matches!(
            classify_openai_status(
                400,
                &BTreeMap::new(),
                &json!({ "error": { "code": "content_filter" } })
            ),
            LlmError::Fatal(FatalLlmError::ContentFiltered)
        ));
    }

    #[test]
    fn unsupported_capability_is_typed() {
        let catalog = catalog_with([LlmCapability::JsonResponse]);
        let config = OpenAiCompatConfig::new(catalog);
        let mut request = sample_request();
        request.tools = vec![LlmToolSpec {
            name: "route".to_owned(),
            description: "Route a call".to_owned(),
            input_schema: json!({ "type": "object" }),
        }];

        let error = build_openai_chat_request(&config, &request, false).unwrap_err();
        assert!(matches!(
            error,
            LlmError::Fatal(FatalLlmError::Unsupported(UnsupportedCapability {
                capability: LlmCapability::ToolCalling,
                ..
            }))
        ));
    }

    #[test]
    fn provider_options_parse_typed_fields_and_preserve_raw_escape_hatch() {
        let options = OpenAiProviderOptions::from_namespaced_value(&json!({
            "parallel_tool_calls": false,
            "reasoning": { "effort": "medium", "summary": "auto" },
            "vendor_extension": { "mode": "strict" }
        }))
        .unwrap();

        assert_eq!(options.parallel_tool_calls, Some(false));
        assert_eq!(
            options
                .reasoning
                .as_ref()
                .and_then(|reasoning| reasoning.effort.as_deref()),
            Some("medium")
        );
        assert_eq!(
            options.raw.get("vendor_extension"),
            Some(&json!({ "mode": "strict" }))
        );

        let wire = options.to_wire_fields();
        assert_eq!(wire.get("parallel_tool_calls"), Some(&json!(false)));
        assert_eq!(
            wire.get("vendor_extension"),
            Some(&json!({ "mode": "strict" }))
        );
    }

    #[test]
    fn abort_retains_partial_text_and_settles_usage() {
        let mut accumulator = OpenAiCompatStreamAccumulator::new();
        let events = accumulator
            .push_chunk(json!({
                "choices": [{
                    "delta": { "content": "hel" },
                    "finish_reason": null
                }]
            }))
            .unwrap();
        assert!(matches!(
            events.first(),
            Some(LlmStreamEvent::TextStart { .. })
        ));

        let usage = LlmUsage {
            input: LlmInputUsage {
                total: 7,
                cache_read: 2,
                cache_write: 0,
            },
            output: LlmOutputUsage {
                total: 3,
                text: 3,
                reasoning: 0,
            },
            raw_provider: json!({ "prompt_tokens": 7, "completion_tokens": 3 }),
        };
        let abort_events = accumulator.abort_with_usage(usage.clone());
        let done = abort_events
            .iter()
            .find_map(|event| match event {
                LlmStreamEvent::Done {
                    message,
                    usage,
                    finish_reason,
                } => Some((message, usage, finish_reason)),
                _ => None,
            })
            .expect("abort should settle with Done");

        assert_eq!(
            done.0.content,
            vec![ContentPart::Text {
                text: "hel".to_owned()
            }]
        );
        assert_eq!(*done.1, usage);
        assert_eq!(*done.2, FinishReason::Cancelled);
    }

    fn sample_request() -> LlmRequest {
        LlmRequest {
            model: ModelId::new("openai/gpt-4.1@2026-07-02").unwrap(),
            envelope: CallEnvelope {
                purpose: CallPurpose::AnswerGen,
                class: CallClass::Durable {
                    fallback: DeterministicFallback {
                        name: "fallback".to_owned(),
                        config: None,
                    },
                },
                tier: TierPrecedence {
                    per_call: None,
                    vault_policy: None,
                    purpose_default: None,
                    global_default: ModelTierRef("standard".to_owned()),
                },
                response_format: ResponseFormat::Json {
                    schema: json!({ "type": "object" }),
                },
                locality: ModelLocality::ThirdParty,
            },
            messages: vec![LlmMessage {
                role: LlmMessageRole::User,
                content: vec![ContentPart::Text {
                    text: "hello".to_owned(),
                }],
            }],
            tools: Vec::new(),
            params: BTreeMap::new(),
            provider_options: BTreeMap::new(),
        }
    }

    fn catalog_with(capabilities: impl IntoIterator<Item = LlmCapability>) -> LlmCatalogEntry {
        LlmCatalogEntry {
            model: ModelId::new("openai/gpt-4.1@2026-07-02").unwrap(),
            display_name: "GPT 4.1".to_owned(),
            locality: ModelLocality::ThirdParty,
            context_window_tokens: 1_000_000,
            max_output_tokens: Some(32_000),
            cost: None,
            capabilities: capabilities.into_iter().collect(),
            metadata: BTreeMap::new(),
        }
    }
}
