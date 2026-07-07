//! Anthropic Messages wire adapter for Oneiron's [`oneiron::LlmBackend`] seam.
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

pub type AnthropicMessagesFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<AnthropicMessagesHttpResponse, AnthropicMessagesTransportError>>
            + Send
            + 'a,
    >,
>;
pub type AnthropicMessagesProviderStream<'a> = Pin<
    Box<
        dyn Stream<Item = Result<AnthropicMessagesStreamFrame, AnthropicMessagesTransportError>>
            + Send
            + 'a,
    >,
>;

#[derive(Debug, Clone, PartialEq)]
pub struct AnthropicMessagesHttpRequest {
    pub method: &'static str,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: JsonValue,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnthropicMessagesHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: JsonValue,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AnthropicMessagesStreamFrame {
    Event(JsonValue),
    Abort { usage: LlmUsage },
    Status(AnthropicMessagesHttpResponse),
}

pub trait AnthropicMessagesTransport: Send + Sync {
    fn execute<'a>(
        &'a self,
        request: AnthropicMessagesHttpRequest,
        lease: &'a BudgetLease,
    ) -> AnthropicMessagesFuture<'a>;

    fn stream<'a>(
        &'a self,
        request: AnthropicMessagesHttpRequest,
        lease: &'a BudgetLease,
    ) -> Result<AnthropicMessagesProviderStream<'a>, AnthropicMessagesTransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AnthropicMessagesTransportError {
    #[error("Anthropic Messages transport timed out")]
    Timeout,
    #[error("Anthropic Messages transport stream was cut")]
    StreamCut,
    #[error("Anthropic Messages transport server error")]
    Server,
    #[error("Anthropic Messages transport connection failed")]
    Connection,
}

impl From<AnthropicMessagesTransportError> for LlmError {
    fn from(error: AnthropicMessagesTransportError) -> Self {
        match error {
            AnthropicMessagesTransportError::Timeout => RetryableLlmError::Timeout.into(),
            AnthropicMessagesTransportError::StreamCut
            | AnthropicMessagesTransportError::Connection => RetryableLlmError::StreamCut.into(),
            AnthropicMessagesTransportError::Server => RetryableLlmError::ServerError.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnthropicMessagesConfig {
    pub endpoint_path: String,
    pub anthropic_version: String,
    pub models: BTreeMap<ModelId, LlmCatalogEntry>,
}

impl AnthropicMessagesConfig {
    #[must_use]
    pub fn new(model: LlmCatalogEntry) -> Self {
        let mut models = BTreeMap::new();
        models.insert(model.model.clone(), model);
        Self {
            endpoint_path: "/v1/messages".to_owned(),
            anthropic_version: "2023-06-01".to_owned(),
            models,
        }
    }

    #[must_use]
    pub fn with_models(models: impl IntoIterator<Item = LlmCatalogEntry>) -> Self {
        Self {
            endpoint_path: "/v1/messages".to_owned(),
            anthropic_version: "2023-06-01".to_owned(),
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

    #[must_use]
    pub fn with_anthropic_version(mut self, version: impl Into<String>) -> Self {
        self.anthropic_version = version.into();
        self
    }

    fn catalog_entry(&self, model: &ModelId) -> LlmResult<&LlmCatalogEntry> {
        self.models
            .get(model)
            .ok_or_else(|| FatalLlmError::InvalidRequest.into())
    }
}

#[derive(Debug)]
pub struct AnthropicMessagesBackend<T> {
    config: AnthropicMessagesConfig,
    transport: T,
}

impl<T> AnthropicMessagesBackend<T> {
    #[must_use]
    pub fn new(config: AnthropicMessagesConfig, transport: T) -> Self {
        Self { config, transport }
    }

    #[must_use]
    pub fn config(&self) -> &AnthropicMessagesConfig {
        &self.config
    }

    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T> LlmBackend for AnthropicMessagesBackend<T>
where
    T: AnthropicMessagesTransport,
{
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let wire_request = build_anthropic_messages_request(&self.config, &request, false)?;
            let response = self.transport.execute(wire_request, lease).await?;
            if !(200..=299).contains(&response.status) {
                return Err(classify_anthropic_status(
                    response.status,
                    &response.headers,
                    &response.body,
                ));
            }
            parse_anthropic_messages_response(&response.body)
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let wire_request = build_anthropic_messages_request(&self.config, &request, true)?;
        let provider_stream = self.transport.stream(wire_request, lease)?;
        Ok(LlmStream::new(AnthropicMessagesLlmStream::new(
            provider_stream,
        )))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AnthropicProviderOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<AnthropicThinkingOptions>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<JsonValue>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub raw: BTreeMap<String, JsonValue>,
}

impl AnthropicProviderOptions {
    pub const NAMESPACE: &'static str = "anthropic";

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
                "thinking" => {
                    options.thinking = Some(
                        serde_json::from_value(value.clone())
                            .map_err(|_| FatalLlmError::InvalidRequest)?,
                    );
                }
                "metadata" => {
                    options.metadata = Some(value.clone());
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
        if let Some(thinking) = &self.thinking {
            fields.insert(
                "thinking".to_owned(),
                serde_json::to_value(thinking)
                    .expect("Anthropic thinking options serialize without failure"),
            );
        }
        if let Some(metadata) = &self.metadata {
            fields.insert("metadata".to_owned(), metadata.clone());
        }
        fields
    }

    #[must_use]
    pub fn requires_reasoning(&self) -> bool {
        self.thinking.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnthropicThinkingOptions {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u64>,
}

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

#[derive(Debug, Clone)]
pub struct AnthropicMessagesStreamAccumulator {
    text_part_id: String,
    text: String,
    text_started: bool,
    usage: Option<LlmUsage>,
    finish_reason: FinishReason,
    done: bool,
}

impl Default for AnthropicMessagesStreamAccumulator {
    fn default() -> Self {
        Self {
            text_part_id: "text-0".to_owned(),
            text: String::new(),
            text_started: false,
            usage: None,
            finish_reason: FinishReason::Stop,
            done: false,
        }
    }
}

impl AnthropicMessagesStreamAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_event(&mut self, event: JsonValue) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.done {
            return Ok(Vec::new());
        }

        let mut events = Vec::new();
        match event.get("type").and_then(JsonValue::as_str) {
            Some("message_start") => {
                if let Some(usage) = event
                    .get("message")
                    .and_then(|message| message.get("usage"))
                {
                    self.usage = Some(parse_anthropic_usage(usage));
                }
            }
            Some("content_block_start") => {
                if event
                    .get("content_block")
                    .and_then(|block| block.get("type"))
                    .and_then(JsonValue::as_str)
                    == Some("text")
                    && !self.text_started
                {
                    self.text_started = true;
                    events.push(LlmStreamEvent::TextStart {
                        part_id: self.text_part_id.clone(),
                    });
                }
            }
            Some("content_block_delta") => {
                if let Some(text) = event
                    .get("delta")
                    .and_then(|delta| delta.get("text"))
                    .and_then(JsonValue::as_str)
                    && !text.is_empty()
                {
                    self.push_text_delta(text, &mut events);
                }
            }
            Some("message_delta") => {
                if let Some(usage) = event.get("usage") {
                    self.usage = Some(parse_anthropic_usage(usage));
                }
                if let Some(stop_reason) = event
                    .get("delta")
                    .and_then(|delta| delta.get("stop_reason"))
                    .and_then(JsonValue::as_str)
                {
                    self.finish_reason = anthropic_finish_reason(stop_reason);
                }
            }
            Some("message_stop") => {
                events.extend(self.finish()?);
            }
            Some("error") => {
                return Err(classify_anthropic_status(500, &BTreeMap::new(), &event));
            }
            _ => {}
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

    fn finish(&mut self) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.done {
            return Ok(Vec::new());
        }
        self.done = true;

        if self.text.is_empty() {
            return Err(
                if matches!(self.finish_reason, FinishReason::ContentFiltered) {
                    FatalLlmError::ContentFiltered.into()
                } else {
                    FatalLlmError::EmptyResponse.into()
                },
            );
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
            finish_reason: self.finish_reason.clone(),
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

pub struct AnthropicMessagesLlmStream<'a> {
    provider_stream: AnthropicMessagesProviderStream<'a>,
    accumulator: AnthropicMessagesStreamAccumulator,
    pending: VecDeque<LlmResult<LlmStreamEvent>>,
}

impl<'a> AnthropicMessagesLlmStream<'a> {
    #[must_use]
    pub fn new(provider_stream: AnthropicMessagesProviderStream<'a>) -> Self {
        Self {
            provider_stream,
            accumulator: AnthropicMessagesStreamAccumulator::new(),
            pending: VecDeque::new(),
        }
    }
}

impl Stream for AnthropicMessagesLlmStream<'_> {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(event) = this.pending.pop_front() {
                return Poll::Ready(Some(event));
            }

            match this.provider_stream.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(AnthropicMessagesStreamFrame::Event(event)))) => {
                    match this.accumulator.push_event(event) {
                        Ok(events) => this.pending.extend(events.into_iter().map(Ok)),
                        Err(error) => return Poll::Ready(Some(Err(error))),
                    }
                }
                Poll::Ready(Some(Ok(AnthropicMessagesStreamFrame::Abort { usage }))) => {
                    this.pending
                        .extend(this.accumulator.abort_with_usage(usage).into_iter().map(Ok));
                }
                Poll::Ready(Some(Ok(AnthropicMessagesStreamFrame::Status(response)))) => {
                    return Poll::Ready(Some(Err(classify_anthropic_status(
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
    provider_options: &AnthropicProviderOptions,
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
    if provider_options.requires_reasoning() || request.params.contains_key("thinking") {
        require(
            catalog,
            LlmCapability::Reasoning,
            "request includes thinking controls",
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

fn parse_anthropic_usage(usage: &JsonValue) -> LlmUsage {
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

fn anthropic_finish_reason(reason: &str) -> FinishReason {
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

#[cfg(test)]
mod tests {
    use super::*;
    use oneiron::{
        CallClass, CallEnvelope, CallPurpose, DeterministicFallback, ModelLocality, ModelTierRef,
        TierPrecedence,
    };

    #[test]
    fn status_code_table_maps_to_typed_errors() {
        let headers = BTreeMap::from([("retry-after".to_owned(), "9".to_owned())]);
        let body = json!({ "error": { "type": "rate_limit_error" } });

        assert!(matches!(
            classify_anthropic_status(429, &headers, &body),
            LlmError::Retryable(RetryableLlmError::RateLimited {
                retry_after: Some(9)
            })
        ));
        assert!(matches!(
            classify_anthropic_status(
                529,
                &BTreeMap::new(),
                &json!({ "error": { "type": "overloaded_error" } })
            ),
            LlmError::Retryable(RetryableLlmError::ServerError)
        ));
        assert!(matches!(
            classify_anthropic_status(408, &BTreeMap::new(), &json!({})),
            LlmError::Retryable(RetryableLlmError::Timeout)
        ));
        assert!(matches!(
            classify_anthropic_status(
                401,
                &BTreeMap::new(),
                &json!({ "error": { "type": "authentication_error" } })
            ),
            LlmError::Fatal(FatalLlmError::Auth)
        ));
        assert!(matches!(
            classify_anthropic_status(
                400,
                &BTreeMap::new(),
                &json!({ "error": { "type": "invalid_request_error" } })
            ),
            LlmError::Fatal(FatalLlmError::InvalidRequest)
        ));
        assert!(matches!(
            classify_anthropic_status(
                400,
                &BTreeMap::new(),
                &json!({ "error": { "type": "content_filter_error" } })
            ),
            LlmError::Fatal(FatalLlmError::ContentFiltered)
        ));
    }

    #[test]
    fn unsupported_capability_is_typed() {
        let catalog = catalog_with([LlmCapability::JsonResponse]);
        let config = AnthropicMessagesConfig::new(catalog);
        let mut request = sample_request();
        request.tools = vec![LlmToolSpec {
            name: "route".to_owned(),
            description: "Route a call".to_owned(),
            input_schema: json!({ "type": "object" }),
        }];

        let error = build_anthropic_messages_request(&config, &request, false).unwrap_err();
        assert!(matches!(
            error,
            LlmError::Fatal(FatalLlmError::Unsupported(UnsupportedCapability {
                capability: LlmCapability::ToolCalling,
                ..
            }))
        ));
    }

    #[test]
    fn json_response_maps_to_native_output_config_format() {
        let catalog = catalog_with([LlmCapability::JsonResponse]);
        let config = AnthropicMessagesConfig::new(catalog);
        let request = sample_request();

        let wire = build_anthropic_messages_request(&config, &request, false).unwrap();

        assert_eq!(
            wire.body.get("output_config"),
            Some(&json!({
                "format": {
                    "type": "json_schema",
                    "schema": { "type": "object" },
                }
            }))
        );
        assert_eq!(wire.body.get("response_format"), None);
    }

    #[test]
    fn json_response_merges_into_caller_output_config() {
        let catalog = catalog_with([LlmCapability::JsonResponse]);
        let config = AnthropicMessagesConfig::new(catalog);
        let mut request = sample_request();
        request
            .params
            .insert("output_config".to_owned(), json!({ "effort": "high" }));

        let wire = build_anthropic_messages_request(&config, &request, false).unwrap();

        assert_eq!(
            wire.body.get("output_config"),
            Some(&json!({
                "effort": "high",
                "format": {
                    "type": "json_schema",
                    "schema": { "type": "object" },
                }
            }))
        );
        assert_eq!(wire.body.get("response_format"), None);
    }

    #[test]
    fn caller_response_format_param_is_stripped_from_wire() {
        let catalog = catalog_with([LlmCapability::JsonResponse]);
        let config = AnthropicMessagesConfig::new(catalog);
        let mut request = sample_request();
        request.envelope.response_format = ResponseFormat::Text;
        request.params.insert(
            "response_format".to_owned(),
            json!({ "type": "json_schema", "schema": { "type": "object" } }),
        );

        let wire = build_anthropic_messages_request(&config, &request, false).unwrap();

        assert_eq!(wire.body.get("response_format"), None);
    }

    #[test]
    fn non_object_output_config_with_json_response_is_invalid_request() {
        let catalog = catalog_with([LlmCapability::JsonResponse]);
        let config = AnthropicMessagesConfig::new(catalog);
        let mut request = sample_request();
        request
            .params
            .insert("output_config".to_owned(), json!("not-an-object"));

        let error = build_anthropic_messages_request(&config, &request, false).unwrap_err();
        assert!(matches!(
            error,
            LlmError::Fatal(FatalLlmError::InvalidRequest)
        ));
    }

    #[test]
    fn provider_options_parse_typed_fields_and_preserve_raw_escape_hatch() {
        let options = AnthropicProviderOptions::from_namespaced_value(&json!({
            "thinking": { "type": "enabled", "budget_tokens": 1024 },
            "metadata": { "user_id": "tenant-a" },
            "vendor_extension": { "mode": "strict" }
        }))
        .unwrap();

        assert_eq!(
            options
                .thinking
                .as_ref()
                .map(|thinking| thinking.kind.as_str()),
            Some("enabled")
        );
        assert_eq!(options.metadata, Some(json!({ "user_id": "tenant-a" })));
        assert_eq!(
            options.raw.get("vendor_extension"),
            Some(&json!({ "mode": "strict" }))
        );

        let wire = options.to_wire_fields();
        assert_eq!(
            wire.get("metadata"),
            Some(&json!({ "user_id": "tenant-a" }))
        );
        assert_eq!(
            wire.get("vendor_extension"),
            Some(&json!({ "mode": "strict" }))
        );
    }

    #[test]
    fn abort_retains_partial_text_and_settles_usage() {
        let mut accumulator = AnthropicMessagesStreamAccumulator::new();
        accumulator
            .push_event(json!({
                "type": "content_block_delta",
                "delta": { "type": "text_delta", "text": "help" }
            }))
            .unwrap();

        let usage = LlmUsage {
            input: LlmInputUsage {
                total: 7,
                cache_read: 2,
                cache_write: 1,
            },
            output: LlmOutputUsage {
                total: 3,
                text: 3,
                reasoning: 0,
            },
            raw_provider: json!({ "input_tokens": 7, "output_tokens": 3 }),
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
                text: "help".to_owned()
            }]
        );
        assert_eq!(*done.1, usage);
        assert_eq!(*done.2, FinishReason::Cancelled);
    }

    fn sample_request() -> LlmRequest {
        LlmRequest {
            model: ModelId::new("anthropic/claude-sonnet@2026-07-02").unwrap(),
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
            model: ModelId::new("anthropic/claude-sonnet@2026-07-02").unwrap(),
            display_name: "Claude Sonnet".to_owned(),
            locality: ModelLocality::ThirdParty,
            context_window_tokens: 200_000,
            max_output_tokens: Some(8_192),
            cost: None,
            capabilities: capabilities.into_iter().collect(),
            metadata: BTreeMap::new(),
        }
    }
}
