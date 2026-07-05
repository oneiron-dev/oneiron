//! Local in-process adapter for Oneiron's [`LlmBackend`] seam.
//!
//! This crate intentionally does not download, select, or quantize models. It
//! adapts an already-loaded llama.cpp/mistral.rs-class runtime into the engine
//! trait and derives runtime capabilities from loaded model metadata.

use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use futures_core::Stream;
use futures_util::StreamExt;
use oneiron::{
    BudgetLease, ContentPart, FatalLlmError, FinishReason, ImageContent, LlmBackend, LlmCapability,
    LlmCatalogEntry, LlmGenerateFuture, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse,
    LlmResult, LlmStream, LlmStreamEvent, LlmStreamResult, LlmUsage, ModelId, ModelLocality,
    ResponseFormat, RetryableLlmError, UnsupportedCapability,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Abort handle for one local generation.
///
/// The adapter checks this handle between local output parts and also flips it
/// when a stream is dropped before a terminal event.
#[derive(Debug, Clone, Default)]
pub struct LocalAbortHandle {
    aborted: Arc<AtomicBool>,
}

impl LocalAbortHandle {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn abort(&self) {
        self.aborted.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }
}

/// Metadata for the currently loaded local model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalModelMetadata {
    pub model: ModelId,
    pub display_name: String,
    pub locality: ModelLocality,
    pub context_window_tokens: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, JsonValue>,
}

impl LocalModelMetadata {
    #[must_use]
    pub fn new(
        model: ModelId,
        display_name: impl Into<String>,
        context_window_tokens: u64,
    ) -> Self {
        Self {
            model,
            display_name: display_name.into(),
            locality: ModelLocality::OnDevice,
            context_window_tokens,
            max_output_tokens: None,
            metadata: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_metadata(mut self, metadata: BTreeMap<String, JsonValue>) -> Self {
        self.metadata = metadata;
        self
    }

    #[must_use]
    pub fn with_max_output_tokens(mut self, max_output_tokens: u64) -> Self {
        self.max_output_tokens = Some(max_output_tokens);
        self
    }

    #[must_use]
    pub fn with_locality(mut self, locality: ModelLocality) -> Self {
        self.locality = locality;
        self
    }

    /// Build the engine catalog descriptor from loaded model metadata.
    #[must_use]
    pub fn catalog_entry(&self) -> LlmCatalogEntry {
        LlmCatalogEntry {
            model: self.model.clone(),
            display_name: if self.display_name.is_empty() {
                self.model.name().to_owned()
            } else {
                self.display_name.clone()
            },
            locality: self.locality,
            context_window_tokens: self.context_window_tokens,
            max_output_tokens: self.max_output_tokens,
            cost: None,
            capabilities: self.detect_capabilities(),
            metadata: self.metadata.clone(),
        }
    }

    #[must_use]
    pub fn detect_capabilities(&self) -> Vec<LlmCapability> {
        let mut capabilities = Vec::new();
        push_capability(&mut capabilities, LlmCapability::Streaming);

        if metadata_declares_tool_calling(&self.metadata) {
            push_capability(&mut capabilities, LlmCapability::ToolCalling);
            push_capability(&mut capabilities, LlmCapability::ToolResults);
        }
        if metadata_declares_capability(&self.metadata, CapabilityProbe::JsonResponse) {
            push_capability(&mut capabilities, LlmCapability::JsonResponse);
        }
        if metadata_declares_capability(&self.metadata, CapabilityProbe::ImageInput) {
            push_capability(&mut capabilities, LlmCapability::ImageInput);
        }
        if metadata_declares_capability(&self.metadata, CapabilityProbe::Reasoning) {
            push_capability(&mut capabilities, LlmCapability::Reasoning);
        }
        if metadata_declares_capability(&self.metadata, CapabilityProbe::Voice) {
            push_capability(&mut capabilities, LlmCapability::Voice);
        }

        capabilities
    }
}

/// Runtime output part emitted by an already-loaded local model.
#[derive(Debug, Clone, PartialEq)]
pub enum LocalOutputPart {
    Text {
        part_id: Option<String>,
        text: String,
    },
    Reasoning {
        part_id: Option<String>,
        text: String,
        signature: Option<String>,
    },
    ToolCall {
        part_id: Option<String>,
        call_id: String,
        name: String,
        input: JsonValue,
    },
    ToolResult {
        part_id: Option<String>,
        call_id: String,
        output: JsonValue,
        is_error: bool,
    },
    Image {
        part_id: Option<String>,
        media_type: String,
        image: ImageContent,
    },
}

impl LocalOutputPart {
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text {
            part_id: None,
            text: text.into(),
        }
    }

    #[must_use]
    pub fn tool_call(
        call_id: impl Into<String>,
        name: impl Into<String>,
        input: JsonValue,
    ) -> Self {
        Self::ToolCall {
            part_id: None,
            call_id: call_id.into(),
            name: name.into(),
            input,
        }
    }

    #[must_use]
    pub fn with_part_id(mut self, part_id: impl Into<String>) -> Self {
        let part_id = Some(part_id.into());
        match &mut self {
            Self::Text {
                part_id: current, ..
            }
            | Self::Reasoning {
                part_id: current, ..
            }
            | Self::ToolCall {
                part_id: current, ..
            }
            | Self::ToolResult {
                part_id: current, ..
            }
            | Self::Image {
                part_id: current, ..
            } => *current = part_id,
        }
        self
    }
}

/// In-progress local generation returned by a runtime binding.
pub struct LocalGeneration<'a> {
    pub parts: Box<dyn Iterator<Item = LlmResult<LocalOutputPart>> + Send + 'a>,
    pub usage: LlmUsage,
    pub finish_reason: FinishReason,
}

impl<'a> LocalGeneration<'a> {
    #[must_use]
    pub fn from_parts<I>(parts: I, usage: LlmUsage, finish_reason: FinishReason) -> Self
    where
        I: IntoIterator<Item = LocalOutputPart>,
        I::IntoIter: Send + 'a,
    {
        Self {
            parts: Box::new(parts.into_iter().map(Ok)),
            usage,
            finish_reason,
        }
    }
}

/// Minimal seam implemented by an in-process local runtime binding.
pub trait LocalLlmRuntime: Send + Sync {
    fn metadata(&self) -> &LocalModelMetadata;

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        abort: LocalAbortHandle,
    ) -> LlmResult<LocalGeneration<'a>>;
}

/// Adapter from a local in-process runtime into [`LlmBackend`].
#[derive(Debug, Clone)]
pub struct LocalLlmBackend<R> {
    runtime: R,
}

impl<R> LocalLlmBackend<R>
where
    R: LocalLlmRuntime,
{
    #[must_use]
    pub fn new(runtime: R) -> Self {
        Self { runtime }
    }

    #[must_use]
    pub fn descriptor(&self) -> LlmCatalogEntry {
        self.runtime.metadata().catalog_entry()
    }

    pub fn stream_with_abort<'a>(
        &'a self,
        request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmResult<(LlmStream<'a>, LocalAbortHandle)> {
        let descriptor = self.descriptor();
        validate_request(&request, &descriptor)?;

        let abort = LocalAbortHandle::new();
        let generation = self.runtime.generate(request, abort.clone())?;
        let stream = LocalEventStream::new(generation, abort.clone());
        Ok((LlmStream::new(stream), abort))
    }
}

impl<R> LlmBackend for LocalLlmBackend<R>
where
    R: LocalLlmRuntime,
{
    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let (mut stream, _abort) = self.stream_with_abort(request, lease)?;
            while let Some(event) = stream.next().await {
                if let LlmStreamEvent::Done {
                    message,
                    usage,
                    finish_reason,
                } = event?
                {
                    return Ok(LlmResponse {
                        message,
                        usage,
                        finish_reason,
                    });
                }
            }

            Err(RetryableLlmError::StreamCut.into())
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        let (stream, _abort) = self.stream_with_abort(request, lease)?;
        Ok(stream)
    }
}

struct LocalEventStream<'a> {
    generation: LocalGeneration<'a>,
    abort: LocalAbortHandle,
    pending: VecDeque<LlmResult<LlmStreamEvent>>,
    content: Vec<ContentPart>,
    next_part_index: usize,
    terminal: bool,
}

impl<'a> LocalEventStream<'a> {
    fn new(generation: LocalGeneration<'a>, abort: LocalAbortHandle) -> Self {
        Self {
            generation,
            abort,
            pending: VecDeque::new(),
            content: Vec::new(),
            next_part_index: 0,
            terminal: false,
        }
    }

    fn finish(&mut self, finish_reason: FinishReason) -> LlmStreamEvent {
        self.terminal = true;
        LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: self.content.clone(),
            },
            usage: self.generation.usage.clone(),
            finish_reason,
        }
    }

    fn next_part_id(&mut self, part_id: Option<String>) -> String {
        let next = self.next_part_index;
        self.next_part_index += 1;
        part_id.unwrap_or_else(|| format!("part-{next}"))
    }

    fn enqueue_part(&mut self, part: LocalOutputPart) {
        match part {
            LocalOutputPart::Text { part_id, text } => {
                let part_id = self.next_part_id(part_id);
                self.pending.push_back(Ok(LlmStreamEvent::TextStart {
                    part_id: part_id.clone(),
                }));
                self.pending.push_back(Ok(LlmStreamEvent::TextDelta {
                    part_id: part_id.clone(),
                    text: text.clone(),
                }));
                self.pending
                    .push_back(Ok(LlmStreamEvent::TextEnd { part_id }));
                self.content.push(ContentPart::Text { text });
            }
            LocalOutputPart::Reasoning {
                part_id,
                text,
                signature,
            } => {
                let part_id = self.next_part_id(part_id);
                self.pending.push_back(Ok(LlmStreamEvent::ReasoningStart {
                    part_id: part_id.clone(),
                    signature: signature.clone(),
                }));
                self.pending.push_back(Ok(LlmStreamEvent::ReasoningDelta {
                    part_id: part_id.clone(),
                    text: text.clone(),
                }));
                self.pending
                    .push_back(Ok(LlmStreamEvent::ReasoningEnd { part_id }));
                self.content
                    .push(ContentPart::Reasoning { text, signature });
            }
            LocalOutputPart::ToolCall {
                part_id,
                call_id,
                name,
                input,
            } => {
                let part_id = self.next_part_id(part_id);
                let input_fragment = input.to_string();
                self.pending.push_back(Ok(LlmStreamEvent::ToolCallStart {
                    part_id: part_id.clone(),
                    call_id: call_id.clone(),
                    name: name.clone(),
                }));
                self.pending.push_back(Ok(LlmStreamEvent::ToolCallDelta {
                    part_id: part_id.clone(),
                    input_fragment,
                }));
                self.pending.push_back(Ok(LlmStreamEvent::ToolCallEnd {
                    part_id,
                    call_id: call_id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                }));
                self.content.push(ContentPart::ToolCall {
                    call_id,
                    name,
                    input,
                });
            }
            LocalOutputPart::ToolResult {
                part_id,
                call_id,
                output,
                is_error,
            } => {
                let part_id = self.next_part_id(part_id);
                let output_fragment = output.to_string();
                self.pending.push_back(Ok(LlmStreamEvent::ToolResultStart {
                    part_id: part_id.clone(),
                    call_id: call_id.clone(),
                }));
                self.pending.push_back(Ok(LlmStreamEvent::ToolResultDelta {
                    part_id: part_id.clone(),
                    output_fragment,
                }));
                self.pending.push_back(Ok(LlmStreamEvent::ToolResultEnd {
                    part_id,
                    call_id: call_id.clone(),
                    output: output.clone(),
                    is_error,
                }));
                self.content.push(ContentPart::ToolResult {
                    call_id,
                    output,
                    is_error,
                });
            }
            LocalOutputPart::Image {
                part_id,
                media_type,
                image,
            } => {
                let part_id = self.next_part_id(part_id);
                let data_fragment = match &image {
                    ImageContent::Base64 { data } => data.clone(),
                    ImageContent::Url { url } => url.clone(),
                };
                self.pending.push_back(Ok(LlmStreamEvent::ImageStart {
                    part_id: part_id.clone(),
                    media_type: media_type.clone(),
                }));
                self.pending.push_back(Ok(LlmStreamEvent::ImageDelta {
                    part_id: part_id.clone(),
                    data_fragment,
                }));
                self.pending.push_back(Ok(LlmStreamEvent::ImageEnd {
                    part_id,
                    media_type: media_type.clone(),
                    image: image.clone(),
                }));
                self.content.push(ContentPart::Image { media_type, image });
            }
        }
    }
}

impl Stream for LocalEventStream<'_> {
    type Item = LlmResult<LlmStreamEvent>;

    fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.terminal {
            return Poll::Ready(None);
        }

        if let Some(event) = self.pending.pop_front() {
            return Poll::Ready(Some(event));
        }

        if self.abort.is_aborted() {
            let event = self.finish(FinishReason::Cancelled);
            return Poll::Ready(Some(Ok(event)));
        }

        match self.generation.parts.next() {
            Some(Ok(part)) => {
                self.enqueue_part(part);
                Poll::Ready(self.pending.pop_front())
            }
            Some(Err(error)) => {
                self.terminal = true;
                Poll::Ready(Some(Err(error)))
            }
            None if self.content.is_empty() => {
                self.terminal = true;
                Poll::Ready(Some(Err(FatalLlmError::EmptyResponse.into())))
            }
            None => {
                let finish_reason = self.generation.finish_reason.clone();
                let event = self.finish(finish_reason);
                Poll::Ready(Some(Ok(event)))
            }
        }
    }
}

impl Drop for LocalEventStream<'_> {
    fn drop(&mut self) {
        if !self.terminal {
            self.abort.abort();
        }
    }
}

fn validate_request(request: &LlmRequest, descriptor: &LlmCatalogEntry) -> LlmResult<()> {
    if request.model != descriptor.model {
        return Err(FatalLlmError::InvalidRequest.into());
    }

    if !request.tools.is_empty() {
        require_capability(
            descriptor,
            LlmCapability::ToolCalling,
            "loaded model metadata does not advertise tool calling",
        )?;
    }

    if request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .any(|part| matches!(part, ContentPart::ToolResult { .. }))
    {
        require_capability(
            descriptor,
            LlmCapability::ToolResults,
            "loaded model metadata does not advertise tool-result replay",
        )?;
    }

    if request
        .messages
        .iter()
        .flat_map(|message| &message.content)
        .any(|part| matches!(part, ContentPart::Image { .. }))
    {
        require_capability(
            descriptor,
            LlmCapability::ImageInput,
            "loaded model metadata does not advertise image input",
        )?;
    }

    if matches!(
        request.envelope.response_format,
        ResponseFormat::Json { .. }
    ) {
        require_capability(
            descriptor,
            LlmCapability::JsonResponse,
            "loaded model metadata does not advertise JSON response mode",
        )?;
    }

    Ok(())
}

fn require_capability(
    descriptor: &LlmCatalogEntry,
    capability: LlmCapability,
    reason: &'static str,
) -> LlmResult<()> {
    if descriptor.supports(&capability) {
        Ok(())
    } else {
        Err(FatalLlmError::Unsupported(UnsupportedCapability {
            capability,
            model: Some(descriptor.model.clone()),
            reason: Some(reason.to_owned()),
        })
        .into())
    }
}

fn push_capability(capabilities: &mut Vec<LlmCapability>, capability: LlmCapability) {
    if !capabilities.contains(&capability) {
        capabilities.push(capability);
    }
}

#[derive(Clone, Copy)]
enum CapabilityProbe {
    JsonResponse,
    ImageInput,
    Reasoning,
    Voice,
}

fn metadata_declares_tool_calling(metadata: &BTreeMap<String, JsonValue>) -> bool {
    metadata.iter().any(|(key, value)| {
        key_declares_tool_calling(key, value)
            || capability_list_contains(value, "tool_calling")
            || value_declares_tool_calling(value)
    })
}

fn value_declares_tool_calling(value: &JsonValue) -> bool {
    match value {
        JsonValue::Object(map) => map.iter().any(|(key, value)| {
            key_declares_tool_calling(key, value)
                || capability_list_contains(value, "tool_calling")
                || value_declares_tool_calling(value)
        }),
        JsonValue::Array(values) => values.iter().any(value_declares_tool_calling),
        JsonValue::String(value) => template_has_tool_calling(value),
        _ => false,
    }
}

fn key_declares_tool_calling(key: &str, value: &JsonValue) -> bool {
    let normalized = normalize_key(key);
    matches!(
        normalized.as_str(),
        "tool_calling"
            | "tool_calls"
            | "supports_tools"
            | "supports_tool_calls"
            | "tool_use"
            | "function_calling"
    ) && truthy(value)
        || (normalized.contains("chat_template")
            && value.as_str().is_some_and(template_has_tool_calling))
}

fn metadata_declares_capability(
    metadata: &BTreeMap<String, JsonValue>,
    probe: CapabilityProbe,
) -> bool {
    metadata
        .iter()
        .any(|(key, value)| key_declares_capability(key, value, probe))
}

fn value_declares_capability(value: &JsonValue, probe: CapabilityProbe) -> bool {
    match value {
        JsonValue::Object(map) => map.iter().any(|(key, value)| {
            key_declares_capability(key, value, probe) || value_declares_capability(value, probe)
        }),
        JsonValue::Array(values) => values
            .iter()
            .any(|value| value_declares_capability(value, probe)),
        _ => false,
    }
}

fn key_declares_capability(key: &str, value: &JsonValue, probe: CapabilityProbe) -> bool {
    if capability_list_contains(value, probe.capability_name()) {
        return true;
    }

    let normalized = normalize_key(key);
    probe
        .key_aliases()
        .iter()
        .any(|alias| normalized == *alias && truthy(value))
        || value_declares_capability(value, probe)
}

impl CapabilityProbe {
    fn capability_name(self) -> &'static str {
        match self {
            Self::JsonResponse => "json_response",
            Self::ImageInput => "image_input",
            Self::Reasoning => "reasoning",
            Self::Voice => "voice",
        }
    }

    fn key_aliases(self) -> &'static [&'static str] {
        match self {
            Self::JsonResponse => &["json_response", "json_mode", "response_format_json"],
            Self::ImageInput => &["image_input", "vision", "multimodal"],
            Self::Reasoning => &["reasoning", "thinking"],
            Self::Voice => &["voice", "audio_output"],
        }
    }
}

fn capability_list_contains(value: &JsonValue, capability: &str) -> bool {
    match value {
        JsonValue::Array(values) => values.iter().any(|value| {
            value
                .as_str()
                .is_some_and(|entry| normalize_key(entry) == capability)
        }),
        JsonValue::String(value) => normalize_key(value) == capability,
        JsonValue::Object(map) => map.iter().any(|(key, value)| {
            normalize_key(key) == "capabilities" && capability_list_contains(value, capability)
        }),
        _ => false,
    }
}

fn truthy(value: &JsonValue) -> bool {
    match value {
        JsonValue::Bool(value) => *value,
        JsonValue::Number(value) => value.as_u64().is_some_and(|value| value > 0),
        JsonValue::String(value) => matches!(
            normalize_key(value).as_str(),
            "true" | "yes" | "1" | "supported" | "native" | "enabled"
        ),
        _ => false,
    }
}

fn template_has_tool_calling(template: &str) -> bool {
    let template = template.to_ascii_lowercase();
    template.contains("tool_call")
        || template.contains("<tool_call")
        || template.contains("available_tools")
        || template.contains("{% if tools")
}

fn normalize_key(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;

    use oneiron::{
        CallClass, CallEnvelope, CallPurpose, DeterministicFallback, LlmError, LlmToolSpec,
        ModelTierRef, TierPrecedence,
    };
    use serde_json::json;

    use super::*;

    #[derive(Clone)]
    struct FixtureRuntime {
        metadata: LocalModelMetadata,
        parts: Vec<LocalOutputPart>,
        usage: LlmUsage,
        finish_reason: FinishReason,
    }

    impl FixtureRuntime {
        fn new(metadata: LocalModelMetadata, parts: Vec<LocalOutputPart>) -> Self {
            Self {
                metadata,
                parts,
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Stop,
            }
        }

        fn with_finish_reason(mut self, finish_reason: FinishReason) -> Self {
            self.finish_reason = finish_reason;
            self
        }
    }

    impl LocalLlmRuntime for FixtureRuntime {
        fn metadata(&self) -> &LocalModelMetadata {
            &self.metadata
        }

        fn generate<'a>(
            &'a self,
            _request: LlmRequest,
            _abort: LocalAbortHandle,
        ) -> LlmResult<LocalGeneration<'a>> {
            Ok(LocalGeneration::from_parts(
                self.parts.clone(),
                self.usage.clone(),
                self.finish_reason.clone(),
            ))
        }
    }

    #[test]
    fn fixture_model_metadata_detects_tool_calling_support() {
        let without_tools = metadata_with(BTreeMap::new());
        let without_entry = without_tools.catalog_entry();
        assert!(without_entry.supports(&LlmCapability::Streaming));
        assert!(!without_entry.supports(&LlmCapability::ToolCalling));

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "tokenizer.chat_template".to_owned(),
            json!("{% if tools %}<tool_call>{{ tool.name }}</tool_call>{% endif %}"),
        );
        let with_tools = metadata_with(metadata);
        let with_entry = with_tools.catalog_entry();

        assert!(with_entry.supports(&LlmCapability::ToolCalling));
        assert!(with_entry.supports(&LlmCapability::ToolResults));
    }

    #[test]
    fn unsupported_tool_calling_request_fails_before_runtime_generation() {
        let backend = LocalLlmBackend::new(FixtureRuntime::new(
            metadata_with(BTreeMap::new()),
            vec![LocalOutputPart::text("unused")],
        ));
        let mut request = sample_request();
        request.tools.push(LlmToolSpec {
            name: "lookup_memory".to_owned(),
            description: "Look up memory".to_owned(),
            input_schema: json!({"type": "object"}),
        });

        let lease = BudgetLease::for_test("lease");
        let error = match backend.stream_with_abort(request, &lease) {
            Ok(_) => panic!("tool requests require detected tool support"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            LlmError::Fatal(FatalLlmError::Unsupported(UnsupportedCapability {
                capability: LlmCapability::ToolCalling,
                ..
            }))
        ));
    }

    #[test]
    fn stream_conforms_to_start_delta_end_and_terminal_done_contract() {
        let backend = LocalLlmBackend::new(
            FixtureRuntime::new(
                metadata_with_tool_support(),
                vec![
                    LocalOutputPart::text("hello").with_part_id("text-1"),
                    LocalOutputPart::tool_call(
                        "call-1",
                        "lookup_memory",
                        json!({"query": "atlas"}),
                    )
                    .with_part_id("tool-1"),
                ],
            )
            .with_finish_reason(FinishReason::ToolCalls),
        );

        let events = collect_events(
            backend
                .stream(sample_request(), &BudgetLease::for_test("lease"))
                .unwrap(),
        );

        assert_eq!(
            events,
            vec![
                LlmStreamEvent::TextStart {
                    part_id: "text-1".to_owned(),
                },
                LlmStreamEvent::TextDelta {
                    part_id: "text-1".to_owned(),
                    text: "hello".to_owned(),
                },
                LlmStreamEvent::TextEnd {
                    part_id: "text-1".to_owned(),
                },
                LlmStreamEvent::ToolCallStart {
                    part_id: "tool-1".to_owned(),
                    call_id: "call-1".to_owned(),
                    name: "lookup_memory".to_owned(),
                },
                LlmStreamEvent::ToolCallDelta {
                    part_id: "tool-1".to_owned(),
                    input_fragment: "{\"query\":\"atlas\"}".to_owned(),
                },
                LlmStreamEvent::ToolCallEnd {
                    part_id: "tool-1".to_owned(),
                    call_id: "call-1".to_owned(),
                    name: "lookup_memory".to_owned(),
                    input: json!({"query": "atlas"}),
                },
                LlmStreamEvent::Done {
                    message: LlmMessage {
                        role: LlmMessageRole::Assistant,
                        content: vec![
                            ContentPart::Text {
                                text: "hello".to_owned(),
                            },
                            ContentPart::ToolCall {
                                call_id: "call-1".to_owned(),
                                name: "lookup_memory".to_owned(),
                                input: json!({"query": "atlas"}),
                            },
                        ],
                    },
                    usage: LlmUsage::zero(),
                    finish_reason: FinishReason::ToolCalls,
                },
            ]
        );
    }

    #[test]
    fn abort_mid_generation_returns_cancelled_done_with_partial_message() {
        let backend = LocalLlmBackend::new(FixtureRuntime::new(
            metadata_with_tool_support(),
            vec![
                LocalOutputPart::text("first").with_part_id("text-1"),
                LocalOutputPart::text("second").with_part_id("text-2"),
            ],
        ));

        let lease = BudgetLease::for_test("lease");
        let (mut stream, abort) = backend.stream_with_abort(sample_request(), &lease).unwrap();
        assert_eq!(
            poll_stream_once(&mut stream).unwrap().unwrap(),
            LlmStreamEvent::TextStart {
                part_id: "text-1".to_owned(),
            }
        );
        assert_eq!(
            poll_stream_once(&mut stream).unwrap().unwrap(),
            LlmStreamEvent::TextDelta {
                part_id: "text-1".to_owned(),
                text: "first".to_owned(),
            }
        );
        assert_eq!(
            poll_stream_once(&mut stream).unwrap().unwrap(),
            LlmStreamEvent::TextEnd {
                part_id: "text-1".to_owned(),
            }
        );

        abort.abort();

        assert_eq!(
            poll_stream_once(&mut stream).unwrap().unwrap(),
            LlmStreamEvent::Done {
                message: LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content: vec![ContentPart::Text {
                        text: "first".to_owned(),
                    }],
                },
                usage: LlmUsage::zero(),
                finish_reason: FinishReason::Cancelled,
            }
        );
        assert!(poll_stream_once(&mut stream).is_none());
    }

    #[test]
    fn dropping_unfinished_stream_signals_prompt_abort() {
        let backend = LocalLlmBackend::new(FixtureRuntime::new(
            metadata_with_tool_support(),
            vec![LocalOutputPart::text("unfinished")],
        ));
        let lease = BudgetLease::for_test("lease");
        let (stream, abort) = backend.stream_with_abort(sample_request(), &lease).unwrap();

        drop(stream);

        assert!(abort.is_aborted());
    }

    fn metadata_with(metadata: BTreeMap<String, JsonValue>) -> LocalModelMetadata {
        LocalModelMetadata::new(
            ModelId::new("local/fixture@2026-07-06").unwrap(),
            "Fixture",
            8192,
        )
        .with_metadata(metadata)
    }

    fn metadata_with_tool_support() -> LocalModelMetadata {
        let mut metadata = BTreeMap::new();
        metadata.insert("tool_calling".to_owned(), json!(true));
        metadata_with(metadata)
    }

    fn sample_request() -> LlmRequest {
        LlmRequest {
            model: ModelId::new("local/fixture@2026-07-06").unwrap(),
            envelope: CallEnvelope {
                purpose: CallPurpose::AutoCheck,
                class: CallClass::Durable {
                    fallback: DeterministicFallback {
                        name: "fail_closed_to_proposed".to_owned(),
                        config: None,
                    },
                },
                tier: TierPrecedence {
                    per_call: None,
                    vault_policy: Some(ModelTierRef("local".to_owned())),
                    purpose_default: Some(ModelTierRef("tiny".to_owned())),
                    global_default: ModelTierRef("standard".to_owned()),
                },
                response_format: ResponseFormat::Text,
                locality: ModelLocality::OnDevice,
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

    fn collect_events(mut stream: LlmStream<'_>) -> Vec<LlmStreamEvent> {
        let mut events = Vec::new();
        while let Some(event) = poll_stream_once(&mut stream) {
            events.push(event.unwrap());
        }
        events
    }

    fn poll_stream_once(stream: &mut LlmStream<'_>) -> Option<LlmResult<LlmStreamEvent>> {
        let waker: &std::task::Waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        match Pin::new(stream).poll_next(&mut cx) {
            Poll::Ready(item) => item,
            Poll::Pending => panic!("fixture stream should not pend"),
        }
    }
}
