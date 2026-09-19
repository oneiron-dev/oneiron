//! Anthropic block-indexed SSE decoder, including thinking and tool input.
use super::wire::{anthropic_finish_reason, parse_anthropic_usage};
use super::{
    AnthropicMessagesProviderStream, AnthropicMessagesStreamFrame, classify_anthropic_status,
};
use futures_core::Stream;
use oneiron::llm::StreamAssembly;
use oneiron::{FatalLlmError, FinishReason, LlmResult, LlmStreamEvent, LlmUsage};
use serde_json::Value as JsonValue;
use std::{
    collections::{BTreeMap, VecDeque},
    pin::Pin,
    task::{Context, Poll},
};

#[derive(Debug, Clone)]
pub struct AnthropicMessagesStreamAccumulator {
    assembly: StreamAssembly,
    tools: BTreeMap<u64, (String, String, Option<JsonValue>)>,
    tool_has_delta: std::collections::BTreeSet<u64>,
    usage: LlmUsage,
    finish_reason: FinishReason,
}
impl Default for AnthropicMessagesStreamAccumulator {
    fn default() -> Self {
        Self {
            assembly: StreamAssembly::default(),
            tools: BTreeMap::new(),
            tool_has_delta: Default::default(),
            usage: LlmUsage::zero(),
            finish_reason: FinishReason::Stop,
        }
    }
}
impl AnthropicMessagesStreamAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    pub fn push_event(&mut self, event: JsonValue) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.assembly.is_done() {
            return Ok(Vec::new());
        }
        let index = event.get("index").and_then(JsonValue::as_u64).unwrap_or(0);
        let id = format!("block-{index}");
        let mut events = Vec::new();
        match event.get("type").and_then(JsonValue::as_str) {
            Some("message_start") => {
                if let Some(usage) = event.get("message").and_then(|m| m.get("usage")) {
                    self.usage = parse_anthropic_usage(usage);
                }
            }
            Some("content_block_start") => {
                let block = &event["content_block"];
                match block.get("type").and_then(JsonValue::as_str) {
                    Some("text") => events.extend(
                        self.assembly
                            .text(&id, block["text"].as_str().unwrap_or(""))?,
                    ),
                    Some("thinking") => events.extend(self.assembly.reasoning(
                        &id,
                        block["thinking"].as_str().unwrap_or(""),
                        block["signature"].as_str().map(str::to_owned),
                    )?),
                    Some("tool_use") => {
                        let call_id = block["id"]
                            .as_str()
                            .ok_or(FatalLlmError::InvalidRequest)?
                            .to_owned();
                        let name = block["name"]
                            .as_str()
                            .ok_or(FatalLlmError::InvalidRequest)?
                            .to_owned();
                        events.extend(self.assembly.tool(&id, &call_id, &name, "")?);
                        self.tools
                            .insert(index, (call_id, name, block.get("input").cloned()));
                    }
                    _ => return Err(FatalLlmError::InvalidRequest.into()),
                }
            }
            Some("content_block_delta") => {
                let delta = &event["delta"];
                match delta.get("type").and_then(JsonValue::as_str) {
                    Some("text_delta") => events.extend(
                        self.assembly.text(
                            &id,
                            delta["text"]
                                .as_str()
                                .ok_or(FatalLlmError::InvalidRequest)?,
                        )?,
                    ),
                    Some("thinking_delta") => events.extend(
                        self.assembly.reasoning(
                            &id,
                            delta["thinking"]
                                .as_str()
                                .ok_or(FatalLlmError::InvalidRequest)?,
                            None,
                        )?,
                    ),
                    Some("signature_delta") => events.extend(
                        self.assembly.reasoning(
                            &id,
                            "",
                            Some(
                                delta["signature"]
                                    .as_str()
                                    .ok_or(FatalLlmError::InvalidRequest)?
                                    .into(),
                            ),
                        )?,
                    ),
                    Some("input_json_delta") => {
                        let (call_id, name, _) = self
                            .tools
                            .get(&index)
                            .ok_or(FatalLlmError::InvalidRequest)?;
                        self.tool_has_delta.insert(index);
                        events.extend(
                            self.assembly.tool(
                                &id,
                                call_id,
                                name,
                                delta["partial_json"]
                                    .as_str()
                                    .ok_or(FatalLlmError::InvalidRequest)?,
                            )?,
                        );
                    }
                    _ => return Err(FatalLlmError::InvalidRequest.into()),
                }
            }
            Some("content_block_stop") => {
                if let Some((call_id, name, input)) = self.tools.get(&index) {
                    if !self.tool_has_delta.contains(&index) {
                        events.extend(self.assembly.tool(
                            &id,
                            call_id,
                            name,
                            &input.as_ref().unwrap_or(&serde_json::json!({})).to_string(),
                        )?);
                    }
                }
                events.push(self.assembly.end(&id)?);
            }
            Some("message_delta") => {
                if let Some(usage) = event.get("usage") {
                    let parsed = parse_anthropic_usage(usage);
                    // Message deltas usually contain output only: do not erase input spend.
                    if usage.get("input_tokens").is_some() {
                        self.usage.input = parsed.input;
                    }
                    if usage.get("output_tokens").is_some() {
                        self.usage.output = parsed.output;
                    }
                    self.usage.raw_provider = usage.clone();
                }
                if let Some(reason) = event["delta"]["stop_reason"].as_str() {
                    self.finish_reason = anthropic_finish_reason(reason);
                }
            }
            Some("message_stop") => events.extend(
                self.assembly
                    .finish(self.usage.clone(), self.finish_reason.clone())?,
            ),
            Some("error") => return Err(classify_anthropic_status(500, &BTreeMap::new(), &event)),
            _ => {}
        }
        Ok(events)
    }
    #[must_use]
    pub fn abort_with_usage(&mut self, usage: LlmUsage) -> Vec<LlmStreamEvent> {
        self.assembly.abort(usage)
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
