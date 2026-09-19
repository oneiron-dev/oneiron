//! OpenAI chunk decoding with correlated text, reasoning, and tool fragments.
use super::{
    OpenAiCompatProviderStream, OpenAiCompatStreamFrame, classify_openai_status,
    wire::{openai_finish_reason, parse_openai_usage},
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

#[derive(Debug, Clone, Default)]
struct ToolHeader {
    call_id: String,
    name: String,
}

#[derive(Debug, Clone, Default)]
pub struct OpenAiCompatStreamAccumulator {
    assembly: StreamAssembly,
    tools: BTreeMap<u64, ToolHeader>,
    usage: Option<LlmUsage>,
    pending_finish: Option<FinishReason>,
}

impl OpenAiCompatStreamAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push_chunk(&mut self, chunk: JsonValue) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.assembly.is_done() {
            return Ok(Vec::new());
        }
        if let Some(usage) = chunk.get("usage").filter(|v| !v.is_null()) {
            self.usage = Some(parse_openai_usage(usage));
        }
        let mut events = Vec::new();
        let Some(choice) = chunk
            .get("choices")
            .and_then(JsonValue::as_array)
            .and_then(|v| v.first())
        else {
            return if self.usage.is_some() {
                self.finish_eof()
            } else {
                Ok(events)
            };
        };
        if choice
            .get("index")
            .and_then(JsonValue::as_u64)
            .is_some_and(|n| n != 0)
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        if let Some(delta) = choice.get("delta") {
            if let Some(text) = delta
                .get("content")
                .and_then(JsonValue::as_str)
                .filter(|v| !v.is_empty())
            {
                events.extend(self.assembly.text("text-0", text)?);
            }
            if let Some(text) = delta
                .get("reasoning_content")
                .or_else(|| delta.get("reasoning"))
                .and_then(JsonValue::as_str)
                .filter(|v| !v.is_empty())
            {
                events.extend(self.assembly.reasoning("reasoning-0", text, None)?);
            }
            if let Some(tools) = delta.get("tool_calls").and_then(JsonValue::as_array) {
                for tool in tools {
                    let index = tool
                        .get("index")
                        .and_then(JsonValue::as_u64)
                        .ok_or(FatalLlmError::InvalidRequest)?;
                    let header = self.tools.entry(index).or_default();
                    if let Some(id) = tool.get("id").and_then(JsonValue::as_str) {
                        header.call_id.push_str(id);
                    }
                    let function = &tool["function"];
                    if let Some(name) = function.get("name").and_then(JsonValue::as_str) {
                        header.name.push_str(name);
                    }
                    if let Some(fragment) = function.get("arguments").and_then(JsonValue::as_str) {
                        events.extend(self.assembly.tool(
                            &format!("tool-{index}"),
                            &header.call_id,
                            &header.name,
                            fragment,
                        )?);
                    }
                }
            }
        }
        if let Some(finish) = choice.get("finish_reason").and_then(JsonValue::as_str) {
            self.pending_finish = Some(openai_finish_reason(finish));
            if self.usage.is_some() {
                events.extend(self.finish_eof()?);
            }
        }
        Ok(events)
    }

    pub fn finish_eof(&mut self) -> LlmResult<Vec<LlmStreamEvent>> {
        match self.pending_finish.take() {
            Some(reason) => {
                for (index, header) in &self.tools {
                    self.assembly.tool(
                        &format!("tool-{index}"),
                        &header.call_id,
                        &header.name,
                        "",
                    )?;
                }
                self.assembly
                    .finish(self.usage.clone().unwrap_or_else(LlmUsage::zero), reason)
            }
            None => Ok(Vec::new()),
        }
    }

    #[must_use]
    pub fn abort_with_usage(&mut self, usage: LlmUsage) -> Vec<LlmStreamEvent> {
        self.assembly.abort(usage)
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
                Poll::Ready(None) => match this.accumulator.finish_eof() {
                    Ok(events) if events.is_empty() => return Poll::Ready(None),
                    Ok(events) => this.pending.extend(events.into_iter().map(Ok)),
                    Err(error) => return Poll::Ready(Some(Err(error))),
                },
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
