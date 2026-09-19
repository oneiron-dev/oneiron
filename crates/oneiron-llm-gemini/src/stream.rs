//! Gemini typed stream decoding. Done is the only durable event.
use super::{GeminiFrame, GeminiProviderStream, classify_status};
use futures_core::Stream;
use oneiron::{
    FatalLlmError, FinishReason, LlmInputUsage, LlmOutputUsage, LlmResult, LlmStreamEvent,
    LlmUsage, llm::StreamAssembly,
};
use serde_json::Value;
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};
#[derive(Debug, Clone, Default)]
pub(super) struct GeminiAccumulator {
    assembly: StreamAssembly,
    usage: Option<LlmUsage>,
    tool_seq: usize,
}
impl GeminiAccumulator {
    pub(super) fn push(&mut self, chunk: Value) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.assembly.is_done() {
            return Ok(vec![]);
        }
        if let Some(usage) = chunk.get("usageMetadata") {
            let count = |key| usage.get(key).and_then(Value::as_u64).unwrap_or(0);
            let text = count("candidatesTokenCount");
            let reasoning = count("thoughtsTokenCount");
            self.usage = Some(LlmUsage {
                input: LlmInputUsage {
                    total: count("promptTokenCount"),
                    cache_read: count("cachedContentTokenCount"),
                    cache_write: 0,
                },
                output: LlmOutputUsage {
                    total: text.saturating_add(reasoning),
                    text,
                    reasoning,
                },
                raw_provider: usage.clone(),
            });
        }
        let Some(candidate) = chunk.pointer("/candidates/0") else {
            if chunk.pointer("/promptFeedback/blockReason").is_some() {
                return Err(FatalLlmError::ContentFiltered.into());
            }
            return Ok(vec![]);
        };
        let mut events = Vec::new();
        if let Some(parts) = candidate
            .pointer("/content/parts")
            .and_then(Value::as_array)
        {
            for part in parts {
                if let Some(text) = part.get("text").and_then(Value::as_str) {
                    if part.get("thought").and_then(Value::as_bool) == Some(true) {
                        events.extend(
                            self.assembly.reasoning(
                                "reasoning-0",
                                text,
                                part.get("thoughtSignature")
                                    .and_then(Value::as_str)
                                    .map(str::to_owned),
                            )?,
                        );
                    } else {
                        events.extend(self.assembly.text("text-0", text)?);
                    }
                } else if let Some(call) = part.get("functionCall") {
                    let name = call
                        .get("name")
                        .and_then(Value::as_str)
                        .ok_or(FatalLlmError::InvalidRequest)?;
                    let id = call
                        .get("id")
                        .and_then(Value::as_str)
                        .map_or_else(|| format!("call-{}", self.tool_seq), str::to_owned);
                    self.tool_seq += 1;
                    let args = call.get("args").ok_or(FatalLlmError::InvalidRequest)?;
                    let part_id = format!("tool-{id}");
                    events.extend(self.assembly.tool(&part_id, &id, name, &args.to_string())?);
                    events.push(self.assembly.end(&part_id)?);
                } else if part.as_object().is_some_and(|fields| fields.len() == 1)
                    && part.get("thoughtSignature").is_some_and(Value::is_string)
                {
                    // Signature-only metadata is not unsupported content.
                    continue;
                } else {
                    return Err(FatalLlmError::InvalidRequest.into());
                }
            }
        }
        if let Some(reason) = candidate.get("finishReason").and_then(Value::as_str) {
            let reason = match reason {
                "STOP" if self.tool_seq > 0 => FinishReason::ToolCalls,
                "STOP" => FinishReason::Stop,
                "MAX_TOKENS" => FinishReason::Length,
                "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" => {
                    FinishReason::ContentFiltered
                }
                other => FinishReason::Other { name: other.into() },
            };
            events.extend(
                self.assembly
                    .finish(self.usage.clone().unwrap_or_else(LlmUsage::zero), reason)?,
            );
        }
        Ok(events)
    }
    pub(super) fn abort(&mut self, usage: LlmUsage) -> Vec<LlmStreamEvent> {
        self.assembly.abort(usage)
    }
}
pub(super) struct GeminiEventStream<'a> {
    source: GeminiProviderStream<'a>,
    accumulator: GeminiAccumulator,
    pending: VecDeque<LlmResult<LlmStreamEvent>>,
}
impl<'a> GeminiEventStream<'a> {
    pub(super) fn new(source: GeminiProviderStream<'a>) -> Self {
        Self {
            source,
            accumulator: Default::default(),
            pending: VecDeque::new(),
        }
    }
}
impl Stream for GeminiEventStream<'_> {
    type Item = LlmResult<LlmStreamEvent>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(event) = this.pending.pop_front() {
                return Poll::Ready(Some(event));
            }
            match this.source.as_mut().poll_next(cx) {
                Poll::Ready(Some(Ok(GeminiFrame::Chunk(chunk)))) => {
                    match this.accumulator.push(chunk) {
                        Ok(events) => this.pending.extend(events.into_iter().map(Ok)),
                        Err(e) => return Poll::Ready(Some(Err(e))),
                    }
                }
                Poll::Ready(Some(Ok(GeminiFrame::Abort(usage)))) => this
                    .pending
                    .extend(this.accumulator.abort(usage).into_iter().map(Ok)),
                Poll::Ready(Some(Ok(GeminiFrame::Status(response)))) => {
                    if (200..300).contains(&response.status) {
                        continue;
                    }
                    return Poll::Ready(Some(Err(classify_status(
                        response.status,
                        &response.body,
                    ))));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
