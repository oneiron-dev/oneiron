//! OpenAI chunk decoding with correlated text, reasoning, and tool fragments.
use super::{
    OpenAiCompatProviderStream, OpenAiCompatStreamFrame, classify_openai_status,
    wire::{openai_finish_reason, parse_openai_usage},
};
use futures_core::Stream;
use oneiron::llm::StreamAssembly;
use oneiron::{FatalLlmError, FinishReason, LlmResult, LlmStreamEvent, LlmUsage, ModelId};
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
    /// The model the call was admitted for, which the stream's inference
    /// receipts are bound to (FIX 8314); `None` binds none.
    model: Option<ModelId>,
}

impl OpenAiCompatStreamAccumulator {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The usage a stream reported, its inference receipts bound to the
    /// admitted model.
    fn bound(&self, mut usage: LlmUsage) -> LlmUsage {
        if let Some(model) = &self.model {
            usage.bind_inference_model(model);
        }
        usage
    }

    pub fn push_chunk(&mut self, chunk: JsonValue) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.assembly.is_done() {
            return Ok(Vec::new());
        }
        // A provider that refuses once its stream is open sends the error as
        // an event: a spent quota there is the refusal a 429 would have been.
        if chunk
            .get("error")
            .is_some_and(|error| error.is_object() || error.is_string())
        {
            let status = oneiron::llm::limit::stream_error_status(&chunk);
            return Err(classify_openai_status(status, &BTreeMap::new(), &chunk));
        }
        if let Some(usage) = chunk.get("usage").filter(|v| !v.is_null()) {
            self.usage = Some(self.bound(parse_openai_usage(usage)));
        }
        let mut events = Vec::new();
        // A chunk this decoder cannot walk could hold a tool request behind
        // the text before it, so choices, a choice or a delta of any other
        // shape fail the stream rather than read as empty.
        let choices = match chunk.get("choices") {
            None | Some(JsonValue::Null) => None,
            Some(JsonValue::Array(choices)) => choices.first(),
            Some(_) => return Err(FatalLlmError::InvalidRequest.into()),
        };
        let Some(choice) = choices else {
            return if self.usage.is_some() {
                self.finish_eof()
            } else {
                Ok(events)
            };
        };
        if !choice.is_object() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        if choice
            .get("index")
            .and_then(JsonValue::as_u64)
            .is_some_and(|n| n != 0)
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        if let Some(delta) = choice.get("delta").filter(|delta| !delta.is_null()) {
            if !delta.is_object() {
                return Err(FatalLlmError::InvalidRequest.into());
            }
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
            // As in the buffered decoder, a tool call this decoder cannot read
            // fails the stream rather than leaving the reply looking tool-free.
            let tools = match delta.get("tool_calls") {
                None | Some(JsonValue::Null) => &[][..],
                Some(JsonValue::Array(tools)) => tools.as_slice(),
                Some(_) => return Err(FatalLlmError::InvalidRequest.into()),
            };
            if delta
                .get("function_call")
                .is_some_and(|call| !call.is_null())
            {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            for tool in tools {
                let index = tool
                    .get("index")
                    .and_then(JsonValue::as_u64)
                    .ok_or(FatalLlmError::InvalidRequest)?;
                let header = self.tools.entry(index).or_default();
                if let Some(id) = tool.get("id").and_then(JsonValue::as_str)
                    && header.call_id != id
                {
                    header.call_id.push_str(id);
                }
                let function = &tool["function"];
                if let Some(name) = function.get("name").and_then(JsonValue::as_str)
                    && header.name != name
                {
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
                    if header.call_id.is_empty() || header.name.is_empty() {
                        return Err(FatalLlmError::InvalidRequest.into());
                    }
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
        let usage = self.bound(usage);
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

    /// The stream of a call admitted for `model`: its inference receipts
    /// name that model (FIX 8314).
    pub(crate) fn bound_to(mut self, model: ModelId) -> Self {
        self.accumulator.model = Some(model);
        self
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
