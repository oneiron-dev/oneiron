//! Chunk accumulation into LlmStreamEvent sequences with abort and empty-content rules.

use super::{
    OpenAiCompatProviderStream, OpenAiCompatStreamFrame, classify_openai_status,
    wire::{openai_finish_reason, parse_openai_usage},
};
use futures_core::Stream;
use oneiron::{
    ContentPart, FatalLlmError, FinishReason, LlmMessage, LlmMessageRole, LlmResult,
    LlmStreamEvent, LlmUsage,
};
use serde_json::Value as JsonValue;
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

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
