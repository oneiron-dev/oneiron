//! SSE accumulation into LlmStreamEvent sequences with abort and empty-content rules.

use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;
use oneiron::{
    ContentPart, FatalLlmError, FinishReason, LlmMessage, LlmMessageRole, LlmResult,
    LlmStreamEvent, LlmUsage,
};
use serde_json::Value as JsonValue;

use super::wire::{anthropic_finish_reason, parse_anthropic_usage};
use super::{
    AnthropicMessagesProviderStream, AnthropicMessagesStreamFrame, classify_anthropic_status,
};

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
