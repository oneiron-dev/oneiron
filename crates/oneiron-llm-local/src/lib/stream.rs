//! Output-part fan-out into LlmStreamEvent sequences with abort and drop handling.
use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_core::Stream;
use oneiron::{
    ContentPart, FatalLlmError, FinishReason, ImageContent, LlmMessage, LlmMessageRole, LlmResult,
    LlmStreamEvent,
};

use super::abort::LocalAbortHandle;
use super::output::{LocalGeneration, LocalOutputPart};

pub(crate) struct LocalEventStream<'a> {
    generation: LocalGeneration<'a>,
    abort: LocalAbortHandle,
    pending: VecDeque<LlmResult<LlmStreamEvent>>,
    content: Vec<ContentPart>,
    next_part_index: usize,
    terminal: bool,
}

impl<'a> LocalEventStream<'a> {
    pub(crate) fn new(generation: LocalGeneration<'a>, abort: LocalAbortHandle) -> Self {
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
