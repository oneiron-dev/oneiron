//! Shared typed stream assembly. Tool JSON is parsed only when its part closes.

use super::{
    ContentPart, FatalLlmError, FinishReason, LlmMessage, LlmMessageRole, LlmResult,
    LlmStreamEvent, LlmUsage, ReasoningPartKind, ReplyAssertions,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
enum PendingPart {
    Text {
        text: String,
        signature: Option<String>,
    },
    Reasoning {
        text: String,
        signature: Option<String>,
        reasoning_kind: ReasoningPartKind,
        data: Option<String>,
    },
    Tool {
        call_id: String,
        name: String,
        json: String,
        signature: Option<String>,
    },
}

/// Protocol-neutral assembly used by wire decoders. It preserves start order,
/// correlates every part, and excludes incomplete tool input from cancellation.
#[derive(Debug, Clone, Default)]
pub struct StreamAssembly {
    pending: BTreeMap<String, PendingPart>,
    completed: BTreeMap<String, ContentPart>,
    order: Vec<String>,
    done: bool,
}

impl StreamAssembly {
    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn text(&mut self, id: &str, text: &str) -> LlmResult<Vec<LlmStreamEvent>> {
        self.text_with_signature(id, text, None)
    }

    pub fn text_with_signature(
        &mut self,
        id: &str,
        text: &str,
        signature: Option<String>,
    ) -> LlmResult<Vec<LlmStreamEvent>> {
        let mut events = Vec::new();
        if !self.pending.contains_key(id) {
            self.start(
                id,
                PendingPart::Text {
                    text: String::new(),
                    signature: None,
                },
            )?;
            events.push(LlmStreamEvent::TextStart { part_id: id.into() });
        }
        let Some(PendingPart::Text {
            text: value,
            signature: stored,
        }) = self.pending.get_mut(id)
        else {
            return Err(FatalLlmError::InvalidRequest.into());
        };
        if signature.is_some() {
            *stored = signature;
        }
        if !text.is_empty() {
            value.push_str(text);
            events.push(LlmStreamEvent::TextDelta {
                part_id: id.into(),
                text: text.into(),
            });
        }
        Ok(events)
    }

    pub fn reasoning(
        &mut self,
        id: &str,
        text: &str,
        signature: Option<String>,
    ) -> LlmResult<Vec<LlmStreamEvent>> {
        self.reasoning_with_kind(id, text, signature, ReasoningPartKind::Full, None)
    }

    pub fn reasoning_with_kind(
        &mut self,
        id: &str,
        text: &str,
        signature: Option<String>,
        reasoning_kind: ReasoningPartKind,
        data: Option<String>,
    ) -> LlmResult<Vec<LlmStreamEvent>> {
        let mut events = Vec::new();
        if !self.pending.contains_key(id) {
            self.start(
                id,
                PendingPart::Reasoning {
                    text: String::new(),
                    signature: signature.clone(),
                    reasoning_kind,
                    data: data.clone(),
                },
            )?;
            events.push(LlmStreamEvent::ReasoningStart {
                part_id: id.into(),
                signature: signature.clone(),
                reasoning_kind,
                data: data.clone(),
            });
        }
        let Some(PendingPart::Reasoning {
            text: value,
            signature: stored,
            reasoning_kind: stored_kind,
            data: stored_data,
        }) = self.pending.get_mut(id)
        else {
            return Err(FatalLlmError::InvalidRequest.into());
        };
        if *stored_kind != reasoning_kind || *stored_data != data {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        if signature.is_some() {
            *stored = signature;
        }
        if !text.is_empty() {
            value.push_str(text);
            events.push(LlmStreamEvent::ReasoningDelta {
                part_id: id.into(),
                text: text.into(),
            });
        }
        Ok(events)
    }

    pub fn tool(
        &mut self,
        id: &str,
        call_id: &str,
        name: &str,
        fragment: &str,
    ) -> LlmResult<Vec<LlmStreamEvent>> {
        self.tool_with_signature(id, call_id, name, fragment, None)
    }

    pub fn tool_with_signature(
        &mut self,
        id: &str,
        call_id: &str,
        name: &str,
        fragment: &str,
        signature: Option<String>,
    ) -> LlmResult<Vec<LlmStreamEvent>> {
        let mut events = Vec::new();
        if !self.pending.contains_key(id) {
            if call_id.is_empty() || name.is_empty() {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            self.start(
                id,
                PendingPart::Tool {
                    call_id: call_id.into(),
                    name: name.into(),
                    json: String::new(),
                    signature: signature.clone(),
                },
            )?;
            events.push(LlmStreamEvent::ToolCallStart {
                part_id: id.into(),
                call_id: call_id.into(),
                name: name.into(),
            });
        }
        let Some(PendingPart::Tool {
            call_id: stored_id,
            name: stored_name,
            json,
            signature: stored,
        }) = self.pending.get_mut(id)
        else {
            return Err(FatalLlmError::InvalidRequest.into());
        };
        if stored_id != call_id || stored_name != name {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        if signature.is_some() {
            *stored = signature;
        }
        if !fragment.is_empty() {
            json.push_str(fragment);
            events.push(LlmStreamEvent::ToolCallDelta {
                part_id: id.into(),
                input_fragment: fragment.into(),
            });
        }
        Ok(events)
    }

    fn start(&mut self, id: &str, part: PendingPart) -> LlmResult<()> {
        if self.done || self.completed.contains_key(id) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.order.push(id.into());
        self.pending.insert(id.into(), part);
        Ok(())
    }

    pub fn end(&mut self, id: &str) -> LlmResult<LlmStreamEvent> {
        let part = self
            .pending
            .remove(id)
            .ok_or(FatalLlmError::InvalidRequest)?;
        let (content, event) = match part {
            PendingPart::Text { text, signature } => (
                ContentPart::Text {
                    text,
                    signature: signature.clone(),
                },
                LlmStreamEvent::TextEnd {
                    part_id: id.into(),
                    signature,
                },
            ),
            PendingPart::Reasoning {
                text,
                signature,
                reasoning_kind,
                data,
            } => (
                ContentPart::Reasoning {
                    text,
                    signature: signature.clone(),
                    reasoning_kind,
                    data,
                },
                LlmStreamEvent::ReasoningEnd {
                    part_id: id.into(),
                    signature,
                },
            ),
            PendingPart::Tool {
                call_id,
                name,
                json,
                signature,
            } => {
                let input: serde_json::Value =
                    serde_json::from_str(&json).map_err(|_| FatalLlmError::InvalidRequest)?;
                if !input.is_object() {
                    return Err(FatalLlmError::InvalidRequest.into());
                }
                let event = LlmStreamEvent::ToolCallEnd {
                    part_id: id.into(),
                    call_id: call_id.clone(),
                    name: name.clone(),
                    input: input.clone(),
                    signature: signature.clone(),
                };
                (
                    ContentPart::ToolCall {
                        call_id,
                        name,
                        input,
                        signature,
                    },
                    event,
                )
            }
        };
        self.completed.insert(id.into(), content);
        Ok(event)
    }

    pub fn finish(
        &mut self,
        usage: LlmUsage,
        reason: FinishReason,
    ) -> LlmResult<Vec<LlmStreamEvent>> {
        if self.done {
            return Ok(Vec::new());
        }
        let mut events = Vec::new();
        for id in self.order.clone() {
            if self.pending.contains_key(&id) {
                events.push(self.end(&id)?);
            }
        }
        let content = self.content();
        if content.is_empty()
            || content.iter().all(|p| match p {
                ContentPart::Text { text, signature } => text.is_empty() && signature.is_none(),
                ContentPart::Reasoning {
                    text,
                    signature,
                    data,
                    ..
                } => text.is_empty() && signature.is_none() && data.is_none(),
                _ => false,
            })
        {
            return Err(if reason == FinishReason::ContentFiltered {
                FatalLlmError::ContentFiltered
            } else {
                FatalLlmError::EmptyResponse
            }
            .into());
        }
        self.done = true;
        events.push(LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content,
            },
            usage,
            finish_reason: reason,
            // A wire's assembly is a raw boundary: it asserts no record.
            reply_assertions: ReplyAssertions::default(),
        });
        Ok(events)
    }

    pub fn abort(&mut self, usage: LlmUsage) -> Vec<LlmStreamEvent> {
        if self.done {
            return Vec::new();
        }
        // An incomplete tool is never promoted into executable content.
        let mut events = Vec::new();
        for id in self.order.clone() {
            if matches!(
                self.pending.get(&id),
                Some(PendingPart::Text { .. } | PendingPart::Reasoning { .. })
            ) && let Ok(event) = self.end(&id)
            {
                events.push(event);
            }
        }
        self.pending.clear();
        self.done = true;
        events.push(LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content: self.content(),
            },
            usage,
            finish_reason: FinishReason::Cancelled,
            reply_assertions: ReplyAssertions::default(),
        });
        events
    }

    fn content(&self) -> Vec<ContentPart> {
        self.order
            .iter()
            .filter_map(|id| self.completed.get(id).cloned())
            .collect()
    }
}
