//! Shared typed stream assembly. Tool JSON is parsed only when its part closes.

use super::{
    ContentPart, FatalLlmError, FinishReason, LlmMessage, LlmMessageRole, LlmResult,
    LlmStreamEvent, LlmUsage,
};
use std::collections::BTreeMap;

#[derive(Debug, Clone)]
enum PendingPart {
    Text(String),
    Reasoning {
        text: String,
        signature: Option<String>,
    },
    Tool {
        call_id: String,
        name: String,
        json: String,
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
        let mut events = Vec::new();
        if !self.pending.contains_key(id) {
            self.start(id, PendingPart::Text(String::new()))?;
            events.push(LlmStreamEvent::TextStart { part_id: id.into() });
        }
        let Some(PendingPart::Text(value)) = self.pending.get_mut(id) else {
            return Err(FatalLlmError::InvalidRequest.into());
        };
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
        let mut events = Vec::new();
        if !self.pending.contains_key(id) {
            self.start(
                id,
                PendingPart::Reasoning {
                    text: String::new(),
                    signature: signature.clone(),
                },
            )?;
            events.push(LlmStreamEvent::ReasoningStart {
                part_id: id.into(),
                signature: signature.clone(),
            });
        }
        let Some(PendingPart::Reasoning {
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
        }) = self.pending.get_mut(id)
        else {
            return Err(FatalLlmError::InvalidRequest.into());
        };
        if stored_id != call_id || stored_name != name {
            return Err(FatalLlmError::InvalidRequest.into());
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
            PendingPart::Text(text) => (
                ContentPart::Text { text },
                LlmStreamEvent::TextEnd { part_id: id.into() },
            ),
            PendingPart::Reasoning { text, signature } => (
                ContentPart::Reasoning { text, signature },
                LlmStreamEvent::ReasoningEnd { part_id: id.into() },
            ),
            PendingPart::Tool {
                call_id,
                name,
                json,
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
                };
                (
                    ContentPart::ToolCall {
                        call_id,
                        name,
                        input,
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
        if content.is_empty() || content.iter().all(|p| matches!(p, ContentPart::Text { text } | ContentPart::Reasoning { text, .. } if text.is_empty())) {
            return Err(if reason == FinishReason::ContentFiltered { FatalLlmError::ContentFiltered } else { FatalLlmError::EmptyResponse }.into());
        }
        self.done = true;
        events.push(LlmStreamEvent::Done {
            message: LlmMessage {
                role: LlmMessageRole::Assistant,
                content,
            },
            usage,
            finish_reason: reason,
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
                Some(PendingPart::Text(_) | PendingPart::Reasoning { .. })
            ) && let Ok(event) = self.end(&id) {
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
