//! Runtime output parts and the in-progress generation envelope.
use oneiron::{FinishReason, ImageContent, LlmResult, LlmUsage};
use serde_json::Value as JsonValue;

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
