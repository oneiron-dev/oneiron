//! What a checked stream has already shown its caller (FIX 8617): each
//! part in the order it started, its text as it arrived, a tool call's and
//! an image's whole content once it ended. A terminal message is held to
//! it: text and reasoning as one run each (backends cut chunks where they
//! like), reasoning signatures, every tool call's identity and input, and
//! every image, in order. A terminal that disagrees does not replace what
//! was shown; the shown output is the answer, typed incomplete.

use std::collections::BTreeMap;

use oneiron::{ContentPart, ImageContent, LlmMessage, LlmMessageRole, LlmStreamEvent};
use serde_json::Value as JsonValue;

/// One part as it was shown.
enum Shown {
    Text(String),
    Reasoning {
        text: String,
        signature: Option<String>,
    },
    Tool {
        call_id: String,
        name: String,
        input: Option<JsonValue>,
    },
    Image {
        media_type: String,
        image: Option<ImageContent>,
    },
}

/// Everything a stream has shown, by part id, in start order.
#[derive(Default)]
pub(crate) struct Emitted {
    order: Vec<String>,
    parts: BTreeMap<String, Shown>,
}

/// The content a message carries, in the shape a terminal is held to.
#[derive(PartialEq)]
struct Summary<'a> {
    text: String,
    reasoning: String,
    signatures: Vec<&'a str>,
    tools: Vec<(&'a str, &'a str, &'a JsonValue)>,
    images: Vec<(&'a str, &'a ImageContent)>,
}

impl Emitted {
    /// Notes `event`, which the stream's checks passed, as shown.
    pub(crate) fn note(&mut self, event: &LlmStreamEvent) {
        use LlmStreamEvent as Event;
        match event {
            Event::TextStart { part_id } => self.start(part_id, Shown::Text(String::new())),
            Event::ReasoningStart { part_id, signature } => self.start(
                part_id,
                Shown::Reasoning {
                    text: String::new(),
                    signature: signature.clone(),
                },
            ),
            Event::TextDelta { part_id, text } | Event::ReasoningDelta { part_id, text } => {
                if let Some(Shown::Text(shown) | Shown::Reasoning { text: shown, .. }) =
                    self.parts.get_mut(part_id)
                {
                    shown.push_str(text);
                }
            }
            Event::ToolCallStart {
                part_id,
                call_id,
                name,
            } => self.start(
                part_id,
                Shown::Tool {
                    call_id: call_id.clone(),
                    name: name.clone(),
                    input: None,
                },
            ),
            Event::ToolCallEnd { part_id, input, .. } => {
                if let Some(Shown::Tool { input: shown, .. }) = self.parts.get_mut(part_id) {
                    *shown = Some(input.clone());
                }
            }
            Event::ImageStart {
                part_id,
                media_type,
            } => self.start(
                part_id,
                Shown::Image {
                    media_type: media_type.clone(),
                    image: None,
                },
            ),
            Event::ImageEnd { part_id, image, .. } => {
                if let Some(Shown::Image { image: shown, .. }) = self.parts.get_mut(part_id) {
                    *shown = Some(image.clone());
                }
            }
            _ => {}
        }
    }

    /// Whether the stream has shown no content yet: a terminal-only answer
    /// is the answer then.
    pub(crate) fn is_empty(&self) -> bool {
        self.parts.values().all(|part| match part {
            Shown::Text(text) | Shown::Reasoning { text, .. } => text.is_empty(),
            Shown::Tool { .. } | Shown::Image { .. } => false,
        })
    }

    /// Whether `message` carries what the stream showed, as a terminal must.
    pub(crate) fn agrees(&self, message: &LlmMessage) -> bool {
        summary(self.content().iter()) == summary(message.content.iter())
    }

    /// What the stream showed, as the answer's message.
    pub(crate) fn message(&self) -> LlmMessage {
        LlmMessage {
            role: LlmMessageRole::Assistant,
            content: self.content(),
        }
    }

    fn start(&mut self, id: &str, part: Shown) {
        self.order.push(id.to_owned());
        self.parts.insert(id.to_owned(), part);
    }

    /// The shown parts as content, in start order. A tool call or an image
    /// shows as content once it ended.
    fn content(&self) -> Vec<ContentPart> {
        self.order
            .iter()
            .filter_map(|id| match self.parts.get(id)? {
                Shown::Text(text) => Some(ContentPart::Text { text: text.clone() }),
                Shown::Reasoning { text, signature } => Some(ContentPart::Reasoning {
                    text: text.clone(),
                    signature: signature.clone(),
                }),
                Shown::Tool {
                    call_id,
                    name,
                    input,
                } => Some(ContentPart::ToolCall {
                    call_id: call_id.clone(),
                    name: name.clone(),
                    input: input.clone()?,
                }),
                Shown::Image { media_type, image } => Some(ContentPart::Image {
                    media_type: media_type.clone(),
                    image: image.clone()?,
                }),
            })
            .collect()
    }
}

/// `content` as a terminal is held to it.
fn summary<'a>(content: impl Iterator<Item = &'a ContentPart>) -> Summary<'a> {
    let mut summary = Summary {
        text: String::new(),
        reasoning: String::new(),
        signatures: Vec::new(),
        tools: Vec::new(),
        images: Vec::new(),
    };
    for part in content {
        match part {
            ContentPart::Text { text } => summary.text.push_str(text),
            ContentPart::Reasoning { text, signature } => {
                summary.reasoning.push_str(text);
                summary.signatures.extend(signature.as_deref());
            }
            ContentPart::ToolCall {
                call_id,
                name,
                input,
            } => summary.tools.push((call_id.as_str(), name.as_str(), input)),
            ContentPart::Image { media_type, image } => {
                summary.images.push((media_type.as_str(), image));
            }
            // Never part of an answer; the terminal's own check refuses them.
            ContentPart::ToolResult { .. } | ContentPart::Audio { .. } => {}
        }
    }
    summary
}
