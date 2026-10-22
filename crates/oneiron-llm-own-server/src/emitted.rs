//! What a checked stream has already shown its caller (FIX 8617): each
//! part in the order it started, its text as it arrived, a tool call's and
//! an image's whole content once it ended. A terminal message is held to
//! it in order (FIX 9324): adjacent text is one run, and adjacent reasoning
//! one run with its signatures, since backends cut chunks where they like,
//! but no run reaches across a tool call or an image, so where text stands
//! between them is held too; every tool call's identity and input, and
//! every image, stand alone in their places. A terminal that disagrees does
//! not replace what was shown; the shown output is the answer, typed
//! incomplete, or still cancelled when the caller stopped it.

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

/// One part of a message in the shape a terminal is held to: a run of
/// adjacent text, a run of adjacent reasoning with its signatures in order,
/// or one tool call or image in its place.
#[derive(PartialEq)]
enum OrderedReplyPart<'a> {
    Text(String),
    Reasoning {
        text: String,
        signatures: Vec<&'a str>,
    },
    Tool {
        call_id: &'a str,
        name: &'a str,
        input: &'a JsonValue,
    },
    Image {
        media_type: &'a str,
        image: &'a ImageContent,
    },
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

    /// Whether `message` carries what the stream showed, in order, as a
    /// terminal must.
    pub(crate) fn agrees(&self, message: &LlmMessage) -> bool {
        let shown = self.content();
        ordered(shown.iter()) == ordered(message.content.iter())
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

/// `content` as a terminal is held to it: in order, adjacent text and
/// adjacent reasoning each one run, an empty chunk adding nothing to it.
fn ordered<'a>(content: impl Iterator<Item = &'a ContentPart>) -> Vec<OrderedReplyPart<'a>> {
    let mut parts: Vec<OrderedReplyPart<'a>> = Vec::new();
    for part in content {
        match part {
            ContentPart::Text { text } => match parts.last_mut() {
                Some(OrderedReplyPart::Text(run)) => run.push_str(text),
                _ if text.is_empty() => {}
                _ => parts.push(OrderedReplyPart::Text(text.clone())),
            },
            ContentPart::Reasoning { text, signature } => match parts.last_mut() {
                Some(OrderedReplyPart::Reasoning {
                    text: run,
                    signatures,
                }) => {
                    run.push_str(text);
                    signatures.extend(signature.as_deref());
                }
                _ if text.is_empty() && signature.is_none() => {}
                _ => parts.push(OrderedReplyPart::Reasoning {
                    text: text.clone(),
                    signatures: signature.as_deref().into_iter().collect(),
                }),
            },
            ContentPart::ToolCall {
                call_id,
                name,
                input,
            } => parts.push(OrderedReplyPart::Tool {
                call_id: call_id.as_str(),
                name: name.as_str(),
                input,
            }),
            ContentPart::Image { media_type, image } => parts.push(OrderedReplyPart::Image {
                media_type: media_type.as_str(),
                image,
            }),
            // Never part of an answer; the terminal's own check refuses them.
            ContentPart::ToolResult { .. } | ContentPart::Audio { .. } => {}
        }
    }
    parts
}
