//! The shapes a provider's embedding endpoint speaks (FIX 866). A text
//! batch goes as `input` on every OpenAI-compatible endpoint; a call with
//! an image or audio part goes in its provider's own shape: vLLM's chat
//! form (`messages`), Infinity's `modality`, Jina's object inputs
//! (`input: [{image}]`) or Cohere's `images`. The host picks the shape by
//! the provider its binding names; vLLM's is the default. A call's
//! documents are all built, and so checked whole, before the first is sent.
use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use oneiron::llm::media::{MediaPart, MediaRequest};
use oneiron::{FatalLlmError, LlmResult};
use serde_json::{Value, json};

use super::prepare::{EmbedPlan, embed_content, with_params};

/// The OpenAI-compatible embeddings route: vLLM's, Infinity's (served under
/// its `/v1` prefix) and Jina's.
const OPENAI_EMBEDDINGS_PATH: &str = "/v1/embeddings";

/// Cohere's v2 embed route.
const COHERE_EMBED_PATH: &str = "/v2/embed";

/// The `input_type` a Cohere text goes as when the call names none: a
/// document a later query is matched against, as a stored row's is.
const COHERE_DOCUMENT: &str = "search_document";

/// How an embedding endpoint takes a call's documents (FIX 866).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EmbedShape {
    /// vLLM's multimodal embedding models: each image or audio part as its
    /// own chat-form document (`messages`).
    #[default]
    VllmChat,
    /// Infinity: each part as its own `input`, its kind named by `modality`
    /// (`text`, `image` or `audio`), media as a data URL.
    Infinity,
    /// Jina: every part in one `input` list of objects, `{text}` or
    /// `{image}` as bare base64. Jina takes no audio.
    Jina,
    /// Cohere's v2 embed: texts as `texts`, each image as its own `images`
    /// document, floats asked for by `embedding_types`. Cohere takes no
    /// audio.
    Cohere,
}

/// One request of a call: how many vectors it answers, the route it goes
/// to, and its body.
pub(super) struct EmbedDocument {
    pub(super) count: usize,
    pub(super) path: &'static str,
    pub(super) body: BTreeMap<String, Value>,
}

impl EmbedShape {
    /// Every check this shape makes of `request` before it sends, with no
    /// I/O and no encoding: a part kind its provider does not embed, or a
    /// param that names one of its fixed fields.
    pub(super) fn check(self, request: &MediaRequest, plan: EmbedPlan) -> LlmResult<()> {
        let fixed: &[&str] = match (self, plan) {
            (Self::Cohere, _) => &["texts", "images", "input_type", "embedding_types"],
            (Self::VllmChat, EmbedPlan::Parts) => &["messages"],
            (Self::Infinity, EmbedPlan::Parts) => &["input", "modality"],
            _ => &["input"],
        };
        let audio = request
            .parts
            .iter()
            .any(|part| matches!(part, MediaPart::Audio { .. }));
        if fixed.iter().any(|field| request.params.contains_key(*field))
            || (audio && matches!(self, Self::Jina | Self::Cohere))
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        Ok(())
    }

    /// `request`'s documents as this shape sends them, `wire` the model's
    /// name at its provider.
    pub(super) fn documents(
        self,
        request: &MediaRequest,
        plan: EmbedPlan,
        wire: &str,
    ) -> LlmResult<Vec<EmbedDocument>> {
        self.check(request, plan)?;
        if plan == EmbedPlan::Texts {
            let texts: Vec<&str> = request.texts().collect();
            let (field, kind) = match self {
                Self::Cohere => ("texts", json!(COHERE_DOCUMENT)),
                _ => ("input", Value::Null),
            };
            let document = self.document(request, wire, texts.len(), field, json!(texts), kind)?;
            return Ok(vec![document]);
        }
        if self == Self::Jina {
            let inputs = request
                .parts
                .iter()
                .map(jina_input)
                .collect::<LlmResult<Vec<_>>>()?;
            let count = inputs.len();
            let document =
                self.document(request, wire, count, "input", json!(inputs), Value::Null)?;
            return Ok(vec![document]);
        }
        request
            .parts
            .iter()
            .map(|part| {
                let (field, input, kind) = match self {
                    Self::Infinity => (
                        "input",
                        json!([part_input(part)?]),
                        json!(modality(part)),
                    ),
                    Self::Cohere => match part {
                        MediaPart::Text { text } => {
                            ("texts", json!([text]), json!(COHERE_DOCUMENT))
                        }
                        _ => ("images", json!([part_input(part)?]), json!("image")),
                    },
                    Self::VllmChat | Self::Jina => (
                        "messages",
                        json!([{ "role": "user", "content": [embed_content(part)?] }]),
                        Value::Null,
                    ),
                };
                self.document(request, wire, 1, field, input, kind)
            })
            .collect()
    }

    /// One document: `model` and `field`, the caller's params, then the
    /// shape's own defaults where the caller named none: the float encoding,
    /// and `kind` (Infinity's `modality`, Cohere's `input_type`).
    fn document(
        self,
        request: &MediaRequest,
        wire: &str,
        count: usize,
        field: &str,
        input: Value,
        kind: Value,
    ) -> LlmResult<EmbedDocument> {
        let mut body = with_params([("model", json!(wire)), (field, input)], &request.params)?;
        let path = match self {
            Self::Cohere => {
                body.entry("embedding_types".into())
                    .or_insert_with(|| json!(["float"]));
                body.entry("input_type".into()).or_insert(kind);
                COHERE_EMBED_PATH
            }
            Self::Infinity if !kind.is_null() => {
                body.entry("modality".into()).or_insert(kind);
                OPENAI_EMBEDDINGS_PATH
            }
            Self::VllmChat | Self::Infinity | Self::Jina => OPENAI_EMBEDDINGS_PATH,
        };
        if self != Self::Cohere {
            body.entry("encoding_format".into())
                .or_insert_with(|| json!("float"));
        }
        Ok(EmbedDocument { count, path, body })
    }

    /// The `count` vectors `reply` holds, in request order.
    pub(super) fn vectors(self, reply: &Value, count: usize) -> Option<Vec<Vec<f32>>> {
        if self != Self::Cohere {
            return super::indexed_vectors(reply, count);
        }
        let rows = reply.get("embeddings")?.get("float")?.as_array()?;
        if rows.len() != count {
            return None;
        }
        rows.iter()
            .map(|row| {
                let vector = row
                    .as_array()?
                    .iter()
                    .map(|value| value.as_f64().map(|value| value as f32))
                    .collect::<Option<Vec<f32>>>()?;
                (!vector.is_empty()).then_some(vector)
            })
            .collect()
    }

    /// The usage `reply` reports, taken out of it: OpenAI's `usage`, or
    /// Cohere's `meta.billed_units`.
    pub(super) fn take_usage(self, reply: &mut Value) -> Value {
        let usage = match self {
            Self::Cohere => reply
                .get_mut("meta")
                .and_then(|meta| meta.get_mut("billed_units")),
            Self::VllmChat | Self::Infinity | Self::Jina => reply.get_mut("usage"),
        };
        usage.map(Value::take).unwrap_or(Value::Null)
    }

    /// The input tokens `usage` counts.
    pub(super) fn tokens(self, usage: &Value) -> u64 {
        let counted = match self {
            Self::Cohere => usage.get("input_tokens"),
            Self::VllmChat | Self::Infinity | Self::Jina => usage
                .get("prompt_tokens")
                .or_else(|| usage.get("total_tokens")),
        };
        counted.and_then(Value::as_u64).unwrap_or(0)
    }
}

/// A part as one bare input: text as itself, media as a data URL.
fn part_input(part: &MediaPart) -> LlmResult<Value> {
    Ok(match part {
        MediaPart::Text { text } => json!(text),
        MediaPart::Image { media_type, bytes } | MediaPart::Audio { media_type, bytes }
            if !bytes.is_empty() =>
        {
            json!(format!("data:{media_type};base64,{}", STANDARD.encode(bytes)))
        }
        _ => return Err(FatalLlmError::InvalidRequest.into()),
    })
}

/// Infinity's name for a part's kind.
fn modality(part: &MediaPart) -> &'static str {
    match part {
        MediaPart::Image { .. } => "image",
        MediaPart::Audio { .. } => "audio",
        _ => "text",
    }
}

/// A part as one of Jina's object inputs.
fn jina_input(part: &MediaPart) -> LlmResult<Value> {
    Ok(match part {
        MediaPart::Text { text } => json!({ "text": text }),
        MediaPart::Image { bytes, .. } if !bytes.is_empty() => {
            json!({ "image": STANDARD.encode(bytes) })
        }
        _ => return Err(FatalLlmError::InvalidRequest.into()),
    })
}
