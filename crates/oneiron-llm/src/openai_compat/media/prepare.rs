//! The OpenAI-compatible media calls' pure builders (FIX 8614, FIX 8616):
//! every check a call's send makes on its own request, with no I/O, shared
//! by the backend's preflight and its send. A call one of them refuses is
//! refused before its permit starts, so it is never charged, and the send
//! cannot check anything the preflight did not. A multi-send call (an
//! embedding's documents) is checked whole before its first send.
//!
//! The embedding call's builder is here; the field rules every family's
//! builders share (the caller's params beside the fixed fields, text-only
//! calls, form fields, audio file names) are here too, so each rule has one
//! copy. The image, video, speech and transcription builders sit with their
//! families' backends.
//!
//! Nothing here copies or encodes a reference, an audio clip or an image
//! part: the send does that once, as it builds what goes out.
use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest};
use oneiron::{FatalLlmError, LlmResult};
use serde_json::{Value, json};

/// How an embedding call's documents go: its texts as one batch, or each
/// part as its own chat-form document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EmbedPlan {
    Texts,
    Parts,
}

/// Checks an embedding call whole, before its first send: parts and no
/// references, each part one a document can carry, and the call's params
/// beside the fixed fields every document goes with.
pub(super) fn prepare_embed(request: &MediaRequest, wire: &str) -> LlmResult<EmbedPlan> {
    if request.operation != AiOperation::Embed
        || request.parts.is_empty()
        || !request.references.is_empty()
    {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let plan = if only_text(request) {
        EmbedPlan::Texts
    } else {
        for part in &request.parts {
            embeddable(part)?;
        }
        EmbedPlan::Parts
    };
    let field = match plan {
        EmbedPlan::Texts => "input",
        EmbedPlan::Parts => "messages",
    };
    with_params(
        [("model", json!(wire)), (field, Value::Null)],
        &request.params,
    )?;
    Ok(plan)
}

/// The call's fixed fields, then each param of the caller's. A param that
/// names a fixed field is refused: the adapter sets those.
pub fn with_params<const N: usize>(
    fixed: [(&str, Value); N],
    params: &BTreeMap<String, Value>,
) -> LlmResult<BTreeMap<String, Value>> {
    let mut body: BTreeMap<String, Value> = fixed
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
    for (key, value) in params {
        if body.contains_key(key) || key.is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        body.insert(key.clone(), value.clone());
    }
    Ok(body)
}

/// Whether `request` is text alone: no reference and no part but text.
#[must_use]
pub fn only_text(request: &MediaRequest) -> bool {
    request.references.is_empty()
        && request
            .parts
            .iter()
            .all(|part| matches!(part, MediaPart::Text { .. }))
}

/// A call's fields as multipart form fields: a string as itself, any other
/// value as its JSON text.
#[must_use]
pub fn form_fields(fields: &BTreeMap<String, Value>) -> BTreeMap<String, String> {
    fields
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                value
                    .as_str()
                    .map_or_else(|| value.to_string(), str::to_owned),
            )
        })
        .collect()
}

/// Whether a chat-form embedding document can carry `part`: text, or an
/// image or audio clip with bytes.
fn embeddable(part: &MediaPart) -> LlmResult<()> {
    match part {
        MediaPart::Text { .. } => Ok(()),
        MediaPart::Image { bytes, .. } | MediaPart::Audio { bytes, .. } if !bytes.is_empty() => {
            Ok(())
        }
        _ => Err(FatalLlmError::InvalidRequest.into()),
    }
}

/// One embedding document's part as a chat content part: an image as a data
/// URL, audio as `input_audio`.
pub(super) fn embed_content(part: &MediaPart) -> LlmResult<Value> {
    embeddable(part)?;
    Ok(match part {
        MediaPart::Image { media_type, bytes } => json!({
            "type": "image_url",
            "image_url": { "url": format!("data:{media_type};base64,{}", STANDARD.encode(bytes)) },
        }),
        MediaPart::Audio { media_type, bytes } => json!({
            "type": "input_audio",
            "input_audio": {
                "data": STANDARD.encode(bytes),
                "format": audio_extension(media_type),
            },
        }),
        MediaPart::Text { text } => json!({ "type": "text", "text": text }),
        _ => return Err(FatalLlmError::InvalidRequest.into()),
    })
}

/// The file extension an audio clip of `media_type` is sent under: a
/// transcription's upload, an embedding's `input_audio` format.
#[must_use]
pub fn audio_extension(media_type: &str) -> &'static str {
    match media_type {
        "audio/mpeg" | "audio/mp3" => "mp3",
        "audio/mp4" | "audio/m4a" | "audio/x-m4a" => "m4a",
        "audio/webm" => "webm",
        "audio/ogg" | "audio/opus" => "ogg",
        "audio/flac" => "flac",
        _ => "wav",
    }
}
