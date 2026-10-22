//! The OpenAI-compatible media calls' pure builders (FIX 8614, FIX 8616):
//! every check a call's send makes on its own request, with no I/O, shared
//! by the backend's preflight and its send. A call one of them refuses is
//! refused before its permit starts, so it is never charged, and the send
//! cannot check anything the preflight did not. A multi-send call (an
//! embedding's documents) is checked whole before its first send.
//!
//! Nothing here copies or encodes a reference, an audio clip or an image
//! part: the send does that once, as it builds what goes out.
use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest};
use oneiron::{FatalLlmError, LlmResult, ModelId};
use serde_json::{Value, json};

use crate::image::{fields, form_fields, reference_extension};

/// The reference images a video job carries: its one `input_reference`. A
/// call with more is not this wire's; a host's ladder passes it to an offer
/// that takes them all, unsent, and this wire never cuts it to its first.
pub(super) const VIDEO_REFERENCE_SLOTS: usize = 1;

/// An image call, checked: the model it answers as and its fields, the
/// provider's model name among them.
pub(super) struct PreparedImage {
    pub(super) model: ModelId,
    pub(super) fields: BTreeMap<String, Value>,
}

/// A speech call, checked: its JSON body, the media type its format names,
/// and the characters it is charged for.
pub(super) struct PreparedSpeech {
    pub(super) body: Value,
    pub(super) format: &'static str,
    pub(super) characters: u64,
}

/// A transcription, checked: its form fields and how its one audio file is
/// named. The file's bytes are taken from the call as it is sent.
pub(super) struct PreparedTranscribe {
    pub(super) fields: BTreeMap<String, String>,
    pub(super) filename: String,
    pub(super) media_type: String,
}

/// How an embedding call's documents go: its texts as one batch, or each
/// part as its own chat-form document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EmbedPlan {
    Texts,
    Parts,
}

/// A video job, checked: its fields. Its start frame, when it has one, is
/// taken from the call as it is sent.
pub(super) struct PreparedVideo {
    pub(super) fields: BTreeMap<String, Value>,
}

/// Checks an image call as its send builds it: every reference (however
/// many, FIX 8614) an image of a type the wire names with bytes, and the
/// fields its intent makes, with the provider's model name `wire`.
pub(super) fn prepare_image(request: &MediaRequest, wire: &str) -> LlmResult<PreparedImage> {
    if request.operation != AiOperation::Image {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    references_are_images(request)?;
    let (model, mut fields) = fields(&request.image_intent()?)?;
    fields.insert("model".into(), json!(wire));
    Ok(PreparedImage { model, fields })
}

/// Checks a speech call as its send builds it: text only, a script, the
/// call's params beside its fixed fields, one voice (a typed voice and a
/// `voice` param together are refused) and a format the wire names.
pub(super) fn prepare_speech(request: &MediaRequest, wire: &str) -> LlmResult<PreparedSpeech> {
    let input = request.text();
    if request.operation != AiOperation::Speech || input.trim().is_empty() || !only_text(request) {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let characters = u64::try_from(input.chars().count()).unwrap_or(u64::MAX);
    let mut body = with_params(
        [("model", json!(wire)), ("input", json!(input))],
        &request.params,
    )?;
    match &request.voice {
        // A typed voice is the call's one voice: a `voice` param beside
        // it is refused, so a raw name never stands in for a banked
        // identity.
        Some(voice) => {
            let id = voice.wire_id().ok_or(FatalLlmError::InvalidRequest)?;
            if body.insert("voice".into(), json!(id)).is_some() {
                return Err(FatalLlmError::InvalidRequest.into());
            }
        }
        None => {
            body.entry("voice".into()).or_insert_with(|| json!("alloy"));
        }
    }
    let format = body
        .entry("response_format".into())
        .or_insert_with(|| json!("mp3"))
        .as_str()
        .and_then(audio_type)
        .ok_or(FatalLlmError::InvalidRequest)?;
    Ok(PreparedSpeech {
        body: Value::Object(body.into_iter().collect()),
        format,
        characters,
    })
}

/// Checks a transcription as its send builds it: one audio part with bytes,
/// no references, and the call's params beside its fixed fields.
pub(super) fn prepare_transcribe(
    request: &MediaRequest,
    wire: &str,
) -> LlmResult<PreparedTranscribe> {
    let [MediaPart::Audio { media_type, bytes }] = request.parts.as_slice() else {
        return Err(FatalLlmError::InvalidRequest.into());
    };
    if request.operation != AiOperation::Transcribe
        || bytes.is_empty()
        || !request.references.is_empty()
    {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let mut body = with_params([("model", json!(wire))], &request.params)?;
    body.entry("response_format".into())
        .or_insert_with(|| json!("json"));
    Ok(PreparedTranscribe {
        fields: form_fields(&body),
        filename: format!("audio.{}", audio_extension(media_type)),
        media_type: media_type.clone(),
    })
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

/// Checks a video job as its submit builds it: a prompt, at most its one
/// start frame of a type the wire names (a call with more is refused here,
/// before it is sent, never cut), and the call's params beside its fixed
/// fields.
pub(super) fn prepare_video(request: &MediaRequest, wire: &str) -> LlmResult<PreparedVideo> {
    let prompt = request.text();
    if request.operation != AiOperation::Video || prompt.trim().is_empty() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    references_are_images(request)?;
    if request.references.len() > VIDEO_REFERENCE_SLOTS {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let fields = with_params(
        [("model", json!(wire)), ("prompt", json!(prompt))],
        &request.params,
    )?;
    Ok(PreparedVideo { fields })
}

/// Every reference is an image of a type the wire names, with bytes, read
/// in place: no copy.
fn references_are_images(request: &MediaRequest) -> LlmResult<()> {
    let sendable = |part: &MediaPart| {
        matches!(part, MediaPart::Image { media_type, bytes }
            if !bytes.is_empty() && reference_extension(media_type).is_some())
    };
    if request.references.iter().all(sendable) {
        Ok(())
    } else {
        Err(FatalLlmError::InvalidRequest.into())
    }
}

/// The call's fixed fields, then each param of the caller's. A param that
/// names a fixed field is refused: the adapter sets those.
pub(super) fn with_params<const N: usize>(
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

pub(super) fn only_text(request: &MediaRequest) -> bool {
    request.references.is_empty()
        && request
            .parts
            .iter()
            .all(|part| matches!(part, MediaPart::Text { .. }))
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

/// The media type a speech `response_format` names.
fn audio_type(format: &str) -> Option<&'static str> {
    Some(match format {
        "mp3" => "audio/mpeg",
        "opus" => "audio/opus",
        "aac" => "audio/aac",
        "flac" => "audio/flac",
        "wav" => "audio/wav",
        "pcm" => "audio/pcm",
        _ => return None,
    })
}

/// The file extension a transcription upload is named with.
fn audio_extension(media_type: &str) -> &'static str {
    match media_type {
        "audio/mpeg" | "audio/mp3" => "mp3",
        "audio/mp4" | "audio/m4a" | "audio/x-m4a" => "m4a",
        "audio/webm" => "webm",
        "audio/ogg" | "audio/opus" => "ogg",
        "audio/flac" => "flac",
        _ => "wav",
    }
}
