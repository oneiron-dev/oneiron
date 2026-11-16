//! The hosted realtime speech tier of ARCH-0061 §5: two hosted wires that
//! are not OpenAI-compatible, Cartesia Sonic ([`super::cartesia`]) and its
//! break-glass fallback, ElevenLabs Flash ([`super::elevenlabs`]). Each call
//! is one request and answers raw 24 kHz PCM16, handed back as a WAV so the
//! caller reads its rate from the header. This module builds the request and
//! reads the reply; the host sends it on the run's media gate, on its own
//! permit, and settles it on the characters it spoke.
use std::collections::BTreeMap;

use oneiron::llm::media::wav::pcm16_wav;
use oneiron::llm::media::{
    AiOperation, MediaPart, MediaRequest, MediaResponse, MediaUsage, MediaVoice,
};
use oneiron::{FatalLlmError, LlmResult, ModelId};
use serde_json::Value as JsonValue;

use super::{cartesia, elevenlabs};

/// The rate both wires are asked to speak at.
pub const PCM_RATE: u32 = 24_000;

/// Which hosted wire a provider speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedWire {
    Cartesia,
    ElevenLabs,
}

/// The existing hosted speech request, shared by direct and broker
/// transports: the text spoken, the path and the JSON body.
pub fn build(
    wire: HostedWire,
    models: &BTreeMap<ModelId, String>,
    request: &mut MediaRequest,
) -> LlmResult<(String, String, JsonValue)> {
    let wire_model = models
        .get(&request.model)
        .ok_or(FatalLlmError::InvalidRequest)?
        .clone();
    let text = request.text();
    if request.operation != AiOperation::Speech
        || text.trim().is_empty()
        || !request.references.is_empty()
        || !request
            .parts
            .iter()
            .all(|part| matches!(part, MediaPart::Text { .. }))
    {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    // A typed voice, or a raw provider voice id as the `voice` param;
    // never both, and these wires speak in no default voice.
    let raw = request.params.remove("voice");
    let voice = match (request.voice.as_ref().map(MediaVoice::wire_id), raw) {
        (Some(Some(id)), None) => id.to_owned(),
        (None, Some(JsonValue::String(id))) => id,
        _ => return Err(FatalLlmError::InvalidRequest.into()),
    };
    // The id may be interpolated into a URL path: no separators,
    // whitespace or credentials.
    if voice.is_empty()
        || !voice
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    let (path, mut body) = match wire {
        HostedWire::Cartesia => cartesia::speech_request(wire_model, &text, &voice),
        HostedWire::ElevenLabs => elevenlabs::speech_request(wire_model, &text, &voice),
    };
    // The caller's other params ride beside the fixed fields; one that
    // names a fixed field is refused.
    let fields = body.as_object_mut().ok_or(FatalLlmError::InvalidRequest)?;
    for (key, value) in std::mem::take(&mut request.params) {
        if key.is_empty() || fields.contains_key(&key) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        fields.insert(key, value);
    }
    Ok((text, path, body))
}

/// The existing hosted speech response, parsed while its sender holds the reply.
pub fn parse(
    status: u16,
    headers: &BTreeMap<String, String>,
    body: &[u8],
    model: ModelId,
    text: &str,
) -> LlmResult<MediaResponse> {
    if !(200..300).contains(&status) {
        let body = serde_json::from_slice(body).unwrap_or(JsonValue::Null);
        return Err(oneiron_llm::openai_compat::classify_openai_status(
            status, headers, &body,
        ));
    }
    let whole = body.len() - body.len() % 2;
    if whole == 0 {
        return Err(FatalLlmError::EmptyResponse.into());
    }
    let wav = pcm16_wav(PCM_RATE, 1, &body[..whole]).ok_or(FatalLlmError::EmptyResponse)?;
    Ok(MediaResponse {
        parts: vec![MediaPart::Audio {
            media_type: "audio/wav".into(),
            bytes: wav,
        }],
        usage: MediaUsage {
            characters: u64::try_from(text.chars().count()).unwrap_or(u64::MAX),
            ..MediaUsage::default()
        },
        model,
    })
}
