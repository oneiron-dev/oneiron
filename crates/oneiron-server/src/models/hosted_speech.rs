//! Hosted speech wires that are not OpenAI-compatible: ARCH-0061 §5's hosted
//! realtime tier, Cartesia Sonic (`POST /tts/bytes`), and its break-glass
//! fallback, ElevenLabs Flash (`POST /v1/text-to-speech/{voice}`). Each is a
//! `[models.media.speech]` rung like any other: one request per call, sent
//! through the run's media gate on its own permit and settled on the
//! characters it spoke. Each answers raw 24 kHz PCM16, handed back as a WAV
//! so the caller reads its rate from the header.
use std::collections::BTreeMap;

use oneiron::llm::media::wav::pcm16_wav;
use oneiron::llm::media::{
    AiOperation, MediaBackend, MediaFuture, MediaPart, MediaRequest, MediaResponse, MediaUsage,
    MediaVoice,
};
use oneiron::{BudgetLease, FatalLlmError, LlmResult, ModelId};
use serde_json::{Value as JsonValue, json};

use super::http::{MediaSend, ProviderHttp};
use super::rerank::transport;

/// The rate both wires are asked to speak at.
const PCM_RATE: u32 = 24_000;
/// The API version every Cartesia call names.
pub(super) const CARTESIA_VERSION: &str = "2026-08-14";

/// Which hosted wire a provider speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HostedWire {
    Cartesia,
    ElevenLabs,
}

/// One hosted speech provider's media client, serving the models the speech
/// seat names on it.
pub(super) struct HostedSpeech {
    pub(super) http: ProviderHttp,
    pub(super) wire: HostedWire,
    /// Engine model id -> the provider's model id.
    pub(super) models: BTreeMap<ModelId, String>,
}

impl HostedSpeech {
    async fn speak(&self, mut request: MediaRequest) -> LlmResult<MediaResponse> {
        let wire_model = self
            .models
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
        let (path, mut body) = match self.wire {
            HostedWire::Cartesia => (
                "/tts/bytes".to_owned(),
                json!({
                    "model_id": wire_model,
                    "transcript": text,
                    "voice": {"mode": "id", "id": voice},
                    "output_format": {
                        "container": "raw",
                        "encoding": "pcm_s16le",
                        "sample_rate": PCM_RATE,
                    },
                }),
            ),
            HostedWire::ElevenLabs => (
                format!("/v1/text-to-speech/{voice}?output_format=pcm_{PCM_RATE}"),
                json!({"model_id": wire_model, "text": text}),
            ),
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
        let reply = self
            .http
            .send_media(&path, MediaSend::Json(body))
            .await
            .map_err(transport)?;
        if !(200..300).contains(&reply.status) {
            let body = serde_json::from_slice(&reply.body).unwrap_or(JsonValue::Null);
            return Err(oneiron_llm_openai::classify_openai_status(
                reply.status,
                &reply.headers,
                &body,
            ));
        }
        let whole = reply.body.len() - reply.body.len() % 2;
        if whole == 0 {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        let wav =
            pcm16_wav(PCM_RATE, 1, &reply.body[..whole]).ok_or(FatalLlmError::EmptyResponse)?;
        Ok(MediaResponse {
            parts: vec![MediaPart::Audio {
                media_type: "audio/wav".into(),
                bytes: wav,
            }],
            usage: MediaUsage {
                characters: u64::try_from(text.chars().count()).unwrap_or(u64::MAX),
                ..MediaUsage::default()
            },
            model: request.model,
        })
    }
}

impl MediaBackend for HostedSpeech {
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(self.speak(request))
    }
}
