//! Hosted speech wires that are not OpenAI-compatible: ARCH-0061 §5's hosted
//! realtime tier, Cartesia Sonic (`POST /tts/bytes`), and its break-glass
//! fallback, ElevenLabs Flash (`POST /v1/text-to-speech/{voice}`). Each is a
//! `[models.media.speech]` rung like any other: one request per call, sent
//! through the run's media gate on its own permit and settled on the
//! characters it spoke. Each answers raw 24 kHz PCM16, handed back as a WAV
//! so the caller reads its rate from the header. Each provider also clones:
//! [`HostedCloner`] makes the provider voice a banked identity renders as,
//! asks whether one its vendor holds for verification is verified, and
//! deletes it, each call on its own paid permit.
use std::collections::BTreeMap;

use oneiron::llm::media::wav::{WavClip, pcm16_wav};
use oneiron::llm::media::{
    AiOperation, MediaBackend, MediaFuture, MediaPart, MediaRequest, MediaResponse, MediaUsage,
    MediaVoice,
};
use oneiron::llm::run_admission::{CallOutcome, PaidConnector, RunAdmission};
use oneiron::voice_identity::ref_bank::VoiceRegisterClip;
use oneiron::{BudgetLease, FatalLlmError, LlmResult, ModelId, ModelLocality};
use reqwest::multipart::{Form, Part};
use serde_json::{Value as JsonValue, json};

use super::host_budgets::ModelHostBudgets;
use super::http::{MediaSend, ProviderHttp, holding_replies};
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

/// A provider voice a clone call made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VendorVoice {
    /// The provider's id for it, safe in a URL path.
    pub id: String,
    /// The provider holds it until the voice is verified there (ElevenLabs'
    /// `requires_verification`, FIX 1567): no finished clone yet.
    pub awaiting_verification: bool,
}

/// A hosted provider's clone wire: it makes a provider voice from a banked
/// identity's refs, and deletes one. The provider's id is a disposable
/// locator, never the identity; the bank records it only while the refs it
/// was made from, and the render consent that let them leave, stay current
/// (ARCH-0061 §5).
pub struct HostedCloner {
    pub(super) http: ProviderHttp,
    pub(super) wire: HostedWire,
    pub(super) locality: ModelLocality,
    /// What each clone call is admitted as on its caller's run (FIX 3009).
    pub(super) connector: PaidConnector,
    /// The vault's budgets its replies hold their bytes on (FIX 9321).
    pub(super) budgets: ModelHostBudgets,
}

impl HostedCloner {
    /// Where the provider runs: how far the voice's render consent must
    /// reach for its refs to go there.
    #[must_use]
    pub fn locality(&self) -> ModelLocality {
        self.locality
    }

    /// Whether a clone must name the language its clip is spoken in.
    #[must_use]
    pub fn needs_language(&self) -> bool {
        self.wire == HostedWire::Cartesia
    }

    /// Makes a provider voice named `name` from `clips`, on `run`. Cartesia
    /// takes one clip, made of every clip that joins into one (FIX 1567),
    /// and must be told its `language`; ElevenLabs takes them all, and may
    /// hold the voice until it is verified there.
    pub async fn create(
        &self,
        run: &RunAdmission,
        name: &str,
        clips: &[VoiceRegisterClip],
        language: Option<&str>,
    ) -> LlmResult<VendorVoice> {
        let first = clips.first().ok_or(FatalLlmError::InvalidRequest)?;
        let (path, form, id_field) = match self.wire {
            HostedWire::Cartesia => {
                let language = language
                    .filter(|language| !language.trim().is_empty())
                    .ok_or(FatalLlmError::InvalidRequest)?;
                let clip = match joined_wav(clips) {
                    Some(joined) => Part::bytes(joined)
                        .file_name("clip-0.wav")
                        .mime_str("audio/wav")
                        .map_err(|_| FatalLlmError::InvalidRequest)?,
                    None => clip_part(0, first)?,
                };
                let form = Form::new()
                    .text("name", name.to_owned())
                    .text("language", language.to_owned())
                    .part("clip", clip);
                ("/voices/clone", form, "id")
            }
            HostedWire::ElevenLabs => {
                let mut form = Form::new().text("name", name.to_owned());
                for (index, clip) in clips.iter().enumerate() {
                    form = form.part("files", clip_part(index, clip)?);
                }
                ("/v1/voices/add", form, "voice_id")
            }
        };
        let http = &self.http;
        let body = self
            .paid(run, async move {
                let reply = http
                    .send_media(path, MediaSend::Multipart(form))
                    .await
                    .map_err(transport)?;
                let body = serde_json::from_slice(&reply.body).unwrap_or(JsonValue::Null);
                if !(200..300).contains(&reply.status) {
                    return Err(oneiron_llm_openai::classify_openai_status(
                        reply.status,
                        &reply.headers,
                        &body,
                    ));
                }
                Ok(body)
            })
            .await?;
        // The id is later interpolated into URL paths.
        let id = body
            .get(id_field)
            .and_then(JsonValue::as_str)
            .filter(|id| url_safe(id))
            .map(str::to_owned)
            .ok_or(FatalLlmError::EmptyResponse)?;
        Ok(VendorVoice {
            id,
            awaiting_verification: self.wire == HostedWire::ElevenLabs
                && body.get("requires_verification") == Some(&JsonValue::Bool(true)),
        })
    }

    /// Whether the provider voice `vendor_voice_id`, held for verification,
    /// is verified there now, on `run` (FIX 1567). ElevenLabs is asked for
    /// the voice's `voice_verification`; Cartesia holds none, so says yes
    /// without a call.
    pub async fn verified(&self, run: &RunAdmission, vendor_voice_id: &str) -> LlmResult<bool> {
        if self.wire == HostedWire::Cartesia {
            return Ok(true);
        }
        if !url_safe(vendor_voice_id) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let path = format!("/v1/voices/{vendor_voice_id}");
        let http = &self.http;
        let body = self
            .paid(run, async move {
                let reply = http
                    .send_media(&path, MediaSend::Get)
                    .await
                    .map_err(transport)?;
                let body = serde_json::from_slice(&reply.body).unwrap_or(JsonValue::Null);
                if !(200..300).contains(&reply.status) {
                    return Err(oneiron_llm_openai::classify_openai_status(
                        reply.status,
                        &reply.headers,
                        &body,
                    ));
                }
                Ok(body)
            })
            .await?;
        let verification = &body["voice_verification"];
        Ok(verification["is_verified"] == JsonValue::Bool(true)
            || verification["requires_verification"] == JsonValue::Bool(false))
    }

    /// Deletes the provider voice `vendor_voice_id`, on `run`; one already
    /// gone counts as deleted.
    pub async fn delete(&self, run: &RunAdmission, vendor_voice_id: &str) -> LlmResult<()> {
        if !url_safe(vendor_voice_id) {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let path = match self.wire {
            HostedWire::Cartesia => format!("/voices/{vendor_voice_id}"),
            HostedWire::ElevenLabs => format!("/v1/voices/{vendor_voice_id}"),
        };
        let http = &self.http;
        self.paid(run, async move {
            let reply = http
                .send_media(&path, MediaSend::Delete)
                .await
                .map_err(transport)?;
            if (200..300).contains(&reply.status) || reply.status == 404 {
                return Ok(());
            }
            let body = serde_json::from_slice(&reply.body).unwrap_or(JsonValue::Null);
            Err(oneiron_llm_openai::classify_openai_status(
                reply.status,
                &reply.headers,
                &body,
            ))
        })
        .await
    }

    /// One clone call, `send`, on `run` (FIX 3009): admitted as this
    /// provider's clone connector before it goes out, its permit started
    /// just before the send and settled after, one unit an answered call. A
    /// refused call sends nothing.
    async fn paid<T>(
        &self,
        run: &RunAdmission,
        send: impl std::future::Future<Output = LlmResult<T>>,
    ) -> LlmResult<T> {
        let permit = run.admit_paid(&self.connector, 1)?;
        run.dispatch_paid(permit.lease(), &self.connector)?;
        // Its replies hold their bytes on the vault's line until it ends.
        let sent = holding_replies(&self.budgets, send).await;
        // The request went out: a failed one keeps its reservation as spend.
        let outcome = match &sent {
            Ok(_) => CallOutcome::UsedCounted(1),
            Err(_) => CallOutcome::Failed,
        };
        if let Err(denied) = permit.settle(outcome) {
            tracing::error!(%denied, "a voice clone call's settlement was refused");
        }
        sent
    }
}

/// A provider voice id: no separators, whitespace or credentials.
fn url_safe(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Every clip as one PCM16 WAV, their samples joined in order: Cartesia
/// clones from one clip (FIX 1567). `None` unless there are several and
/// each is a PCM16 WAV of whole frames at one rate and channel count; the
/// first clip goes alone then, as before.
fn joined_wav(clips: &[VoiceRegisterClip]) -> Option<Vec<u8>> {
    let wavs = clips
        .iter()
        .map(|clip| WavClip::parse(&clip.audio).filter(WavClip::is_pcm16))
        .collect::<Option<Vec<_>>>()?;
    let (first, rest) = wavs.split_first()?;
    let frame = usize::from(first.channels) * 2;
    let joins = |wav: &WavClip<'_>| {
        wav.sample_rate == first.sample_rate
            && wav.channels == first.channels
            && frame > 0
            && wav.data.len().is_multiple_of(frame)
    };
    if rest.is_empty() || !wavs.iter().all(joins) {
        return None;
    }
    let samples: Vec<u8> = wavs.iter().flat_map(|wav| wav.data).copied().collect();
    pcm16_wav(first.sample_rate, first.channels, &samples)
}

/// One clip as a form file, named by its place rather than its register.
fn clip_part(index: usize, clip: &VoiceRegisterClip) -> LlmResult<Part> {
    let extension: String = match clip.media_type.as_str() {
        "audio/mpeg" => "mp3".to_owned(),
        other => other
            .trim_start_matches("audio/")
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect(),
    };
    Part::bytes(clip.audio.clone())
        .file_name(format!("clip-{index}.{extension}"))
        .mime_str(&clip.media_type)
        .map_err(|_| FatalLlmError::InvalidRequest.into())
}
