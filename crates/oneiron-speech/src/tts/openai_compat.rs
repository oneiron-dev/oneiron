//! The OpenAI-compatible speech wire (`/v1/audio/speech`). [`OpenAiTtsBackend`]
//! speaks it over the provider's shared
//! `oneiron_llm::openai_compat::OpenAiMediaClient`, whose transport seam and
//! shared field rules are `oneiron_llm`'s. HTTP and authentication stay
//! host-owned: the host's transport sends one request per call, so a run's
//! media gate may wrap this backend.
use std::sync::Arc;

use oneiron::llm::media::{
    AiOperation, InterruptedMediaCall, MediaBackend, MediaFuture, MediaPart, MediaProgressFuture,
    MediaRequest, MediaResponse, MediaUsage,
};
use oneiron::llm::{BrokerIsolation, DispatchRelease};
use oneiron::{BudgetLease, FatalLlmError, LlmResult};
use oneiron_llm::openai_compat::{
    OpenAiMediaBody, OpenAiMediaClient, OpenAiMediaMethod, OpenAiMediaTransport, only_text,
    with_params,
};
use serde_json::{Value, json};

/// One provider's speech calls over its shared client.
pub struct OpenAiTtsBackend<T> {
    client: Arc<OpenAiMediaClient<T>>,
}

impl<T> OpenAiTtsBackend<T> {
    #[must_use]
    pub fn new(client: Arc<OpenAiMediaClient<T>>) -> Self {
        Self { client }
    }
}

impl<T: OpenAiMediaTransport> OpenAiTtsBackend<T> {
    async fn speech(
        &self,
        request: MediaRequest,
        lease: &BudgetLease,
        release: Option<DispatchRelease<'_>>,
    ) -> LlmResult<MediaResponse> {
        let wire = self.client.wire_model(&request.model)?;
        let PreparedSpeech {
            body,
            format,
            characters,
        } = prepare_speech(&request, &wire)?;
        let body = OpenAiMediaBody::Json(body);
        let reply = self
            .client
            .send_released(
                OpenAiMediaMethod::Post,
                "/v1/audio/speech".into(),
                body,
                lease,
                release,
            )
            .await?;
        if reply.body.is_empty() {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        let media_type = reply
            .content_type()
            .filter(|kind| kind.starts_with("audio/"))
            .unwrap_or(format)
            .to_owned();
        Ok(MediaResponse {
            parts: vec![MediaPart::Audio {
                media_type,
                bytes: reply.body,
            }],
            usage: MediaUsage {
                characters,
                ..MediaUsage::default()
            },
            model: request.model,
        })
    }
}

/// Serves speech calls alone: every other call is another wire's, and is
/// refused here with `InvalidRequest` before anything is sent.
impl<T: OpenAiMediaTransport> MediaBackend for OpenAiTtsBackend<T> {
    /// A model this client was not built for, a call its send's own
    /// builders refuse (conflicting speech params, a param naming a field
    /// the adapter sets, FIX 8616), or its transport's refusal: all before
    /// the call's permit starts, so none of them is charged.
    fn preflight(&self, request: &MediaRequest) -> LlmResult<()> {
        request.validate_image_mask()?;
        let wire = self.client.wire_model(&request.model)?;
        if request.operation != AiOperation::Speech {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        prepare_speech(request, &wire)?;
        self.client.transport().preflight()
    }

    fn broker_isolation(&self) -> Option<BrokerIsolation> {
        self.client.transport().broker_isolation()
    }

    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async move {
            request.validate_image_mask()?;
            if request.operation != AiOperation::Speech {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            self.speech(request, lease, None).await
        })
    }

    fn run_progress_released<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
        release: Option<DispatchRelease<'a>>,
    ) -> MediaProgressFuture<'a> {
        if request.operation != AiOperation::Speech {
            return self.run_progress(request, lease);
        }
        Box::pin(async move {
            self.speech(request, lease, release)
                .await
                .map_err(InterruptedMediaCall::nothing)
        })
    }
}

/// A speech call, checked: its JSON body, the media type its format names,
/// and the characters it is charged for.
struct PreparedSpeech {
    body: Value,
    format: &'static str,
    characters: u64,
}

/// Checks a speech call as its send builds it: text only, a script, the
/// call's params beside its fixed fields, one voice (a typed voice and a
/// `voice` param together are refused) and a format the wire names.
fn prepare_speech(request: &MediaRequest, wire: &str) -> LlmResult<PreparedSpeech> {
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
