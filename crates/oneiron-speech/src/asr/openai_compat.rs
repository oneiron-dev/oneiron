//! The OpenAI-compatible transcription wire (`/v1/audio/transcriptions`).
//! [`OpenAiAsrBackend`] speaks it over the provider's shared
//! `oneiron_llm::openai_compat::OpenAiMediaClient`, whose transport seam and
//! shared field rules are `oneiron_llm`'s. HTTP and authentication stay
//! host-owned: the host's transport sends one request per call, so a run's
//! media gate may wrap this backend.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::media::wav::WavClip;
use oneiron::llm::media::{
    AiOperation, InterruptedMediaCall, MediaBackend, MediaFuture, MediaPart, MediaProgressFuture,
    MediaRequest, MediaResponse, MediaUsage,
};
use oneiron::llm::{BrokerIsolation, DispatchRelease, INFERENCE_CALLS_KEY, InferenceCallReceipt};
use oneiron::{BudgetLease, FatalLlmError, LlmResult, ModelId};
use oneiron_llm::openai_compat::{
    OpenAiImagePart, OpenAiMediaBody, OpenAiMediaClient, OpenAiMediaMethod, OpenAiMediaTransport,
    audio_extension, form_fields, with_params,
};
use serde::Deserialize;
use serde_json::{Value, json};

/// One provider's transcription calls over its shared client.
pub struct OpenAiAsrBackend<T> {
    client: Arc<OpenAiMediaClient<T>>,
}

impl<T> OpenAiAsrBackend<T> {
    #[must_use]
    pub fn new(client: Arc<OpenAiMediaClient<T>>) -> Self {
        Self { client }
    }
}

impl<T: OpenAiMediaTransport> OpenAiAsrBackend<T> {
    async fn transcribe(
        &self,
        request: MediaRequest,
        lease: &BudgetLease,
        release: Option<DispatchRelease<'_>>,
    ) -> LlmResult<MediaResponse> {
        let wire = self.client.wire_model(&request.model)?;
        let PreparedTranscribe {
            fields,
            filename,
            media_type,
        } = prepare_transcribe(&request, &wire)?;
        // The one audio part the builder checked, taken, not copied.
        let Some(MediaPart::Audio { bytes, .. }) = request.parts.into_iter().next() else {
            return Err(FatalLlmError::InvalidRequest.into());
        };
        let measured_ms = WavClip::parse(&bytes).map(|clip| clip.duration_ms());
        let file = OpenAiImagePart {
            name: "file",
            filename,
            media_type,
            bytes,
        };
        let body = OpenAiMediaBody::Multipart {
            fields,
            files: vec![file],
        };
        let reply = self
            .client
            .send_released(
                OpenAiMediaMethod::Post,
                "/v1/audio/transcriptions".into(),
                body,
                lease,
                release,
            )
            .await?;
        let mut reply = reply.json();
        let text = reply
            .get("text")
            .and_then(Value::as_str)
            .ok_or(FatalLlmError::EmptyResponse)?
            .to_owned();
        let raw = reply
            .get_mut("usage")
            .map(Value::take)
            .unwrap_or(Value::Null);
        let count = |key: &str| raw.get(key).and_then(Value::as_u64).unwrap_or(0);
        let (input_tokens, output_tokens) = (count("input_tokens"), count("output_tokens"));
        // A duration-priced model reports seconds; a verbose reply its
        // length.
        let seconds = raw
            .get("seconds")
            .or_else(|| reply.get("duration"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        // A provider that reports neither is charged the length of the WAV
        // it was sent, read from the audio's own header.
        let audio_ms = match (seconds.max(0.0) * 1_000.0).ceil() as u64 {
            0 => measured_ms.unwrap_or(0),
            reported => reported,
        };
        // A worker's inference receipts (FIX 8318) also go where the run
        // reads them, bound to the model this call was admitted for; its
        // usage stays as it came.
        let receipts = transcription_receipts(&raw, &request.model);
        let mut usage = MediaUsage {
            input_tokens,
            output_tokens,
            audio_ms,
            raw_provider: json!({ "usage": raw }),
            ..MediaUsage::default()
        };
        usage.put_inference_calls(&receipts);
        Ok(MediaResponse {
            parts: vec![MediaPart::Text { text }],
            usage,
            model: request.model,
        })
    }
}

/// Serves transcriptions alone: every other call is another wire's, and is
/// refused here with `InvalidRequest` before anything is sent.
impl<T: OpenAiMediaTransport> MediaBackend for OpenAiAsrBackend<T> {
    /// A model this client was not built for, a call its send's own
    /// builders refuse (a voice, a param naming a field the adapter sets,
    /// FIX 8616), or its transport's refusal: all before the call's permit
    /// starts, so none of them is charged.
    fn preflight(&self, request: &MediaRequest) -> LlmResult<()> {
        request.validate_image_mask()?;
        let wire = self.client.wire_model(&request.model)?;
        // A voice is a speech call's alone.
        if request.voice.is_some() || request.operation != AiOperation::Transcribe {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        prepare_transcribe(request, &wire)?;
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
            // A voice is a speech call's alone.
            if request.voice.is_some() || request.operation != AiOperation::Transcribe {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            self.transcribe(request, lease, None).await
        })
    }

    fn run_progress_released<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
        release: Option<DispatchRelease<'a>>,
    ) -> MediaProgressFuture<'a> {
        if request.operation != AiOperation::Transcribe {
            return self.run_progress(request, lease);
        }
        Box::pin(async move {
            if request.voice.is_some() {
                return Err(InterruptedMediaCall::nothing(
                    FatalLlmError::InvalidRequest.into(),
                ));
            }
            self.transcribe(request, lease, release)
                .await
                .map_err(InterruptedMediaCall::nothing)
        })
    }
}

/// A transcription, checked: its form fields and how its one audio file is
/// named. The file's bytes are taken from the call as it is sent.
struct PreparedTranscribe {
    fields: BTreeMap<String, String>,
    filename: String,
    media_type: String,
}

/// Checks a transcription as its send builds it: one audio part with bytes,
/// no references, and the call's params beside its fixed fields.
fn prepare_transcribe(request: &MediaRequest, wire: &str) -> LlmResult<PreparedTranscribe> {
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

/// The inference receipts a transcription's usage carries under
/// [`INFERENCE_CALLS_KEY`] (a local ASR worker's), each bound to `model`,
/// the engine model the call was admitted for. A record that does not read
/// as a receipt is no evidence and is left out.
fn transcription_receipts(usage: &Value, model: &ModelId) -> Vec<InferenceCallReceipt> {
    usage
        .get(INFERENCE_CALLS_KEY)
        .and_then(Value::as_array)
        .map(|records| {
            records
                .iter()
                .filter_map(|record| InferenceCallReceipt::deserialize(record).ok())
                .map(|receipt| InferenceCallReceipt {
                    model: Some(model.clone()),
                    ..receipt
                })
                .collect()
        })
        .unwrap_or_default()
}
