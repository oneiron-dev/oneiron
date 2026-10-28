//! The own-server speech rung on a VoxCPM2 worker (`deploy/voxcpm2`,
//! OF-410): a `[models.media.speech]` rung on a `voxcpm2` provider. The
//! worker keeps no clones. Each call carries the banked identity's source
//! clip ([`MediaVoice::Reference`]), which the host fenced from the bank;
//! the worker renders the sentence from it and erases it. Like any rung,
//! each call is admitted on its own permit, sent through the run's media
//! gate and settled on the characters it spoke.
//!
//! The wire is the worker's own. `GET /ready` names the warm target a
//! render must pin. `POST /render` sends a length-prefixed JSON header and
//! then the clip's WAV, and the worker answers with a header for the same
//! target and mono PCM16. Nothing is refused for its size (Rule 5): text
//! past the worker's per-render `max_text_bytes` goes as several renders,
//! in order, and their PCM is handed back as one WAV. Each render is one
//! physical request, with its own inference receipt naming the worker as
//! far as `/ready` proves it (FIX 8314, [`WarmTarget::worker`]).
//!
//! Each render's upload of the clip is under the bank's current reference
//! (FIX 9517): right before it, and again before a refused compressed
//! body's plain resend, the runtime's [`VoiceReferenceUploadGuard`]
//! re-reads the bank. A withdrawal or a replacement stops the renders still
//! to come, and the call ends as interrupted, the renders that answered
//! keeping their usage and receipts for the run to settle.
use std::collections::BTreeMap;
use std::sync::Arc;

use oneiron::llm::InferenceCallReceipt;
use oneiron::llm::media::wav::pcm16_wav;
use oneiron::llm::media::{
    AiOperation, InterruptedMediaCall, MediaBackend, MediaCallProgress, MediaFuture, MediaPart,
    MediaProgressFuture, MediaRequest, MediaResponse, MediaUsage, MediaVoice,
};
use oneiron::voice_cascade::speakable_pieces;
use oneiron::voice_cascade::voxcpm2::WarmTarget;
use oneiron::{BudgetLease, FatalLlmError, LlmError, LlmResult, ModelId, ModelLocality};
use serde_json::{Value as JsonValue, json};

use super::http::{BytesReply, MediaSend, ProviderHttp, UploadAdmission};
use super::media::{AdmittedReference, VoiceReferenceUploadGuard};
use super::rerank::transport;

/// One VoxCPM2 worker's media client, serving the models the speech seat
/// names on it.
pub(super) struct VoxCpm2Speech {
    pub(super) http: ProviderHttp,
    /// Engine model id -> the provider's model id. The worker serves one
    /// model, so the call names none on its wire.
    pub(super) models: BTreeMap<ModelId, String>,
    /// The render target the bank knows this worker by: its provider's name.
    pub(super) target: String,
    /// Where the worker runs, as its provider says.
    pub(super) locality: ModelLocality,
    /// The runtime's guard, asked before every upload of a clip.
    pub(super) voice_refs: VoiceReferenceUploadGuard,
}

/// What the renders that answered completed: their count, the characters
/// they spoke and their receipts.
fn progress(
    completed: u64,
    characters: u64,
    receipts: &[InferenceCallReceipt],
) -> MediaCallProgress {
    let mut usage = MediaUsage {
        characters,
        ..MediaUsage::default()
    };
    usage.put_inference_calls(receipts);
    MediaCallProgress { completed, usage }
}

/// A worker's refusal, read as any provider's status.
fn refused(reply: &BytesReply) -> LlmError {
    let body = serde_json::from_slice(&reply.body).unwrap_or(JsonValue::Null);
    oneiron_llm_openai::classify_openai_status(reply.status, &reply.headers, &body)
}

impl VoxCpm2Speech {
    /// The warm target the worker reports now. Asked once per call, so a
    /// restarted worker (a new boot id) is pinned right away.
    async fn warm(&self) -> LlmResult<WarmTarget> {
        let reply = self
            .http
            .send_media("/ready", MediaSend::Get)
            .await
            .map_err(transport)?;
        if !(200..300).contains(&reply.status) {
            return Err(refused(&reply));
        }
        let warm: WarmTarget =
            serde_json::from_slice(&reply.body).map_err(|_| FatalLlmError::EmptyResponse)?;
        warm.validate().map_err(|_| FatalLlmError::EmptyResponse)?;
        Ok(warm)
    }

    async fn speak(
        &self,
        mut request: MediaRequest,
    ) -> Result<MediaResponse, InterruptedMediaCall> {
        let text = request.text();
        if !self.models.contains_key(&request.model)
            || request.operation != AiOperation::Speech
            || text.trim().is_empty()
            || !request.references.is_empty()
            || !request
                .parts
                .iter()
                .all(|part| matches!(part, MediaPart::Text { .. }))
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        // The worker answers a WAV and takes no other params.
        let format = request.params.remove("response_format");
        if format.is_some_and(|format| format != "wav") || !request.params.is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        // No stock voice and no clones here: only a fenced reference.
        let Some(MediaVoice::Reference {
            voice_id,
            owner,
            register,
            revision,
            media_type,
            audio,
            transcript,
        }) = request.voice.take()
        else {
            return Err(FatalLlmError::InvalidRequest.into());
        };
        if media_type != "audio/wav" || transcript.trim().is_empty() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let warm = self.warm().await?;
        let target = json!({
            "voice_id": voice_id,
            "owner": owner,
            "register": register,
            "reference_revision": revision,
            "limits": warm.limits,
            "warm": warm,
        });
        let max = usize::try_from(warm.limits.max_text_bytes).unwrap_or(usize::MAX);
        // FIX 9517: every upload of the clip goes only under the bank's
        // current reference; what answered before keeps its usage.
        let admits: UploadAdmission = {
            let (guard, render_target, locality) =
                (self.voice_refs.clone(), self.target.clone(), self.locality);
            Arc::new(move || {
                let admitted = AdmittedReference {
                    voice_id: &voice_id,
                    owner: &owner,
                    register: &register,
                    revision: &revision,
                };
                guard.admits_upload(&render_target, locality, &admitted)
            })
        };
        let mut pcm = Vec::new();
        let mut receipts = Vec::new();
        let mut spoken = 0u64;
        for piece in speakable_pieces(&text, max) {
            let rendered = if admits() {
                self.render(&warm, &target, piece, &transcript, &audio, &admits)
                    .await
            } else {
                Err(FatalLlmError::InvalidRequest.into())
            };
            let error = match rendered {
                Ok(rendered) => {
                    pcm.extend(rendered);
                    receipts.push(warm.render_receipt(&request.model));
                    spoken = spoken.saturating_add(piece.chars().count() as u64);
                    continue;
                }
                Err(error) => error,
            };
            return Err(InterruptedMediaCall {
                error,
                progress: progress(receipts.len() as u64, spoken, &receipts),
            });
        }
        // A WAV's 32-bit lengths are the one bound on the joined audio.
        let wav = pcm16_wav(warm.sample_rate, 1, &pcm).ok_or(FatalLlmError::EmptyResponse)?;
        let mut usage = MediaUsage {
            characters: u64::try_from(text.chars().count()).unwrap_or(u64::MAX),
            ..MediaUsage::default()
        };
        usage.put_inference_calls(&receipts);
        Ok(MediaResponse {
            parts: vec![MediaPart::Audio {
                media_type: "audio/wav".into(),
                bytes: wav,
            }],
            usage,
            model: request.model,
        })
    }

    /// One render of `text`, within the worker's per-render bound, from the
    /// whole reference clip: the mono PCM16 the worker answers for `target`.
    /// `admits` is asked again before any resend of the clip.
    async fn render(
        &self,
        warm: &WarmTarget,
        target: &JsonValue,
        text: &str,
        transcript: &str,
        audio: &[u8],
        admits: &UploadAdmission,
    ) -> LlmResult<Vec<u8>> {
        let limits = warm.limits;
        let header = serde_json::to_vec(&json!({
            "target": target,
            "text": text,
            "transcript": transcript,
        }))
        .map_err(|_| FatalLlmError::InvalidRequest)?;
        // The worker's JSON header decoder bound, its wire's own.
        if header.len() as u64 > limits.max_header_bytes {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let length = u32::try_from(header.len()).map_err(|_| FatalLlmError::InvalidRequest)?;
        let mut body = Vec::with_capacity(4 + header.len() + audio.len());
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&header);
        body.extend_from_slice(audio);
        let reply = self
            .http
            .send_media("/render", MediaSend::Octets(body, Arc::clone(admits)))
            .await
            .map_err(transport)?;
        if !(200..300).contains(&reply.status) {
            return Err(refused(&reply));
        }
        let mut received = reply.body;
        if received.len() < 5 {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        let n = u32::from_be_bytes([received[0], received[1], received[2], received[3]]) as usize;
        if n == 0 || n as u64 > limits.max_header_bytes || received.len() <= n + 4 {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        let meta: JsonValue = serde_json::from_slice(&received[4..4 + n])
            .map_err(|_| FatalLlmError::EmptyResponse)?;
        // The audio must be for the very target this call pinned.
        if meta["target"] != *target
            || meta["sample_rate"].as_u64() != Some(u64::from(warm.sample_rate))
            || meta["channels"].as_u64() != Some(1)
            || !(received.len() - 4 - n).is_multiple_of(2)
        {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        Ok(received.split_off(4 + n))
    }
}

impl MediaBackend for VoxCpm2Speech {
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async move { self.speak(request).await.map_err(LlmError::from) })
    }

    fn run_progress<'a>(
        &'a self,
        request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaProgressFuture<'a> {
        Box::pin(self.speak(request))
    }
}
