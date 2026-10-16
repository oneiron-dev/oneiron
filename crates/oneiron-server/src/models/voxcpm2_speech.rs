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
//! target and mono PCM16, which is handed back as a WAV.
use std::collections::BTreeMap;

use oneiron::llm::media::wav::pcm16_wav;
use oneiron::llm::media::{
    AiOperation, MediaBackend, MediaFuture, MediaPart, MediaRequest, MediaResponse, MediaUsage,
    MediaVoice,
};
use oneiron::voice_cascade::voxcpm2::WarmTarget;
use oneiron::{BudgetLease, FatalLlmError, LlmError, LlmResult, ModelId};
use serde_json::{Value as JsonValue, json};

use super::http::{BytesReply, MediaSend, ProviderHttp};
use super::rerank::transport;

/// The longest reference transcript the worker takes, in characters.
const MAX_TRANSCRIPT_CHARS: usize = 16_384;

/// One VoxCPM2 worker's media client, serving the models the speech seat
/// names on it.
pub(super) struct VoxCpm2Speech {
    pub(super) http: ProviderHttp,
    /// Engine model id -> the provider's model id. The worker serves one
    /// model, so the call names none on its wire.
    pub(super) models: BTreeMap<ModelId, String>,
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

    async fn speak(&self, mut request: MediaRequest) -> LlmResult<MediaResponse> {
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
        if media_type != "audio/wav"
            || transcript.trim().is_empty()
            || transcript.chars().count() > MAX_TRANSCRIPT_CHARS
        {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let warm = self.warm().await?;
        let limits = warm.limits;
        if text.len() as u64 > limits.max_text_bytes || audio.len() as u64 > limits.max_ref_bytes {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let target = json!({
            "voice_id": voice_id,
            "owner": owner,
            "register": register,
            "reference_revision": revision,
            "limits": limits,
            "warm": warm,
        });
        let header = serde_json::to_vec(&json!({
            "target": target,
            "text": text,
            "transcript": transcript,
        }))
        .map_err(|_| FatalLlmError::InvalidRequest)?;
        if header.len() as u64 > limits.max_header_bytes {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let length = u32::try_from(header.len()).map_err(|_| FatalLlmError::InvalidRequest)?;
        let mut body = Vec::with_capacity(4 + header.len() + audio.len());
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&header);
        body.extend_from_slice(&audio);
        let reply = self
            .http
            .send_media("/render", MediaSend::Octets(body))
            .await
            .map_err(transport)?;
        if !(200..300).contains(&reply.status) {
            return Err(refused(&reply));
        }
        let received = reply.body;
        if received.len() < 5
            || received.len() as u64 > limits.max_pcm_bytes + limits.max_header_bytes + 4
        {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        let n = u32::from_be_bytes([received[0], received[1], received[2], received[3]]) as usize;
        if n == 0 || n as u64 > limits.max_header_bytes || received.len() <= n + 4 {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        let meta: JsonValue = serde_json::from_slice(&received[4..4 + n])
            .map_err(|_| FatalLlmError::EmptyResponse)?;
        // The audio must be for the very target this call pinned.
        let pcm = &received[4 + n..];
        if meta["target"] != target
            || meta["sample_rate"].as_u64() != Some(u64::from(warm.sample_rate))
            || meta["channels"].as_u64() != Some(1)
            || !pcm.len().is_multiple_of(2)
        {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        let wav = pcm16_wav(warm.sample_rate, 1, pcm).ok_or(FatalLlmError::EmptyResponse)?;
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

impl MediaBackend for VoxCpm2Speech {
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(self.speak(request))
    }
}
