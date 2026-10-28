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
//! far as `/ready` proves it (FIX 8314, [`WarmTarget::worker`]). A render's
//! reply is taken as it arrives (FIX 6122): its header within the worker's
//! bound, then its PCM into the spool the cascade's own VoxCPM2 path uses
//! ([`PcmSpool`]), in memory up to the vault's result-body inline bound and
//! spilled past it; the WAV is read together from the spools at the end.
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
use oneiron::voice_cascade::voxcpm2::{PcmSpool, VoxCpm2PcmBody, WarmTarget};
use oneiron::{
    BudgetLease, FatalLlmError, LlmError, LlmResult, ModelId, ModelLocality, RetryableLlmError,
    Vault,
};
use serde_json::{Value as JsonValue, json};

use super::http::{BytesReply, MediaSend, ProviderHttp, StreamedReply, UploadAdmission};
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

/// Audio this machine could not spool or read back (its body directory, its
/// spill): no fault of the worker's answer, so the call may be tried again,
/// as one whose reply could not be allocated (FIX 8615).
fn spool_failed(error: oneiron::Error) -> LlmError {
    tracing::warn!(%error, "a VoxCPM2 render's audio could not be spooled; the call fails locally");
    RetryableLlmError::ServerError.into()
}

/// The header of one mono WAV at `sample_rate` holding every render's
/// audio, with room for it: the header [`pcm16_wav`] writes for an empty
/// clip, its RIFF and data lengths the joined audio's. `None` when the
/// joined audio overflows a WAV's 32-bit lengths.
fn joined_wav_header(sample_rate: u32, renders: &[VoxCpm2PcmBody]) -> Option<Vec<u8>> {
    let data = u32::try_from(renders.iter().map(VoxCpm2PcmBody::len).sum::<u64>()).ok()?;
    let riff = data.checked_add(36)?;
    let mut wav = pcm16_wav(sample_rate, 1, &[])?;
    wav.get_mut(4..8)?.copy_from_slice(&riff.to_le_bytes());
    wav.get_mut(40..44)?.copy_from_slice(&data.to_le_bytes());
    wav.reserve_exact(data as usize);
    Some(wav)
}

/// One render's framed reply, taken as it arrives: a 4-byte big-endian
/// header length, the JSON header, then the mono PCM16, which goes to its
/// spool.
struct FramedRender<'a> {
    warm: &'a WarmTarget,
    target: &'a JsonValue,
    /// The length prefix, then the header, until both are whole.
    head: Vec<u8>,
    /// The header's length, once its prefix is in.
    header: Option<usize>,
    spool: PcmSpool,
}

impl FramedRender<'_> {
    /// Takes the reply's next bytes. The header's length is checked against
    /// the worker's bound before a byte of the header is held, and the
    /// header against the target this call pinned before any audio is kept.
    fn push(&mut self, mut bytes: &[u8]) -> LlmResult<()> {
        let length = match self.header {
            Some(length) => length,
            None => {
                let take = (4 - self.head.len()).min(bytes.len());
                self.head.extend_from_slice(&bytes[..take]);
                bytes = &bytes[take..];
                let Ok(prefix) = <[u8; 4]>::try_from(self.head.as_slice()) else {
                    return Ok(());
                };
                let n = u32::from_be_bytes(prefix);
                if n == 0 || u64::from(n) > self.warm.limits.max_header_bytes {
                    return Err(FatalLlmError::EmptyResponse.into());
                }
                let length = n as usize;
                self.header = Some(length);
                length
            }
        };
        if self.head.len() < 4 + length {
            let take = (4 + length - self.head.len()).min(bytes.len());
            self.head.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.head.len() < 4 + length {
                return Ok(());
            }
            self.check_header()?;
        }
        if !bytes.is_empty() {
            self.spool.write(bytes).map_err(spool_failed)?;
        }
        Ok(())
    }

    /// The audio must be for the very target this call pinned.
    fn check_header(&self) -> LlmResult<()> {
        let meta: JsonValue =
            serde_json::from_slice(&self.head[4..]).map_err(|_| FatalLlmError::EmptyResponse)?;
        if meta["target"] != *self.target
            || meta["sample_rate"].as_u64() != Some(u64::from(self.warm.sample_rate))
            || meta["channels"].as_u64() != Some(1)
        {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        Ok(())
    }

    /// The render's whole audio, once its reply ended: none when the reply
    /// ended before its header did, held no audio or split a sample.
    fn finish(self, vault: &Vault) -> LlmResult<VoxCpm2PcmBody> {
        if self
            .header
            .is_none_or(|length| self.head.len() < 4 + length)
        {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        let body = self.spool.finish(vault).map_err(spool_failed)?;
        if body.is_empty() || !body.len().is_multiple_of(2) {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        Ok(body)
    }
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
        let mut renders = Vec::new();
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
                    renders.push(rendered);
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
        let mut wav =
            joined_wav_header(warm.sample_rate, &renders).ok_or(FatalLlmError::EmptyResponse)?;
        for render in &renders {
            if let Err(error) = render.append_to(&mut wav) {
                // Every render answered: each keeps its usage and receipt.
                return Err(InterruptedMediaCall {
                    error: spool_failed(error),
                    progress: progress(receipts.len() as u64, spoken, &receipts),
                });
            }
        }
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
    /// whole reference clip: the mono PCM16 the worker answers for `target`,
    /// spooled as it arrives. `admits` is asked again before any resend of
    /// the clip.
    async fn render(
        &self,
        warm: &WarmTarget,
        target: &JsonValue,
        text: &str,
        transcript: &str,
        audio: &[u8],
        admits: &UploadAdmission,
    ) -> LlmResult<VoxCpm2PcmBody> {
        // Bound whenever `admits` let the clip go: the runtime's own vault.
        let vault = self
            .voice_refs
            .vault()
            .ok_or(FatalLlmError::InvalidRequest)?;
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
        let mut reply = match self
            .http
            .send_media_streamed("/render", MediaSend::Octets(body, Arc::clone(admits)))
            .await
            .map_err(transport)?
        {
            StreamedReply::Body(reply) => reply,
            StreamedReply::Refused(reply) => return Err(refused(&reply)),
        };
        let mut framed = FramedRender {
            warm,
            target,
            head: Vec::with_capacity(4),
            header: None,
            spool: PcmSpool::new(&vault).map_err(spool_failed)?,
        };
        while let Some(chunk) = reply.chunk().await.map_err(transport)? {
            framed.push(&chunk)?;
        }
        framed.finish(&vault)
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
