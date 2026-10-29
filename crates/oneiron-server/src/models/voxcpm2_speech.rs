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
//! past the effective per-render `max_text_bytes` goes as several renders,
//! in order, and their PCM is handed back as one WAV. A reference
//! transcript that would push the header past the worker's
//! `max_header_bytes` (FIX 3758) rides as a frame of its own after the
//! header when `/ready` says the worker takes one; on a worker that does
//! not, the text goes as smaller renders until each header fits. Each
//! render is one physical request, with its own inference receipt naming
//! the worker as far as `/ready` proves it (FIX 8314,
//! [`WarmTarget::worker`]). A render's reply is taken as it arrives (FIX
//! 6122): its header within the effective bound, then its PCM into the
//! spool the cascade's own VoxCPM2 path uses ([`PcmSpool`]), in memory up
//! to the vault's result-body inline bound and spilled past it; the WAV is
//! read together from the spools at the end.
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
use oneiron::voice_cascade::voxcpm2::{PcmSpool, VoiceServingLimits, VoxCpm2PcmBody, WarmTarget};
use oneiron::{
    BudgetLease, EntityId, FatalLlmError, LlmError, LlmResult, ModelId, ModelLocality,
    RetryableLlmError, Vault,
};
use serde_json::{Value as JsonValue, json};

use super::http::{BytesReply, MediaSend, ProviderHttp, StreamedReply, UploadAdmission};
use super::media::{AdmittedReference, VoiceReferenceUploadGuard};
use super::rerank::transport;

/// The field a worker's `/ready` sets, beside its warm target and never in
/// it, when its render wire takes the reference transcript as a frame of
/// its own after the header (FIX 3758). A worker that sets none takes the
/// transcript in the header only.
const TRANSCRIPT_FRAME_FIELD: &str = "transcript_frame";

/// Where a render's reference transcript rides.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TranscriptPlacement {
    /// In the JSON header, beside the text: every worker takes this.
    Header,
    /// As its own frame of `transcript_bytes` bytes between the header and
    /// the clip, for a worker whose `/ready` says it takes one.
    Frame,
}

/// A render's reference transcript and where it rides.
#[derive(Clone, Copy)]
struct Transcript<'a> {
    text: &'a str,
    placement: TranscriptPlacement,
}

/// One render's JSON header: the pinned target, the text, and the reference
/// transcript when it rides here, else its byte length.
fn render_header(target: &JsonValue, text: &str, transcript: Transcript<'_>) -> LlmResult<Vec<u8>> {
    let header = match transcript.placement {
        TranscriptPlacement::Header => json!({
            "target": target,
            "text": text,
            "transcript": transcript.text,
        }),
        TranscriptPlacement::Frame => json!({
            "target": target,
            "text": text,
            "transcript_bytes": transcript.text.len(),
        }),
    };
    serde_json::to_vec(&header).map_err(|_| FatalLlmError::InvalidRequest.into())
}

/// The bytes `text` takes as a JSON string, without its quotes.
fn escaped_len(text: &str) -> usize {
    serde_json::to_string(text).map_or(usize::MAX, |quoted| quoted.len().saturating_sub(2))
}

/// The renders `text` goes as, and where their reference transcript rides,
/// so every render's header stays within the worker's decoder bound
/// `max_header` (FIX 3758). The transcript rides in the header while every
/// piece within `max_text` fits beside it, as before; past that, as a frame
/// of its own when the worker takes one; else the pieces split again until
/// each header fits. Refused only when not one character fits.
fn header_pieces<'t>(
    target: &JsonValue,
    text: &'t str,
    transcript: &'t str,
    limits: VoiceServingLimits,
    takes_frame: bool,
) -> LlmResult<(Transcript<'t>, Vec<&'t str>)> {
    let max_text = usize::try_from(limits.max_text_bytes).unwrap_or(usize::MAX);
    let max_header = usize::try_from(limits.max_header_bytes).unwrap_or(usize::MAX);
    let pieces = speakable_pieces(text, max_text);
    // Every header differs from the empty-text one only by its text.
    let fits_beside = |transcript: Transcript<'_>| -> LlmResult<_> {
        let overhead = render_header(target, "", transcript)?.len();
        Ok(move |piece: &str| overhead.saturating_add(escaped_len(piece)) <= max_header)
    };
    let inline = Transcript {
        text: transcript,
        placement: TranscriptPlacement::Header,
    };
    let fits = fits_beside(inline)?;
    if pieces.iter().all(|&piece| fits(piece)) {
        return Ok((inline, pieces));
    }
    let transcript = if takes_frame {
        Transcript {
            text: transcript,
            placement: TranscriptPlacement::Frame,
        }
    } else {
        inline
    };
    let fits = fits_beside(transcript)?;
    let mut fitted = Vec::with_capacity(pieces.len());
    for piece in pieces {
        split_to_fit(piece, &fits, &mut fitted)?;
    }
    Ok((transcript, fitted))
}

/// `piece` as pieces whose header `fits`, in order: one that does not is
/// split again within half its length.
fn split_to_fit<'t>(
    piece: &'t str,
    fits: &dyn Fn(&str) -> bool,
    out: &mut Vec<&'t str>,
) -> LlmResult<()> {
    if fits(piece) {
        out.push(piece);
        return Ok(());
    }
    // One character that does not fit beside the transcript cannot go.
    if piece.chars().nth(1).is_none() {
        return Err(FatalLlmError::InvalidRequest.into());
    }
    for part in speakable_pieces(piece, piece.len() / 2) {
        split_to_fit(part, fits, out)?;
    }
    Ok(())
}

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

/// The vault's serving policy for `holder`, narrowed to the worker's
/// ceiling: each field the smaller of the two, so a narrowing never widens
/// past what the worker reports. The worker's own ceiling when the vault is
/// unbound or its policy cannot be read.
fn effective_limits(
    vault: Option<&Vault>,
    holder: Option<EntityId>,
    warm: &VoiceServingLimits,
) -> VoiceServingLimits {
    let Some(vault) = vault else {
        return *warm;
    };
    let Ok(narrowed) = vault.voice_serving_limits(holder) else {
        return *warm;
    };
    VoiceServingLimits {
        max_text_bytes: narrowed.max_text_bytes.min(warm.max_text_bytes),
        max_ref_bytes: narrowed.max_ref_bytes.min(warm.max_ref_bytes),
        max_queued_renders: narrowed.max_queued_renders.min(warm.max_queued_renders),
        max_inflight_uploads: narrowed.max_inflight_uploads.min(warm.max_inflight_uploads),
        upload_read_deadline_ms: narrowed
            .upload_read_deadline_ms
            .min(warm.upload_read_deadline_ms),
        http_deadline_ms: narrowed.http_deadline_ms.min(warm.http_deadline_ms),
        max_header_bytes: narrowed.max_header_bytes.min(warm.max_header_bytes),
    }
}

/// One render's framed reply, taken as it arrives: a 4-byte big-endian
/// header length, the JSON header, then the mono PCM16, which goes to its
/// spool.
struct FramedRender<'a> {
    warm: &'a WarmTarget,
    limits: VoiceServingLimits,
    target: &'a JsonValue,
    /// The length prefix, then the header, until both are whole.
    head: Vec<u8>,
    /// The header's length, once its prefix is in.
    header: Option<usize>,
    spool: PcmSpool,
}

impl FramedRender<'_> {
    /// Takes the reply's next bytes. The header's length is checked against
    /// the effective bound before a byte of the header is held, and the
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
                if n == 0 || u64::from(n) > self.limits.max_header_bytes {
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
    /// The warm target the worker reports now, and whether it takes the
    /// reference transcript as a frame of its own. Asked once per call, so a
    /// restarted worker (a new boot id) is pinned right away.
    async fn warm(&self) -> LlmResult<(WarmTarget, bool)> {
        let reply = self
            .http
            .send_media("/ready", MediaSend::Get)
            .await
            .map_err(transport)?;
        if !(200..300).contains(&reply.status) {
            return Err(refused(&reply));
        }
        let mut ready: JsonValue =
            serde_json::from_slice(&reply.body).map_err(|_| FatalLlmError::EmptyResponse)?;
        // Said beside the target, so the target a render echoes stays the
        // worker's own.
        let takes_frame = ready
            .as_object_mut()
            .and_then(|fields| fields.remove(TRANSCRIPT_FRAME_FIELD))
            == Some(JsonValue::Bool(true));
        let warm: WarmTarget =
            serde_json::from_value(ready).map_err(|_| FatalLlmError::EmptyResponse)?;
        warm.validate().map_err(|_| FatalLlmError::EmptyResponse)?;
        Ok((warm, takes_frame))
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
        let (warm, takes_frame) = self.warm().await?;
        // The vault's policy for the voice's holder, narrowed to the worker's
        // ceiling: what the renders send as their effective limits.
        let holder = EntityId::from_hex(&owner).ok();
        let vault = self.voice_refs.vault();
        let limits = effective_limits(vault.as_deref(), holder, &warm.limits);
        let target = json!({
            "voice_id": voice_id,
            "owner": owner,
            "register": register,
            "reference_revision": revision,
            "limits": limits,
            "warm": warm,
        });
        let (transcript, pieces) = header_pieces(&target, &text, &transcript, limits, takes_frame)?;
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
        for piece in pieces {
            let rendered = if admits() {
                self.render(&warm, limits, &target, piece, transcript, &audio, &admits)
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

    /// One render of `text`, within the effective per-render bounds, from the
    /// whole reference clip and its `transcript`: the mono PCM16 the worker
    /// answers for `target`, spooled as it arrives. `admits` is asked again
    /// before any resend of the clip.
    async fn render(
        &self,
        warm: &WarmTarget,
        limits: VoiceServingLimits,
        target: &JsonValue,
        text: &str,
        transcript: Transcript<'_>,
        audio: &[u8],
        admits: &UploadAdmission,
    ) -> LlmResult<VoxCpm2PcmBody> {
        // Bound whenever `admits` let the clip go: the runtime's own vault.
        let vault = self
            .voice_refs
            .vault()
            .ok_or(FatalLlmError::InvalidRequest)?;
        let header = render_header(target, text, transcript)?;
        // The effective JSON header decoder bound, its wire's own: the
        // pieces were cut to fit within it.
        if header.len() as u64 > limits.max_header_bytes {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        let length = u32::try_from(header.len()).map_err(|_| FatalLlmError::InvalidRequest)?;
        let framed = match transcript.placement {
            TranscriptPlacement::Header => &[][..],
            TranscriptPlacement::Frame => transcript.text.as_bytes(),
        };
        let mut body = Vec::with_capacity(4 + header.len() + framed.len() + audio.len());
        body.extend_from_slice(&length.to_be_bytes());
        body.extend_from_slice(&header);
        body.extend_from_slice(framed);
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
            limits,
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
