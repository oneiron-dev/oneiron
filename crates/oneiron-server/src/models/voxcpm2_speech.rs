//! The own-server speech rung on a VoxCPM2 worker (`deploy/voxcpm2`,
//! OF-410): a `[models.media.speech]` rung on a `voxcpm2` provider. The
//! worker keeps no clones. Each call carries the banked identity's source
//! clip ([`MediaVoice::Reference`]), which the host fenced from the bank;
//! the worker renders the sentence from it and erases it. Like any rung,
//! each call is admitted on its own permit, sent through the run's media
//! gate and settled on the characters it spoke.
//!
//! The wire is the worker's voice socket. One call is one connection
//! (`GET /v1/voice`) and one generation: the host reads `ready` for the warm
//! target a render must pin, sends `start` once with the reference transcript
//! and clip as their own binary frames, then one `text` frame per render,
//! and reads each render's `audio` frames until its `usage`. Nothing is
//! refused for its size (Rule 5): text past the effective per-render
//! `max_text_bytes` goes as several renders, in order, and their PCM is
//! handed back as one WAV. The transcript rides as its own frame within the
//! worker's `max_header_bytes` (FIX 3758); the text goes as smaller renders
//! until each `text` frame fits. Each render is one `text` exchange, with its
//! own inference receipt naming the worker as far as `ready` proves it (FIX
//! 8314, [`WarmTarget::worker`]). A render's reply is taken as it arrives
//! (FIX 6122): each `audio` binary into the spool the cascade's own VoxCPM2
//! path uses ([`PcmSpool`]), in memory up to the vault's result-body inline
//! bound and spilled past it; the WAV is read together from the spools at
//! the end.
//!
//! The reference uploads once per call, with the first render, and every
//! render goes only under the bank's current reference (FIX 9517): right
//! before each `text` frame the runtime's [`VoiceReferenceUploadGuard`]
//! re-reads the bank. A withdrawal or a replacement stops the renders still
//! to come, and the call ends as interrupted, the renders that answered
//! keeping their usage and receipts for the run to settle.
pub(in crate::models) mod socket;

use std::collections::BTreeMap;

use oneiron::llm::InferenceCallReceipt;
use oneiron::llm::media::{
    AiOperation, InterruptedMediaCall, MediaBackend, MediaCallProgress, MediaFuture, MediaPart,
    MediaProgressFuture, MediaRequest, MediaResponse, MediaUsage, MediaVoice,
};
use oneiron::voice_cascade::voxcpm2::{PcmSpool, VoiceServingLimits, VoxCpm2PcmBody, WarmTarget};
use oneiron::{
    BudgetLease, EntityId, FatalLlmError, LlmError, LlmResult, ModelId, ModelLocality,
    RetryableLlmError, Vault,
};
use oneiron_speech::tts::voxcpm2::{joined_wav_header, text_pieces};
use serde_json::{Value as JsonValue, json};

use super::media::{AdmittedReference, VoiceReferenceUploadGuard};

/// One VoxCPM2 worker's media client, serving the models the speech seat
/// names on it.
pub(super) struct VoxCpm2Speech {
    pub(super) voice: socket::VoiceSocketDialer,
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

/// Audio this machine could not spool or read back (its body directory, its
/// spill): no fault of the worker's answer, so the call may be tried again,
/// as one whose reply could not be allocated (FIX 8615).
fn spool_failed(error: oneiron::Error) -> LlmError {
    tracing::warn!(%error, "a VoxCPM2 render's audio could not be spooled; the call fails locally");
    RetryableLlmError::ServerError.into()
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

impl VoxCpm2Speech {
    async fn speak(
        &self,
        mut request: MediaRequest,
        dispatch: Option<(oneiron::llm::DispatchRelease<'_>, &BudgetLease)>,
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
        if let Some((release, _)) = dispatch {
            release()?;
        }
        let (mut socket, warm): (socket::VoiceSocket, WarmTarget) = self.voice.open().await?;
        let result = async {
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
            let pieces = text_pieces(&text, limits)?;
            // FIX 9517: every render goes only under the bank's current
            // reference; what answered before keeps its usage.
            let guard = self.voice_refs.clone();
            let render_target = self.target.clone();
            let locality = self.locality;
            let admits = || {
                let admitted = AdmittedReference {
                    voice_id: &voice_id,
                    owner: &owner,
                    register: &register,
                    revision: &revision,
                };
                guard.admits_upload(&render_target, locality, &admitted)
            };
            let mut renders = Vec::new();
            let mut receipts = Vec::new();
            let mut spoken = 0u64;
            let mut started = false;
            for piece in pieces {
                let rendered = async {
                    if !admits() {
                        return Err(FatalLlmError::InvalidRequest.into());
                    }
                    if let Some((release, lease)) = dispatch {
                        release()?;
                        lease.begin_physical_attempt();
                    }
                    let body = self
                        .render(
                            &mut socket,
                            &target,
                            warm.sample_rate,
                            piece,
                            &transcript,
                            &audio,
                            limits.max_header_bytes,
                            !started,
                        )
                        .await?;
                    started = true;
                    Ok::<_, LlmError>(body)
                }
                .await;
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
            let mut wav = joined_wav_header(warm.sample_rate, &renders)
                .ok_or(FatalLlmError::EmptyResponse)?;
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
                model: request.model.clone(),
            })
        }
        .await;
        socket.end().await;
        result
    }

    /// One render of `text`, within the effective per-render bounds, from the
    /// whole reference clip and its `transcript`: the mono PCM16 the worker
    /// answers for `target`, spooled as it arrives. The generation's `start`
    /// goes with the first render only.
    async fn render(
        &self,
        socket: &mut socket::VoiceSocket,
        target: &JsonValue,
        sample_rate: u32,
        text: &str,
        transcript: &str,
        audio: &[u8],
        max_header_bytes: u64,
        send_start: bool,
    ) -> LlmResult<VoxCpm2PcmBody> {
        // Bound whenever `admits` let the clip go: the runtime's own vault.
        let vault = self
            .voice_refs
            .vault()
            .ok_or(FatalLlmError::InvalidRequest)?;
        if send_start {
            socket
                .start(target, sample_rate, transcript, audio, max_header_bytes)
                .await?;
        }
        let mut spool = PcmSpool::new(&vault).map_err(spool_failed)?;
        socket
            .render(text, &mut |chunk| spool.write(chunk).map_err(spool_failed))
            .await?;
        let body = spool.finish(&vault).map_err(spool_failed)?;
        if body.is_empty() || !body.len().is_multiple_of(2) {
            return Err(FatalLlmError::EmptyResponse.into());
        }
        Ok(body)
    }
}

impl MediaBackend for VoxCpm2Speech {
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async move { self.speak(request, None).await.map_err(LlmError::from) })
    }

    fn run_progress<'a>(
        &'a self,
        request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaProgressFuture<'a> {
        Box::pin(self.speak(request, None))
    }

    fn run_progress_released<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
        release: Option<oneiron::llm::DispatchRelease<'a>>,
    ) -> MediaProgressFuture<'a> {
        Box::pin(self.speak(request, release.map(|release| (release, lease))))
    }
}
