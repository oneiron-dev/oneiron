//! The voice cascade's routes on the media seats (OF-410). A voice lane
//! speaks or hears on the one `[models.media]` rung its vault row's tier is
//! bound to (`tiers` on the speech and transcribe seats), and each call it
//! makes goes through [`ModelRuntime`] as a media door, admitted on its own
//! permit and settled on the media meter.
use std::collections::BTreeMap;

use oneiron::llm::media::{AiMediaDoor, AiOperation, MediaFuture, MediaRequest, MediaResponse};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext, PurposeDefault, VoiceLane};
use oneiron::voice_cascade::media::MediaVoiceRoute;
use oneiron::{CallClass, CallEnvelope, CallPurpose, ResponseFormat, TierPrecedence, Vault};

use super::ModelRuntime;

impl ModelRuntime {
    /// The media rung `lane` runs on, picked before any work. The vault's
    /// voice row for the lane (or an authenticated, narrower `explicit` row)
    /// names a tier and a locality, and exactly one bound rung must serve
    /// both: none, or two, refuses rather than relabel another rung. The
    /// vault's inference policy then admits the route, and its envelope
    /// rides every call the lane makes.
    pub fn voice_route(
        &self,
        vault: &Vault,
        lane: VoiceLane,
        explicit: Option<&PurposeDefault>,
    ) -> oneiron::Result<MediaVoiceRoute> {
        let operation = match lane {
            VoiceLane::AsrLive | VoiceLane::AsrBatch => AiOperation::Transcribe,
            VoiceLane::TtsLive | VoiceLane::TtsBatch => AiOperation::Speech,
        };
        let backend =
            vault.select_voice_backend(lane, explicit, &self.media.voice_backends(operation))?;
        let (_, target, _) = self
            .media
            .rung_targets(operation, &backend.model)
            .into_iter()
            .next()
            .ok_or_else(|| oneiron::Error::InvalidConfig("voice rung did not start".into()))?;
        let purpose = CallPurpose::Voice;
        let probe = MediaRequest {
            model: backend.model.clone(),
            envelope: CallEnvelope {
                scope: Default::default(),
                tier: TierPrecedence::for_purpose(&purpose, backend.tier.clone()),
                purpose,
                class: CallClass::BestEffort,
                response_format: ResponseFormat::Text,
                locality: backend.locality,
                seat_effort: None,
            },
            operation,
            parts: Vec::new(),
            references: Vec::new(),
            params: BTreeMap::new(),
            voice: None,
        };
        let context = HostInferenceContext {
            binding: HostInferenceBinding::Advertised {
                model: backend.model.clone(),
                locality: backend.locality,
            },
            extraction_egress: None,
        };
        let mut envelope = vault
            .authorize_raw_inference(probe.admission_request(), &context)?
            .into_request()
            .envelope;
        // A voice call vouches for no world.
        envelope.scope.world = None;
        Ok(MediaVoiceRoute {
            lane,
            model: backend.model,
            tier: backend.tier,
            locality: backend.locality,
            reference_target: self.media.renders_from_refs(&target),
            target,
            envelope,
        })
    }
}

/// The door engine code holds when it keeps the runtime itself (the voice
/// cascade's media worker): each call is a run of its own on the media
/// meter, rung by rung through the media gate.
impl AiMediaDoor for ModelRuntime {
    fn call<'a>(&'a self, request: MediaRequest) -> MediaFuture<'a, MediaResponse> {
        Box::pin(self.media.run(request))
    }
}

/// The door the voice cascade opens a live stream through
/// ([`oneiron::voice_cascade::media::LeasedAsrStream`]): each stream is a
/// run of its own on the media meter, on one permit.
impl oneiron::voice_cascade::media::VoiceStreamDoor for ModelRuntime {
    fn open_stream<'a>(
        &'a self,
        request: MediaRequest,
        bound_ms: u64,
    ) -> MediaFuture<'a, oneiron::llm::run_admission::MediaStreamLease> {
        Box::pin(async move { self.media.open_stream(request, bound_ms) })
    }
}
