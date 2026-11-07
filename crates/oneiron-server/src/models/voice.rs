//! The voice cascade's routes on the media seats (OF-410). A voice lane
//! speaks or hears on the one `[models.media]` rung its vault row's tier is
//! bound to (`tiers` on the speech and transcribe seats), and each call it
//! makes goes through the server's vault-bound media door
//! (`crate::server::MediaDoor`), admitted again by the vault's inference
//! policy and on its own permit, and settled on the media meter.
use std::collections::BTreeMap;

use oneiron::llm::media::{AiOperation, MediaRequest};
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
    /// rides every call the lane makes, each admitted again at its door.
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
        self.route_for(vault, lane, operation, backend)
    }

    /// The other tier-bound backends of `lane`'s seat as admitted routes,
    /// in seat order: the fallback targets a banked voice may bind on when
    /// the lane's own rung is down (FIX 3195). A rung this vault's policy
    /// refuses is passed over with a warning; whether a route's target
    /// holds the voice is for its bind to say.
    pub fn voice_fallback_routes(
        &self,
        vault: &Vault,
        lane: VoiceLane,
        primary: &MediaVoiceRoute,
    ) -> Vec<MediaVoiceRoute> {
        let operation = match lane {
            VoiceLane::AsrLive | VoiceLane::AsrBatch => AiOperation::Transcribe,
            VoiceLane::TtsLive | VoiceLane::TtsBatch => AiOperation::Speech,
        };
        self.media
            .voice_backends(operation)
            .into_iter()
            .filter(|backend| backend.model != primary.model)
            .filter_map(|backend| {
                let model = backend.model.clone();
                match self.route_for(vault, lane, operation, backend) {
                    Ok(route) => Some(route),
                    Err(error) => {
                        tracing::warn!(%error, model = %model, "a voice fallback rung was not admitted");
                        None
                    }
                }
            })
            .collect()
    }

    /// One rung of `lane`'s seat as an admitted route: its render target,
    /// then a probe of the rung the vault's inference policy admits.
    fn route_for(
        &self,
        vault: &Vault,
        lane: VoiceLane,
        operation: AiOperation,
        backend: oneiron::llm::VoiceBackendBinding,
    ) -> oneiron::Result<MediaVoiceRoute> {
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
                host_keyless: false,
                host_paid: false,
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
                keyless: false,
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

impl ModelRuntime {
    /// Selects a voice route from the receiving agent's actual frozen list.
    pub(crate) fn voice_route_for_models(
        &self,
        vault: &Vault,
        lane: VoiceLane,
        explicit: Option<&PurposeDefault>,
        listed: &[oneiron::agent_def::AgentModel],
    ) -> oneiron::Result<MediaVoiceRoute> {
        let operation = match lane {
            VoiceLane::AsrLive | VoiceLane::AsrBatch => AiOperation::Transcribe,
            VoiceLane::TtsLive | VoiceLane::TtsBatch => AiOperation::Speech,
        };
        let backends: Vec<_> = self
            .media
            .voice_backends(operation)
            .into_iter()
            .filter(|backend| {
                oneiron::agent_def::ensure_inherited_model_list(listed, &backend.model).is_ok()
            })
            .collect();
        let backend = vault.select_voice_backend(lane, explicit, &backends)?;
        self.route_for(vault, lane, operation, backend)
    }

    /// Keeps the original fallback order while conjoining the frozen list.
    pub(crate) fn voice_fallback_routes_for_models(
        &self,
        vault: &Vault,
        lane: VoiceLane,
        primary: &MediaVoiceRoute,
        listed: &[oneiron::agent_def::AgentModel],
    ) -> Vec<MediaVoiceRoute> {
        self.voice_fallback_routes(vault, lane, primary)
            .into_iter()
            .filter(|route| {
                oneiron::agent_def::ensure_inherited_model_list(listed, &route.model).is_ok()
            })
            .collect()
    }
}
