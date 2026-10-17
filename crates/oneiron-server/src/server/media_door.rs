//! The vault-bound media door (FIX-LIST 467): the one door engine code makes
//! a media call through. It holds the server's model runtime with the vault
//! and the extraction-egress predicate it serves, and admits each call, and
//! each live stream it opens, afresh on the vault's inference policy, as a
//! `/v1/ai` media verb admits its call ([`admit_media`]). A route the policy
//! admitted once, when it was built (a voice lane's), is no check at its
//! later calls. Only then does the call go down its seat's ladder, on a
//! permit of its own; a runtime alone is no door.
use std::sync::Arc;

use oneiron::llm::media::{AiMediaDoor, MediaFuture, MediaRequest, MediaResponse};
use oneiron::llm::run_admission::MediaStreamLease;
use oneiron::llm::{
    ExtractionEgressPredicate, HostInferenceBinding, HostInferenceContext, VoiceLane,
};
use oneiron::voice_cascade::media::{MediaVoiceRoute, VoiceStreamDoor};
use oneiron::{FatalLlmError, LlmResult, Vault};

use super::core::SyncServer;
use crate::models::soniox::SonioxLive;
use crate::models::{MediaRuntime, ModelRuntime};

/// Why a media call is refused before it goes out.
pub(crate) enum MediaRefusal {
    /// No seat or rung of the call's operation has the id it names.
    UnknownModel,
    /// The call names a route selector of its own: this parameter.
    SelectorOverride(String),
    /// The vault's inference policy refuses it.
    Denied(oneiron::Error),
}

/// `request` as the vault's inference policy admits it: on the locality
/// `media` attests for the model it names, with no route selector of its
/// own, and carrying the envelope the policy authorized, with no world it
/// vouches for. Every media call is admitted here, at each call: a
/// `/v1/ai` media verb's and engine code's through [`MediaDoor`].
pub(crate) fn admit_media(
    vault: &Vault,
    media: &MediaRuntime,
    extraction_egress: Option<&dyn ExtractionEgressPredicate>,
    mut request: MediaRequest,
) -> Result<MediaRequest, MediaRefusal> {
    let locality = media
        .locality(request.operation, &request.model)
        .ok_or(MediaRefusal::UnknownModel)?;
    request.envelope.locality = locality;
    if let Some(key) = request.admission_request().route_selector_override() {
        return Err(MediaRefusal::SelectorOverride(key));
    }
    let context = HostInferenceContext {
        binding: HostInferenceBinding::Advertised {
            model: request.model.clone(),
            locality,
        },
        extraction_egress,
    };
    let authorized = vault
        .authorize_raw_inference(request.admission_request(), &context)
        .map_err(MediaRefusal::Denied)?;
    request.envelope = authorized.into_request().envelope;
    // The world a caller names does not vouch for what it sends: a
    // fallback judges the call as naming none, as a raw text call is.
    request.envelope.scope.world = None;
    Ok(request)
}

/// The media door engine code holds ([`AiMediaDoor`], and
/// [`VoiceStreamDoor`] for a live hearing's segments): the server's model
/// runtime bound to its vault. Each call is admitted by [`admit_media`],
/// then runs on the media meter as a run of its own.
pub struct MediaDoor {
    vault: Arc<Vault>,
    runtime: Arc<ModelRuntime>,
    extraction_egress: Option<Arc<dyn ExtractionEgressPredicate>>,
}

impl MediaDoor {
    /// `request`, admitted on the vault's inference policy. A refused call
    /// is an invalid one to its caller.
    fn admit(&self, request: MediaRequest) -> LlmResult<MediaRequest> {
        admit_media(
            &self.vault,
            self.runtime.media(),
            self.extraction_egress.as_deref(),
            request,
        )
        .map_err(|refused| {
            match refused {
                MediaRefusal::UnknownModel => {
                    tracing::warn!("an engine media call names no media seat or rung");
                }
                MediaRefusal::SelectorOverride(key) => {
                    tracing::warn!(%key, "an engine media call names a route selector");
                }
                MediaRefusal::Denied(error) => {
                    tracing::warn!(%error, "the vault refused an engine media call");
                }
            }
            FatalLlmError::InvalidRequest.into()
        })
    }

    /// The media rung voice lane `lane` runs on, from the vault's voice row
    /// for it ([`ModelRuntime::voice_route`]).
    pub(crate) fn voice_route(&self, lane: VoiceLane) -> oneiron::Result<MediaVoiceRoute> {
        self.runtime.voice_route(&self.vault, lane, None)
    }

    /// The live hearing for `route` when its rung hears live, each of its
    /// segments' leases opened through this door
    /// ([`ModelRuntime::open_voice_asr`]).
    pub(crate) fn open_voice_asr(
        self: &Arc<Self>,
        route: &MediaVoiceRoute,
        sample_rate: u32,
        channels: u16,
    ) -> oneiron::Result<Option<SonioxLive>> {
        self.runtime
            .open_voice_asr(Arc::clone(self), route, sample_rate, channels)
    }
}

impl AiMediaDoor for MediaDoor {
    fn call<'a>(&'a self, request: MediaRequest) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async move {
            let request = self.admit(request)?;
            self.runtime.media().run(request).await
        })
    }
}

impl VoiceStreamDoor for MediaDoor {
    fn open_stream<'a>(
        &'a self,
        request: MediaRequest,
        bound_ms: u64,
    ) -> MediaFuture<'a, MediaStreamLease> {
        Box::pin(async move {
            let request = self.admit(request)?;
            self.runtime.media().open_stream(request, bound_ms)
        })
    }
}

impl SyncServer {
    /// The vault-bound media door over this server's model runtime: the
    /// one engine code (the voice host's media worker and live hearing)
    /// makes its media calls through.
    #[must_use]
    pub(crate) fn media_door(&self) -> Arc<MediaDoor> {
        Arc::new(MediaDoor {
            vault: Arc::clone(&self.vault),
            runtime: Arc::clone(self.ai.models()),
            extraction_egress: self.extraction_egress.clone(),
        })
    }
}
