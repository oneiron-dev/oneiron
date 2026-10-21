//! Media backends and the host's media door.
//! Entry: MediaBackend.
//! Definitions: this module; the parent re-exports the old paths.

use super::{
    AiOperation, Arc, BrokerIsolation, BudgetLease, FatalLlmError, ImageBackend, LlmError,
    LlmResult, MediaFuture, MediaJobState, MediaRequest, MediaResponse, ModelId,
};

/// A provider adapter's media wire. Each call carries the lease of the
/// permit that bought it; a host-built transport sends one request per call,
/// so a run's media gate may wrap it. A job's poll and cancel ride the
/// permit its submit started.
pub trait MediaBackend: Send + Sync {
    /// Runs one call to its answer.
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse>;

    /// Starts one long call as a provider job; returns the provider's job id.
    fn submit<'a>(
        &'a self,
        _request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, String> {
        Box::pin(async { Err::<String, LlmError>(FatalLlmError::InvalidRequest.into()) })
    }

    /// Where the provider's job `job` for `model` stands; a done job's
    /// answer is fetched with it.
    fn poll<'a>(
        &'a self,
        _model: &'a ModelId,
        _job: &'a str,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaJobState> {
        Box::pin(async { Err::<MediaJobState, LlmError>(FatalLlmError::InvalidRequest.into()) })
    }

    /// Asks the provider to stop job `job`.
    fn cancel<'a>(
        &'a self,
        _model: &'a ModelId,
        _job: &'a str,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, ()> {
        Box::pin(async { Err::<(), LlmError>(FatalLlmError::InvalidRequest.into()) })
    }

    /// Every check this backend makes before it sends, with no I/O: the
    /// refusal its call would return for `request` before any byte leaves (a
    /// model it does not serve, no broker to send through, a key its custody
    /// door would refuse), or `Ok` when it would send. A run's media gate
    /// asks it before the call's permit starts, so a refusal costs nothing.
    fn preflight(&self, request: &MediaRequest) -> LlmResult<()> {
        let _ = request;
        Ok(())
    }

    /// How the credential broker that sends this backend's calls is kept
    /// apart from the daemon, for the dispatch receipt. `None`, the default,
    /// for a backend whose key, if any, no broker holds.
    fn broker_isolation(&self) -> Option<BrokerIsolation> {
        None
    }
}

/// An [`ImageBackend`] as a media backend: an image call with reference
/// images is its reference edit, one without is a generation.
pub struct ImageMedia(pub Arc<dyn ImageBackend>);

impl MediaBackend for ImageMedia {
    fn run<'a>(
        &'a self,
        request: MediaRequest,
        lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async move {
            if request.operation != AiOperation::Image {
                return Err(FatalLlmError::InvalidRequest.into());
            }
            let references = request
                .reference_images()
                .ok_or(FatalLlmError::InvalidRequest)?;
            let intent = request.image_intent()?;
            let response = if references.is_empty() {
                self.0.generate(intent, lease).await?
            } else {
                self.0.reference_edit(intent, references, lease).await?
            };
            Ok::<_, LlmError>(MediaResponse::from_image(response))
        })
    }
}

/// The host's door for one engine media call: it admits the call under its
/// run, sends it rung by rung and settles it. Engine code that makes a media
/// call holds this, never a backend or a bare lease.
pub trait AiMediaDoor: Send + Sync {
    fn call<'a>(&'a self, request: MediaRequest) -> MediaFuture<'a, MediaResponse>;
}
