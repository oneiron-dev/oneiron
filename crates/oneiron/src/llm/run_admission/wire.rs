//! A media rung whose wire the host drives itself, on its own thread: a local
//! process or a loopback worker whose answer is the host's own record (a
//! meeting pack's aligned words, a VoxCPM2 worker's PCM), not a
//! [`MediaResponse`](super::super::media::MediaResponse). Each call on it is
//! one media call of its run, as any other is: admitted as
//! [`RunAdmission::admit_media`] admits one, its permit checked and started
//! at the rung's media gate before the host's wire sends, its dispatch
//! receipt written when the wire ends, and settled in the rung's native units
//! at its row's rates, or as failed, its reservation spent, when the wire
//! failed after it started. Nothing here refuses a call for its size, its
//! count or its rate.
use std::sync::Arc;

use super::super::media::{
    AiOperation, MediaBackend, MediaCaps, MediaFuture, MediaPart, MediaRequest, MediaResponse,
    MediaUsage, MediaVoice,
};
use super::super::{BudgetLease, CallEnvelope, FatalLlmError, LlmError, ModelLocality};
use super::admission::RunAdmission;
use super::host::OfferBinding;
use super::settle::CallOutcome;

/// One media rung a host sends on through its own wire.
#[derive(Clone)]
pub struct WireSeat {
    run: RunAdmission,
    offer: OfferBinding,
    /// The vault's admission of the rung; every call carries it.
    envelope: CallEnvelope,
    /// The rung's row: the rates its native units settle at.
    caps: MediaCaps,
}

/// Why a call on a host's wire gave no answer.
#[derive(Debug)]
pub enum WireCallError<E> {
    /// The run refused the call, or its gate would not start it: nothing
    /// was sent.
    Refused(LlmError),
    /// The wire failed after the call started.
    Failed(E),
}

impl WireSeat {
    /// The rung `offer` binds for `run`, under `envelope`, at `caps`' rates.
    #[must_use]
    pub fn new(
        run: RunAdmission,
        offer: OfferBinding,
        envelope: CallEnvelope,
        caps: MediaCaps,
    ) -> Self {
        Self {
            run,
            offer,
            envelope,
            caps,
        }
    }

    /// Where the rung runs.
    #[must_use]
    pub fn locality(&self) -> ModelLocality {
        self.offer.locality
    }

    /// The model the rung serves.
    #[must_use]
    pub fn model(&self) -> &str {
        self.offer.model.as_str()
    }

    /// The call `operation` makes on this rung over `parts`, in `voice`:
    /// the rung's model, at its offer's locality.
    #[must_use]
    pub fn request(
        &self,
        operation: AiOperation,
        parts: Vec<MediaPart>,
        voice: Option<MediaVoice>,
    ) -> MediaRequest {
        let mut envelope = self.envelope.clone();
        envelope.locality = self.offer.locality;
        MediaRequest {
            model: self.offer.model.clone(),
            envelope,
            operation,
            parts,
            references: Vec::new(),
            params: std::collections::BTreeMap::new(),
            voice,
        }
    }

    /// Sends `request` on the host's wire as one admitted media call:
    /// `send` runs only once its permit has started, and `usage` reads the
    /// native counts an answer settles on.
    pub fn call<T, E>(
        &self,
        request: &MediaRequest,
        send: impl FnOnce() -> Result<T, E>,
        usage: impl FnOnce(&T) -> MediaUsage,
    ) -> Result<T, WireCallError<E>> {
        let permit = self
            .run
            .admit_media(None, request, &self.offer)
            .map_err(|denied| WireCallError::Refused(denied.into()))?;
        let gate = self.run.media_gate(Arc::new(HostWire), &self.offer);
        // A permit the gate does not start is dropped unstarted, which
        // releases its reservation.
        let answer = gate
            .run_wire(request, permit.lease(), send)
            .map_err(WireCallError::Refused)?;
        let settled = match &answer {
            Ok(answer) => {
                permit.settle_media(usage(answer).token_units(request.operation, &self.caps))
            }
            Err(_) => permit.settle(CallOutcome::Failed),
        };
        if let Err(denied) = settled {
            tracing::error!(%denied, "a host wire's media call settlement was refused");
        }
        answer.map_err(WireCallError::Failed)
    }
}

/// The backend of a host's wire: the host sends, so this one sends nothing,
/// and a call routed to it is refused.
struct HostWire;

impl MediaBackend for HostWire {
    fn run<'a>(
        &'a self,
        _request: MediaRequest,
        _lease: &'a BudgetLease,
    ) -> MediaFuture<'a, MediaResponse> {
        Box::pin(async { Err::<MediaResponse, LlmError>(FatalLlmError::InvalidRequest.into()) })
    }
}
