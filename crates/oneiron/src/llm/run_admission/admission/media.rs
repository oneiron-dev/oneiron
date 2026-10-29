//! Media and single-route doors for one run's admission handle.
use std::sync::Arc;

use super::super::gate::GatedBackend;
use super::super::host::OfferBinding;
use super::super::media::MediaGate;
use super::super::permit::RunPermit;
use super::{RunAdmission, RunCall, RunDenied};
use crate::llm::SingleRouteBackend;
use crate::llm::media::{MediaBackend, MediaRequest};

impl RunAdmission {
    /// The only backend a host hands a run for `offer`, over that offer's own
    /// backend and credential: it checks and starts the call's permit before
    /// any byte leaves, on `generate` and `stream`. A permit admitted under
    /// another offer never starts here, whatever route the two share.
    #[must_use]
    pub fn gate(&self, inner: Arc<dyn SingleRouteBackend>, offer: &OfferBinding) -> GatedBackend {
        let offer = self.inner.bound(offer).dispatch_binding();
        GatedBackend::new(Arc::clone(&self.inner), inner, offer)
    }

    /// Admits one media call (`ai.image`, `ai.video`, `ai.speech`,
    /// `ai.transcribe`, `ai.embed`) as the text call its admission request
    /// names: the same teachers, offer, locality and route rules, and one
    /// permit for one physical call.
    pub fn admit_media(
        &self,
        selector: Option<&str>,
        request: &MediaRequest,
        offer: &OfferBinding,
    ) -> Result<RunPermit, RunDenied> {
        let admission = request.admission_request();
        self.admit(RunCall {
            selector,
            request: &admission,
            offer,
        })
    }

    /// Admits one bounded media stream (live `ai.transcribe` partials) as
    /// [`Self::admit_media`] admits one call, on one permit for the whole
    /// stream. The permit reserves `reserve_units`, the stream's bound at its
    /// rung's rate ([`MediaStreamLease::reserve_units`](super::super::MediaStreamLease::reserve_units)), in place of one
    /// call's reservation; the run's line and the vault's allocation must
    /// hold all of it before any audio leaves.
    pub fn admit_media_stream(
        &self,
        selector: Option<&str>,
        request: &MediaRequest,
        offer: &OfferBinding,
        reserve_units: u64,
    ) -> Result<RunPermit, RunDenied> {
        let admission = request.admission_request();
        let offer = self.inner.bound(offer);
        let call = RunCall {
            selector,
            request: &admission,
            offer: &*offer,
        };
        let (revision, declaration) = self.inner.snapshot();
        let declaration = declaration.with_reserve(reserve_units);
        let admitted = self
            .inner
            .admit_model(&declaration, revision, call, None, self.origin());
        self.inner.receipt_for(
            revision,
            selector,
            admission.model.as_str(),
            admitted,
            Some(admission.model.clone()),
        )
    }

    /// The only media backend a host hands a run for `offer`: it checks and
    /// starts a media call's permit before any byte leaves, as
    /// [`Self::gate`] does for a text call.
    #[must_use]
    pub fn media_gate(&self, inner: Arc<dyn MediaBackend>, offer: &OfferBinding) -> MediaGate {
        let offer = self.inner.bound(offer).dispatch_binding();
        MediaGate::new(
            Arc::clone(&self.inner),
            inner,
            offer,
            self.submit_key.clone(),
        )
    }
}
