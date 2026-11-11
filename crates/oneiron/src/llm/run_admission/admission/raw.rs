//! A model call whose host sends the exact bytes its caller wrote, not a
//! request the engine built: a seat's model door relays an official CLI's
//! request as the CLI wrote it (FIX 15702). The call is admitted as any
//! other is, on a permit bound to the digest of those bytes
//! ([`RunAdmission::admit_request`]); this is its gate. The host starts the
//! permit where the bytes leave, after the key is read and before the
//! broker sends, and the call's dispatch receipt is written once, when the
//! host ends it or drops it.
use std::sync::{Arc, Mutex, PoisonError};

use crate::llm::{
    BrokerIsolation, BudgetLease, DispatchBinding, FatalLlmError, LlmResult, ModelId,
};

use super::super::gate::Dispatch;
use super::super::host::OfferBinding;
use super::super::permit::RunPermit;
use super::{RunAdmission, RunInner};

/// One admitted call's gate on a host's own wire: it starts the call's
/// permit once, for exactly the bytes and the offer it was admitted for,
/// and writes its dispatch receipt once it started.
pub struct RawDispatch {
    run: Arc<RunInner>,
    call: DispatchBinding,
    lease: BudgetLease,
    model: ModelId,
    digest: String,
    isolation: Option<BrokerIsolation>,
    /// Set once the permit started; taken when the receipt is written.
    started: Mutex<Option<Dispatch>>,
}

impl RunAdmission {
    /// The gate of `permit`'s call, which the host sends itself as the
    /// bytes whose digest is `request_digest`, through `offer` and a broker
    /// of `isolation`. Nothing starts until [`RawDispatch::start`].
    #[must_use]
    pub fn raw_dispatch(
        &self,
        permit: &RunPermit,
        offer: &OfferBinding,
        request_digest: &str,
        isolation: Option<BrokerIsolation>,
    ) -> RawDispatch {
        let call = DispatchBinding {
            request_digest: Some(request_digest.to_owned()),
            ..self.inner.bound(offer).dispatch_binding()
        };
        RawDispatch {
            run: Arc::clone(&self.inner),
            call,
            lease: permit.lease().clone(),
            model: offer.model.clone(),
            digest: request_digest.to_owned(),
            isolation,
            started: Mutex::new(None),
        }
    }
}

impl RawDispatch {
    /// Checks and starts the call's permit, before any byte leaves: a lease
    /// this run did not issue, one closed or already used, or one admitted
    /// for other bytes or another offer is refused. It starts once.
    ///
    /// # Errors
    ///
    /// The run's refusal, as the model error it reads as.
    pub fn start(&self) -> LlmResult<()> {
        let mut started = self.started.lock().unwrap_or_else(PoisonError::into_inner);
        if started.is_some() {
            return Err(FatalLlmError::InvalidRequest.into());
        }
        self.run.begin_dispatch(&self.lease, &self.call)?;
        *started = Some(Dispatch {
            lease: self.lease.clone(),
            model: self.model.clone(),
            digest: self.digest.clone(),
            broker_isolation: self.isolation,
        });
        Ok(())
    }

    /// Whether the permit started: the call may have left.
    #[must_use]
    pub fn started(&self) -> bool {
        self.started
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }

    /// Writes the call's dispatch receipt, once it started: whether the
    /// provider answered it, and the model it said it served. A second end
    /// writes nothing.
    pub fn finish(&self, served_model: Option<String>, answered: bool) {
        let dispatch = self
            .started
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(dispatch) = dispatch {
            self.run
                .dispatched(dispatch, &self.call.route, served_model, answered);
        }
    }
}

impl Drop for RawDispatch {
    fn drop(&mut self) {
        self.finish(None, false);
    }
}
