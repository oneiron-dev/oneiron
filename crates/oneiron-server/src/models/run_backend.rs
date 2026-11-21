//! A ladder as an [`LlmBackend`], for engine code that calls a backend
//! itself (the Dreamer's step layer). Each call is admitted under the run on
//! its own permits and sent through the run's gate. The caller's lease is
//! the caller's own meter's business; this backend never dispatches on it.
//! A sourced call carries the rows its caller names in place of the run's
//! own (FIX 5760, 7104). A backend bound to the rows a call's input was read
//! from ([`SourceFence`]) sends nothing of that input once one of them is
//! withdrawn ([DREAMER-STEP-RESENDS-ERASED-SOURCE-WORDS]), and ends the
//! call with [`FatalLlmError::SourceWithdrawn`].
use std::sync::Arc;

use oneiron::code_run::source_rows_withdrawn;
use oneiron::llm::run_admission::RunAdmission;
use oneiron::llm::{FatalLlmError, LlmError, OwnedDispatchRelease};
use oneiron::{
    BudgetLease, EntityId, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, ModelId, Vault,
};

use super::OfferLadder;

/// The rows one call's input was read from, read again in their vault
/// before each rung, each wait slice and each resend of the call, and at
/// each physical send: once one is erased, deleted or withdrawn
/// ([`source_rows_withdrawn`]), its words, already in the request's bytes,
/// go out again to no provider and warm no prompt cache. Text sent before
/// is not recalled; a request built afresh from the rows that stand sends.
#[derive(Clone)]
pub struct SourceFence {
    vault: Arc<Vault>,
    rows: Arc<[EntityId]>,
}

impl SourceFence {
    #[must_use]
    pub fn new(vault: Arc<Vault>, rows: Vec<EntityId>) -> Self {
        Self {
            vault,
            rows: rows.into(),
        }
    }

    /// Whether every row still stands in the vault now.
    #[must_use]
    pub fn stands(&self) -> bool {
        !source_rows_withdrawn(&self.vault, &self.rows)
    }

    /// What a call bound to rows one of which is withdrawn ends with:
    /// [`FatalLlmError::SourceWithdrawn`], which no step retries and no
    /// deterministic fallback answers (REVIEW-10342), where an invalid
    /// request would read as a provider's failure.
    #[must_use]
    pub fn refusal() -> LlmError {
        LlmError::from(FatalLlmError::SourceWithdrawn)
    }

    /// `generated` as this fence ends it: a call that failed once one of the
    /// rows is withdrawn (refused by the ladder before a rung, in a wait or
    /// at a physical send) ends with [`Self::refusal`]; any other outcome
    /// stays as it came.
    ///
    /// # Errors
    /// [`Self::refusal`] for a failure after a row was withdrawn, else
    /// `generated`'s own error.
    pub fn failure_as_refusal<T>(&self, generated: oneiron::LlmResult<T>) -> oneiron::LlmResult<T> {
        match generated {
            Err(_) if !self.stands() => Err(Self::refusal()),
            generated => generated,
        }
    }

    /// The fence as a run's pre-send condition: a physical send, after any
    /// wait for a key or an offer, asks it again.
    #[must_use]
    pub fn release(&self) -> OwnedDispatchRelease {
        let fence = self.clone();
        Arc::new(move || {
            if fence.stands() {
                Ok(())
            } else {
                Err(Self::refusal())
            }
        })
    }
}

pub struct RunBackend {
    ladder: Arc<OfferLadder>,
    run: RunAdmission,
    fence: Option<SourceFence>,
}

impl RunBackend {
    #[must_use]
    pub fn new(ladder: Arc<OfferLadder>, run: RunAdmission) -> Self {
        Self {
            ladder,
            run,
            fence: None,
        }
    }

    /// This backend for calls whose input was read from `fence`'s rows:
    /// each call asks them first and sends nothing once one is withdrawn
    /// ([`SourceFence::refusal`]), the ladder asks them
    /// before each rung and through each wait, and the run's gate at each
    /// physical send.
    #[must_use]
    pub fn within_source_fence(self, fence: SourceFence) -> Self {
        Self {
            run: self.run.within_text_dispatch_release(fence.release()),
            ladder: self.ladder,
            fence: Some(fence),
        }
    }

    /// Whether this backend may send now: unfenced, or every row stands.
    fn may_send(&self) -> bool {
        self.fence.as_ref().is_none_or(SourceFence::stands)
    }

    /// One generation on `run`, fenced as this backend is.
    async fn generate_on(
        &self,
        run: &RunAdmission,
        request: LlmRequest,
    ) -> oneiron::LlmResult<oneiron::LlmResponse> {
        if !self.may_send() {
            return Err(SourceFence::refusal());
        }
        let may_send = || self.may_send();
        let generated = self
            .ladder
            .generate_while(run, request, None, &may_send)
            .await;
        match &self.fence {
            Some(fence) => fence.failure_as_refusal(generated),
            None => generated,
        }
    }
}

impl LlmBackend for RunBackend {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.ladder.supports(model, &capability)
    }

    fn generate<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmGenerateFuture<'a> {
        Box::pin(self.generate_on(&self.run, request))
    }

    fn generate_sourced<'a>(
        &'a self,
        request: LlmRequest,
        _: &'a BudgetLease,
        sources: Option<Vec<EntityId>>,
    ) -> LlmGenerateFuture<'a> {
        Box::pin(async move {
            let run = self.run.sourced(sources);
            self.generate_on(&run, request).await
        })
    }

    fn stream<'a>(&'a self, request: LlmRequest, _: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.ladder.stream(&self.run, request, None)
    }
}
