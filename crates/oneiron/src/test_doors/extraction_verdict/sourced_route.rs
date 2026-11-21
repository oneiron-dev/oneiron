//! Records the rows each fixture model call is sent under.
//!
//! A host lends each Dreamer role a route that can send one call bound to the rows its
//! input was read from. The parity fixture and the NOTE review door lend this one beside
//! their scripted backend: a bound call goes to the same backend, and the route keeps the
//! rows it was bound to, so a test reads what each read named. A call that names no
//! complete set never reaches the route and leaves no entry.

use std::sync::{Arc, Mutex, PoisonError};

use crate::dreamer_consolidation::SourcedBackend;
use crate::entity_id::EntityId;
use crate::{
    BudgetLease, LlmBackend, LlmCapability, LlmGenerateFuture, LlmRequest, LlmStreamResult, ModelId,
};

/// Holds the fixture's sourced route: the scripted backend with the rows of every call it
/// was asked to bind, in call order.
pub(in crate::test_doors) struct RecordingSourcedRoute {
    /// Answers every bound call, as it answers the unbound ones.
    backend: Arc<dyn LlmBackend>,
    /// Holds the rows of each bound call since the last take, in call order.
    bound: Mutex<Vec<Vec<EntityId>>>,
}

impl RecordingSourcedRoute {
    /// Builds the route over `backend` with no bound call recorded.
    pub(in crate::test_doors) fn new(backend: Arc<dyn LlmBackend>) -> Self {
        Self {
            backend,
            bound: Mutex::new(Vec::new()),
        }
    }

    /// Returns the rows of every call bound since the last take, in call order, and
    /// forgets them.
    pub(in crate::test_doors) fn take(&self) -> Vec<Vec<EntityId>> {
        std::mem::take(&mut *self.bound.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

impl SourcedBackend for RecordingSourcedRoute {
    /// Records `rows` and lends the scripted backend for the one call.
    fn sourced(&self, rows: Vec<EntityId>) -> Box<dyn LlmBackend + '_> {
        self.bound
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(rows);
        Box::new(BoundCall {
            backend: self.backend.as_ref(),
        })
    }
}

/// Sends one bound call on the scripted backend.
struct BoundCall<'r> {
    /// Borrows the scripted backend the route answers with.
    backend: &'r dyn LlmBackend,
}

impl LlmBackend for BoundCall<'_> {
    fn supports(&self, model: &ModelId, capability: LlmCapability) -> bool {
        self.backend.supports(model, capability)
    }

    fn generate<'a>(
        &'a self,
        request: LlmRequest,
        lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        self.backend.generate(request, lease)
    }

    fn stream<'a>(&'a self, request: LlmRequest, lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        self.backend.stream(request, lease)
    }
}
