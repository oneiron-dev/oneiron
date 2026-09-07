use std::cell::Cell;
use std::sync::Arc;

use oneiron::Effort;
use oneiron::llm::{BudgetAdmission, BudgetGuard, BudgetLease};
use oneiron::retrieval_depth::DeepSearchBackend;

use super::MemoryReasonBackend;
use crate::error::ApiError;
use crate::server::SyncServer;

/// The deep-retrieval attachment: a host backend AND the budget that pays for
/// it.
///
/// The two are one value because they are one decision. A backend without a
/// guard would be a second executor spending outside the meter; a guard
/// without a backend would gate a tier that cannot run. `SyncServer::new`
/// attaches neither.
pub(crate) struct DeepRetrievalHost {
    pub(super) backend: Arc<dyn MemoryReasonBackend>,
    guard: BudgetGuard,
}

impl DeepRetrievalHost {
    /// Binds a backend to the budget guard that leases its spend.
    #[allow(dead_code)] // No in-tree production host yet; the tests are its only caller.
    pub(crate) fn new(backend: Arc<dyn MemoryReasonBackend>, guard: BudgetGuard) -> Self {
        Self { backend, guard }
    }
}

/// One admitted deep read: the lease, plus the host it was minted for.
pub(crate) struct DeepAdmission {
    pub(super) host: Arc<DeepRetrievalHost>,
    admission: BudgetAdmission,
    finalized: Cell<bool>,
    tokens_used: Cell<u64>,
}

impl DeepAdmission {
    pub(crate) fn lease(&self) -> &BudgetLease {
        &self.admission.lease
    }

    /// The retrieval half of the host, upcast to the seam the engine takes.
    pub(crate) fn search_backend(&self) -> &dyn DeepSearchBackend {
        self.host.backend.as_ref()
    }

    /// Records each stage's reported usage before any later fallible work.
    pub(crate) fn record_usage(&self, tokens_used: u64) {
        self.tokens_used
            .set(self.tokens_used.get().saturating_add(tokens_used));
    }

    /// Settles successful reads, and failed reads that consumed tokens, before
    /// returning either result. A zero-use failure is left for Drop to abort.
    pub(crate) fn finish<T>(&self, result: Result<T, ApiError>) -> Result<T, ApiError> {
        if result.is_ok() || self.tokens_used.get() != 0 {
            self.settle()?;
        }
        result
    }

    /// Adds this read's actual usage once and releases its reservation.
    /// Settlement failure blocks the response, including an otherwise usable
    /// answer; it must not be reduced to a warning and a successful read.
    pub(crate) fn settle(&self) -> Result<(), ApiError> {
        self.host
            .guard
            .settle_usage(&self.admission.lease, self.tokens_used.get())
            .map_err(|error| {
                tracing::warn!(?error, "deep retrieval lease settlement failed");
                ApiError::deep_retrieval_unavailable()
            })?;
        self.finalized.set(true);
        Ok(())
    }
}

impl Drop for DeepAdmission {
    fn drop(&mut self) {
        if self.finalized.get() {
            return;
        }
        // Never erase recorded spend with an abort, even during unwinding or
        // a failed explicit settlement. Settlement is idempotent.
        if self.tokens_used.get() != 0 {
            let _ = self.settle(); // Already logged; Drop cannot return an error.
        } else if let Err(error) = self.host.guard.abort(self.lease()) {
            tracing::warn!(?error, "deep retrieval lease abort failed");
        }
    }
}

/// Admits a deep read, or refuses it.
///
/// The non-deep tiers admit trivially with no host and no lease, which is what
/// makes `tokensUsed: 0` on those tiers a structural fact rather than a
/// promise: there is no meter to draw on.
pub(crate) fn admit_deep_retrieval(
    server: &SyncServer,
    effort: Effort,
) -> Result<Option<DeepAdmission>, ApiError> {
    if effort != Effort::Deep {
        return Ok(None);
    }
    let host = server
        .deep_retrieval
        .clone()
        .ok_or_else(ApiError::deep_retrieval_unavailable)?;
    // A guard that refuses admission mints no lease, and the engine's own
    // preflight refuses a leaseless deep read. Reported as the same
    // capability-absent 503 rather than as a budget code, because from the
    // caller's side the two are one fact — deep is not servable right now —
    // and the alternative would describe this server's spend state to a
    // caller that has no standing to know it.
    let admission = host.guard.admit().map_err(|error| {
        tracing::warn!(?error, "deep retrieval budget refused admission");
        ApiError::deep_retrieval_unavailable()
    })?;
    Ok(Some(DeepAdmission {
        host,
        admission,
        finalized: Cell::new(false),
        tokens_used: Cell::new(0),
    }))
}

#[cfg(test)]
mod tests;
