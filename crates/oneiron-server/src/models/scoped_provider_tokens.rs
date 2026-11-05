//! Provider observations on the actual meter of a scoped code-mode call.

use std::sync::Arc;

use oneiron::agent_dispatch::{AgentDispatcher, ProviderLeaseTokenObservation, SpendScopeId};
use oneiron::llm::run_admission::{PayerPerson, RunAdmission, RunReceipt, RunReceiptSink};
use oneiron::{BudgetGuard, Vault};

use super::ModelRuntime;

struct ScopedProviderTokens {
    vault: Arc<Vault>,
    scope: SpendScopeId,
    guard: BudgetGuard,
    inner: Arc<dyn RunReceiptSink>,
}

impl ScopedProviderTokens {
    fn capture(&self, lease: Option<&ProviderLeaseTokenObservation>) {
        let snapshot = self.guard.provider_token_snapshot();
        let dispatcher = AgentDispatcher::new(&self.vault);
        let recorded = match lease {
            Some(lease) => dispatcher.record_provider_lease_tokens(&self.scope, &snapshot, lease),
            None => dispatcher.record_provider_token_snapshot(&self.scope, &snapshot),
        };
        if let Err(error) = recorded {
            tracing::warn!(
                kind = ?error.kind(),
                scope = self.scope.as_str(),
                "a scoped model call's provider observation was not recorded"
            );
        }
    }
}

impl RunReceiptSink for ScopedProviderTokens {
    fn record(&self, receipt: RunReceipt) {
        let lease = ProviderLeaseTokenObservation::from_receipt(&receipt);
        self.inner.record(receipt);
        if let Some(lease) = lease {
            self.capture(Some(&lease));
        }
    }

    fn budget_hit(&self, seat: &str, guard: &BudgetGuard, denied: &oneiron::llm::BudgetDenied) {
        self.inner.budget_hit(seat, guard, denied);
    }
}

impl ModelRuntime {
    /// The ordinary funded run with observations on its actual native scope.
    /// Construction records entry into the model-call path, not a sent call.
    /// Later receipts can mark one native permit's end, never the whole run's.
    pub(crate) fn funded_run_on_scope(
        &self,
        run: impl Into<String>,
        meter: BudgetGuard,
        payer: Option<PayerPerson>,
        vault: Arc<Vault>,
        scope: SpendScopeId,
    ) -> RunAdmission {
        let receipts = Arc::new(ScopedProviderTokens {
            vault,
            scope,
            guard: meter.clone(),
            inner: Arc::clone(&self.receipts),
        });
        receipts.capture(None);
        super::raw::funded_run(run, meter, self.host.clone(), receipts, payer)
    }
}
