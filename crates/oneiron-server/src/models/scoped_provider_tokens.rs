//! Provider observations on the actual meter of a scoped code-mode call.

use std::sync::Arc;

use oneiron::agent_dispatch::{
    AgentDispatcher, ProviderLeaseTokenObservation, ProviderRunTokenObservation, SpendScopeId,
};
use oneiron::llm::run_admission::{PayerPerson, RunAdmission, RunReceipt, RunReceiptSink};
use oneiron::{AttemptId, BudgetGuard, Vault};

use super::ModelRuntime;

struct ScopedProviderTokens {
    vault: Arc<Vault>,
    scope: SpendScopeId,
    owner_attempt: Option<AttemptId>,
    guard: BudgetGuard,
    inner: Arc<dyn RunReceiptSink>,
}

impl ScopedProviderTokens {
    fn capture(&self, lease: &ProviderLeaseTokenObservation) {
        let snapshot = self.guard.provider_token_snapshot();
        if let Err(error) = AgentDispatcher::new(&self.vault).record_provider_lease_tokens(
            &self.scope,
            &snapshot,
            lease,
        ) {
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
        let lease = ProviderLeaseTokenObservation::from_receipt(&receipt, self.owner_attempt);
        self.inner.record(receipt);
        if let Some(lease) = lease {
            self.capture(&lease);
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
        owner_attempt: Option<AttemptId>,
    ) -> RunAdmission {
        let receipts = Arc::new(ScopedProviderTokens {
            vault,
            scope,
            owner_attempt,
            guard: meter.clone(),
            inner: Arc::clone(&self.receipts),
        });
        let run = super::raw::funded_run(run, meter, self.host.clone(), receipts.clone(), payer);
        record_model_stage(&receipts.vault, &receipts.scope, &run, owner_attempt, false);
        run
    }
}

/// The scoped code-mode ladder future returned. This is not a run seal or
/// a promise that no clone can admit more work or that all requests reported.
pub(crate) fn record_scoped_model_return(
    vault: &Vault,
    scope: &SpendScopeId,
    run: &RunAdmission,
    owner_attempt: Option<AttemptId>,
) {
    record_model_stage(vault, scope, run, owner_attempt, true);
}

fn record_model_stage(
    vault: &Vault,
    scope: &SpendScopeId,
    run: &RunAdmission,
    owner_attempt: Option<AttemptId>,
    model_future_returned: bool,
) {
    let snapshot = run.provider_token_snapshot();
    let observation = ProviderRunTokenObservation {
        instance: run.instance(),
        owner_attempt,
        entry_recorded: !model_future_returned,
        model_future_returned,
    };
    if let Err(error) =
        AgentDispatcher::new(vault).record_provider_run_tokens(scope, &snapshot, &observation)
    {
        tracing::warn!(
            kind = ?error.kind(),
            scope = scope.as_str(),
            "a scoped model call's source stage was not recorded"
        );
    }
}
