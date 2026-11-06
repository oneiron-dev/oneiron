//! The selected original backend and its usage-observing receipt sink.
use std::sync::Arc;

use oneiron::llm::run_admission::{
    BudgetLine, LeaseUnit, PayerPerson, PersistentAllocation, RunAdmission, RunAttribution,
    RunDeclaration, RunReceiptSink,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard};

#[derive(Clone)]
pub(crate) struct NativeRunAllocation {
    allocation: Arc<PersistentAllocation>,
    receipts: Arc<dyn RunReceiptSink>,
}

impl NativeRunAllocation {
    pub(crate) fn new(
        allocation: Arc<PersistentAllocation>,
        receipts: Arc<dyn RunReceiptSink>,
    ) -> Self {
        Self {
            allocation,
            receipts,
        }
    }

    pub(crate) fn funded_run(
        &self,
        run: impl Into<String>,
        meter: BudgetGuard,
        payer: Option<PayerPerson>,
        attribution: Option<RunAttribution>,
    ) -> RunAdmission {
        let line = BudgetLine {
            limit_units: meter.read().limit_units,
            reserve_units: meter.reserve_units(),
            unit: LeaseUnit::tokens(),
        };
        RunAdmission::with_persistent_allocation(
            run,
            RunDeclaration::undeclared(line),
            meter,
            Arc::clone(&self.allocation),
            Arc::clone(&self.receipts),
            payer,
            attribution,
        )
        .capturing_settlements()
    }

    pub(crate) fn declared_run(
        &self,
        run: impl Into<String>,
        declaration: RunDeclaration,
    ) -> RunAdmission {
        let run = run.into();
        let line = declaration.budget();
        let meter = BudgetGuard::with_reserve_units(
            run.clone(),
            line.limit_units,
            line.reserve_units,
            BudgetExhaustionPolicy::Suspend,
        );
        RunAdmission::with_persistent_allocation(
            run,
            declaration,
            meter,
            Arc::clone(&self.allocation),
            Arc::clone(&self.receipts),
            None,
            None,
        )
        .capturing_settlements()
    }
}
