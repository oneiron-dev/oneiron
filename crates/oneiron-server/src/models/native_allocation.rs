//! The selected original backend and its usage-observing receipt sink.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use oneiron::llm::run_admission::{
    AllocationStoreError, BudgetLine, LeaseUnit, Payer, PayerPerson, PersistentAllocation,
    RunAdmission, RunAttribution, RunDeclaration, RunEvent, RunReceipt, RunReceiptSink,
    VaultAllocationLedger,
};
use oneiron::{BudgetExhaustionPolicy, BudgetGuard, EntityId};

use super::ServerReceipts;
use crate::runtime::{NativeUsageProducer, VaultUsage};

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

/// Shared only by future run factories. A constructed run keeps its original backend.
#[derive(Clone, Default)]
pub(crate) struct NativeUsageBinding {
    inner: Arc<NativeUsageSelection>,
}

#[derive(Default)]
struct NativeUsageSelection {
    selected: OnceLock<Arc<NativeUsage>>,
    installation: Mutex<()>,
}

impl NativeUsageBinding {
    pub(crate) fn current(&self) -> Option<Arc<NativeUsage>> {
        self.inner.selected.get().cloned()
    }

    pub(crate) fn installation(&self) -> MutexGuard<'_, ()> {
        self.inner
            .installation
            .lock()
            .expect("native usage installation lock poisoned")
    }

    pub(crate) fn publish(&self, native: Arc<NativeUsage>) {
        assert!(
            self.inner.selected.set(native).is_ok(),
            "native usage already bound"
        );
    }
}

pub(crate) struct NativeUsage {
    pub(crate) ledger: Arc<VaultAllocationLedger>,
    pub(crate) backend: Arc<PersistentAllocation>,
    pub(crate) producer: Arc<NativeUsageProducer>,
    receipts: Arc<NativeReceipts>,
}

impl NativeUsage {
    pub(crate) fn runs(&self) -> NativeRunAllocation {
        NativeRunAllocation::new(Arc::clone(&self.backend), self.receipts.clone())
    }

    pub(crate) fn new(
        usage: Arc<VaultUsage>,
        sink: Arc<ServerReceipts>,
    ) -> Result<Arc<Self>, AllocationStoreError> {
        let producer = usage.allocation_producer();
        let commit = VaultAllocationLedger::new(producer.vault())?;
        if commit.postcommit_error.is_some() {
            tracing::error!(
                revision = commit.revision,
                "native allocation binding committed before later vault work failed"
            );
        }
        let ledger = commit.value;
        let backend = PersistentAllocation::new(Arc::clone(&ledger), producer.clone());
        Ok(Arc::new(Self {
            ledger,
            backend,
            producer,
            receipts: Arc::new(NativeReceipts {
                sink,
                calls: Mutex::default(),
            }),
        }))
    }

    pub(crate) fn undeclared_run(&self, run: String, meter: BudgetGuard) -> RunAdmission {
        self.runs().funded_run(run, meter, None, None)
    }
}

// Only the native constructor above takes this sink. Host admissions with an
// allocation are its actual committed holds; free and memory-work calls have
// no hold and keep the ordinary usage path. The set only selects observation,
// never admission, money, or release of a hold.
struct NativeReceipts {
    sink: Arc<ServerReceipts>,
    calls: Mutex<BTreeSet<(EntityId, String)>>,
}

impl RunReceiptSink for NativeReceipts {
    fn record(&self, receipt: RunReceipt) {
        let native = match &receipt.event {
            RunEvent::Admitted(facts)
                if facts.payer == Payer::Host && facts.allocation.is_some() =>
            {
                self.calls
                    .lock()
                    .expect("native receipt calls lock poisoned")
                    .insert((receipt.instance, facts.lease.clone()));
                true
            }
            RunEvent::Settled { lease, .. } => self
                .calls
                .lock()
                .expect("native receipt calls lock poisoned")
                .remove(&(receipt.instance, lease.clone())),
            _ => false,
        };
        if native {
            self.sink.observe(receipt);
        } else {
            self.sink.record(receipt);
        }
    }

    fn budget_hit(&self, seat: &str, guard: &BudgetGuard, denied: &oneiron::llm::BudgetDenied) {
        self.sink.budget_hit(seat, guard, denied);
    }
}
