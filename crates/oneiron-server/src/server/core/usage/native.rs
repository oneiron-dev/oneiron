//! Explicit native allocation selection; ordinary server construction is unchanged.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use oneiron::llm::run_admission::{
    AllocationStoreError, BudgetLine, LeaseUnit, Payer, PersistentAllocation, RunAdmission,
    RunDeclaration, RunEvent, RunReceipt, RunReceiptSink, VaultAllocationLedger,
};
use oneiron::{BudgetGuard, EntityId, Vault};

use crate::models::ServerReceipts;
use crate::runtime::{NativeUsageProducer, VaultUsage};

pub(in crate::server::core) struct NativeUsage {
    pub(in crate::server::core) ledger: Arc<VaultAllocationLedger>,
    pub(in crate::server::core) backend: Arc<PersistentAllocation>,
    pub(in crate::server::core) producer: Arc<NativeUsageProducer>,
    receipts: Arc<NativeReceipts>,
}

impl NativeUsage {
    pub(in crate::server::core) fn new(
        vault: Arc<Vault>,
        usage: Arc<VaultUsage>,
        sink: Arc<ServerReceipts>,
    ) -> Result<Arc<Self>, AllocationStoreError> {
        let commit = VaultAllocationLedger::new(vault)?;
        if commit.postcommit_error.is_some() {
            tracing::error!(
                revision = commit.revision,
                "native allocation binding committed before later vault work failed"
            );
        }
        let ledger = commit.value;
        let producer = usage.allocation_producer();
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

    pub(in crate::server::core) fn undeclared_run(
        &self,
        run: String,
        meter: BudgetGuard,
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
            Arc::clone(&self.backend),
            self.receipts.clone(),
            None,
            None,
        )
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
