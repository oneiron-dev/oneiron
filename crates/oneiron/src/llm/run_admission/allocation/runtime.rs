//! Explicit run binding for the native allocation ledger. The producer uses
//! the ledger's caller-owned writer, never the non-authoritative receipt sink.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::{
    AllocationCallContext, AllocationCallKey, AllocationCommit, AllocationStoreError,
    AllocationTerminal, DurableAllocationHold, VaultAllocationLedger,
};
use crate::llm::run_admission::admission::RunInner;
use crate::llm::run_admission::permit::RunPermit;
use crate::llm::run_admission::{Payer, RunDenied, RunEvent, RunReceipt};

/// The host's original admitted producer and existing settlement pipeline.
/// Implementations persist under their actual source-custody/erase contract;
/// these methods may only use the supplied writer, not acquire another one.
pub trait AllocationProducer: Send + Sync {
    fn freeze_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        admitted: &RunReceipt,
        context: &AllocationCallContext,
    ) -> Result<(), AllocationStoreError>;

    /// Called only by the durable hold's once-selected terminal transition.
    /// Stage the existing usage.pending from the original frozen admission
    /// and this exact receipt, including its clock and stable event identity.
    fn settle_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        terminal: &RunReceipt,
    ) -> Result<(), AllocationStoreError>;

    /// Releases memory-only producer facts only after the original hold and
    /// usage transaction committed. No vault writer is held here.
    fn terminal_committed(&self, _terminal: &RunReceipt) {}
}

/// A caller's original durable intent, committed with its native hold and
/// the original admitted usage producer. Implementations use only `txn` and
/// retain the hold's original call key, not a reflected copy of its money.
pub trait AllocationCallIntent: Send + Sync {
    fn freeze_in_write_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        hold: &DurableAllocationHold,
        admitted: &RunReceipt,
    ) -> Result<(), AllocationStoreError>;
}

/// An explicit backend selection, not a grant or a reflected balance. Grant,
/// status and retirement remain operations on the same native ledger.
pub struct PersistentAllocation {
    pub(super) ledger: Arc<VaultAllocationLedger>,
    producer: Arc<dyn AllocationProducer>,
    pub(super) pending_terminals:
        Mutex<BTreeMap<(crate::EntityId, String), super::terminal::PendingTerminal>>,
}

impl PersistentAllocation {
    #[must_use]
    pub fn new(
        ledger: Arc<VaultAllocationLedger>,
        producer: Arc<dyn AllocationProducer>,
    ) -> Arc<Self> {
        Arc::new(Self {
            ledger,
            producer,
            pending_terminals: Mutex::new(BTreeMap::new()),
        })
    }

    pub(super) fn commit_terminal(
        &self,
        key: &AllocationCallKey,
        terminal: &AllocationTerminal,
        receipt: &RunReceipt,
    ) -> Result<AllocationCommit<()>, AllocationStoreError> {
        let commit = self.ledger.settle(key, terminal.clone(), |txn, _, _| {
            self.producer.settle_in_write_txn(txn, receipt)
        })?;
        self.producer.terminal_committed(receipt);
        Ok(commit)
    }
}

impl RunInner {
    /// No run, meter or resident lock is held across the native writer.
    pub(in crate::llm::run_admission) fn freeze_allocation(
        &self,
        permit: &mut RunPermit,
        intent: Option<&dyn AllocationCallIntent>,
    ) -> Result<RunReceipt, RunDenied> {
        let Some(account) = self
            .persistent_allocation
            .as_ref()
            .filter(|_| permit.facts.payer == Payer::Host && !self.memory_work())
        else {
            return Ok(self.receipt(
                permit.revision,
                RunEvent::Admitted(Box::new(permit.facts.clone())),
            ));
        };
        let key = AllocationCallKey {
            instance: self.instance(),
            lease: permit.lease.id().to_owned(),
        };
        let resident = permit
            .facts
            .initiator
            .or_else(|| permit.facts.attribution.as_ref().map(|bound| bound.agent));
        let line_source = self.guard.reservation_source(&permit.lease);
        let reserve = account.ledger.reserve(
            key,
            permit.reserve_native,
            &permit.native,
            &permit.rates,
            resident,
            |txn, hold| {
                let mut facts = permit.facts.clone();
                facts.allocation = Some(hold.allocation.clone());
                facts.allocation_unit = Some(hold.unit.clone());
                facts.allocation_reserved_units = Some(hold.reserved_units);
                let receipt = self.receipt(permit.revision, RunEvent::Admitted(Box::new(facts)));
                let context = AllocationCallContext {
                    run: receipt.run.clone(),
                    revision: receipt.revision,
                    admitted_occurred_at: receipt.occurred_at,
                    native: permit.native.clone(),
                    unit_cost: permit.unit_cost,
                    reserve_native: permit.reserve_native,
                    rates: permit.rates.clone(),
                    metered: permit.metered,
                    line_source,
                };
                account
                    .producer
                    .freeze_in_write_txn(txn, &receipt, &context)?;
                if let Some(intent) = intent {
                    intent.freeze_in_write_txn(txn, hold, &receipt)?;
                }
                Ok(receipt)
            },
        );
        let commit = reserve.map_err(|error| allocation_denied("reserve", error))?;
        let (hold, receipt) = committed("reserve", commit);
        if let RunEvent::Admitted(facts) = &receipt.event {
            permit.facts = *facts.clone();
        }
        permit.persistent_allocation = Some(hold);
        self.persistent_calls
            .lock()
            .expect("persistent call mutex poisoned")
            .insert(permit.lease.id().to_owned());
        Ok(receipt)
    }

    pub(in crate::llm::run_admission) fn start_allocation(
        &self,
        lease: &str,
    ) -> Result<(), RunDenied> {
        let persistent = self
            .persistent_calls
            .lock()
            .expect("persistent call mutex poisoned")
            .contains(lease);
        if !persistent {
            return Ok(());
        }
        let account = self
            .persistent_allocation
            .as_ref()
            .expect("a persistent call has its original backend");
        let commit = account
            .ledger
            .begin_dispatch(&AllocationCallKey {
                instance: self.instance(),
                lease: lease.to_owned(),
            })
            .map_err(|error| allocation_denied("dispatch", error))?;
        committed("dispatch", commit);
        Ok(())
    }

    pub(in crate::llm::run_admission) fn settle_allocation(
        &self,
        hold: &DurableAllocationHold,
        receipt: &RunReceipt,
        units: u64,
        dispatched: bool,
    ) -> Result<(), RunDenied> {
        let account = self
            .persistent_allocation
            .as_ref()
            .expect("a persistent hold has its original backend");
        let bytes = serde_json::to_vec(receipt).map_err(|_| RunDenied::AllocationStorage {
            operation: "terminal_receipt",
        })?;
        let terminal = AllocationTerminal {
            occurred_at: receipt.occurred_at,
            receipt_digest: *blake3::hash(&bytes).as_bytes(),
            receipt_json: bytes,
            dispatched,
            units,
        };
        let commit = match account.commit_terminal(&hold.key, &terminal, receipt) {
            Ok(commit) => commit,
            Err(error) => {
                let pending = super::terminal::PendingTerminal {
                    key: hold.key.clone(),
                    terminal,
                    receipt: receipt.clone(),
                    calls: Arc::clone(&self.persistent_calls),
                    observer: Arc::clone(&self.receipts),
                };
                account
                    .pending_terminals
                    .lock()
                    .expect("pending native terminal mutex poisoned")
                    .entry((hold.key.instance, hold.key.lease.clone()))
                    .or_insert(pending);
                return Err(allocation_denied("settle", error));
            }
        };
        committed("settle", commit);
        self.persistent_calls
            .lock()
            .expect("persistent call mutex poisoned")
            .remove(&hold.key.lease);
        Ok(())
    }
}

fn allocation_denied(operation: &'static str, error: AllocationStoreError) -> RunDenied {
    match error {
        AllocationStoreError::NoAllocation => RunDenied::NoAllocation,
        AllocationStoreError::Exhausted => RunDenied::AllocationExhausted,
        AllocationStoreError::AllocationRefused { reason } => {
            RunDenied::AllocationRefused { reason }
        }
        AllocationStoreError::UnitMismatch { from, to } => RunDenied::UnitMismatch { from, to },
        AllocationStoreError::ResidentShareSpent { resident } => {
            RunDenied::ResidentShareSpent { resident }
        }
        _ => RunDenied::AllocationStorage { operation },
    }
}

// The value is authoritative once committed. A later vault error cannot
// unreserve, reissue, re-clock or prevent a physical start already committed.
fn committed<T>(operation: &'static str, commit: AllocationCommit<T>) -> T {
    if commit.postcommit_error.is_some() {
        tracing::error!(
            operation,
            revision = commit.revision,
            "allocation committed before later vault work failed"
        );
    }
    commit.value
}
