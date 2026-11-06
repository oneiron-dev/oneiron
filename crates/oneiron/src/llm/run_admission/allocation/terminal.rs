//! Memory custody for native terminal writes that have not committed yet.
//! This is not a usage outbox: only the native hold's same-writer callback
//! stages the existing durable usage.pending settlement.
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use super::{AllocationCallKey, AllocationStoreError, AllocationTerminal, PersistentAllocation};
use crate::llm::run_admission::admission::publish_receipt_to;
use crate::llm::run_admission::{RunReceipt, RunReceiptSink};

pub(super) struct PendingTerminal {
    pub(super) key: AllocationCallKey,
    pub(super) terminal: AllocationTerminal,
    pub(super) receipt: RunReceipt,
    pub(super) calls: Arc<Mutex<BTreeSet<String>>>,
    pub(super) observer: Arc<dyn RunReceiptSink>,
}

impl PersistentAllocation {
    /// Retries each currently retained terminal once, with its original receipt,
    /// clock, digest and producer. No run, meter, resident or queue lock spans a
    /// vault write. Each queued call is taken by one drain at a time.
    ///
    /// On failure the exact original remains in memory and its durable hold
    /// remains pending. This does not recover terminals lost in a process crash.
    /// Receipt sinks are observers, not a second money settlement producer.
    pub fn retry_settlements(&self) -> Result<usize, AllocationStoreError> {
        let keys: Vec<_> = self
            .pending_terminals
            .lock()
            .expect("pending native terminal mutex poisoned")
            .keys()
            .cloned()
            .collect();
        let mut committed = 0;
        let mut first_error = None;
        for key in keys {
            let pending = self
                .pending_terminals
                .lock()
                .expect("pending native terminal mutex poisoned")
                .remove(&key);
            let Some(pending) = pending else { continue };
            match self.commit_terminal(&pending.key, &pending.terminal, &pending.receipt) {
                Ok(commit) => {
                    if commit.postcommit_error.is_some() {
                        tracing::error!(
                            revision = commit.revision,
                            "native terminal committed before later vault work failed"
                        );
                    }
                    pending
                        .calls
                        .lock()
                        .expect("persistent call mutex poisoned")
                        .remove(&pending.key.lease);
                    committed += 1;
                    publish_receipt_to(&pending.observer, pending.receipt);
                }
                Err(error) => {
                    self.pending_terminals
                        .lock()
                        .expect("pending native terminal mutex poisoned")
                        .entry(key)
                        .or_insert(pending);
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(committed),
        }
    }
}
