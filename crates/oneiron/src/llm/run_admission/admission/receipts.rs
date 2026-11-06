//! Admission and terminal receipts share one original clock-stamped value.
use super::{CallFacts, ModelId, RunDenied, RunInner, RunPermit};
use crate::llm::run_admission::{RunEvent, RunReceipt};

impl RunInner {
    pub(super) fn receipt_for(
        &self,
        revision: u32,
        selector: Option<&str>,
        subject: &str,
        admitted: Result<RunPermit, RunDenied>,
        model: Option<ModelId>,
    ) -> Result<RunPermit, RunDenied> {
        let admitted = admitted.and_then(|mut permit| match self.freeze_allocation(&mut permit) {
            Ok(receipt) => Ok((permit, receipt)),
            Err(error) => {
                permit.discard_unadmitted();
                Err(error)
            }
        });
        match admitted {
            Ok((permit, receipt)) => {
                if let Some(model) = model {
                    self.lock_calls().insert(
                        permit.lease.id().to_owned(),
                        CallFacts {
                            revision,
                            model,
                            request_digest: None,
                            served_model: None,
                            settled_units: None,
                        },
                    );
                } else {
                    self.lock_paid().insert(permit.lease.id().to_owned());
                }
                if let Some(hold) = &permit.persistent_allocation
                    && hold.overdraft_units > 0
                    && let Some(resident) = hold.resident
                {
                    self.record(
                        revision,
                        RunEvent::ResidentOverdraft {
                            lease: hold.key.lease.clone(),
                            resident,
                            allocation: hold.allocation.clone(),
                            share_units: hold.resident_share_units,
                            used_units: hold.resident_committed_units,
                            overdraft_units: hold.overdraft_units,
                        },
                    );
                }
                self.publish_receipt(receipt);
                Ok(permit)
            }
            Err(reason) => {
                self.record(
                    revision,
                    RunEvent::Denied {
                        selector: selector.map(str::to_owned),
                        subject: Some(subject.to_owned()),
                        lease: None,
                        reason: reason.clone(),
                    },
                );
                if let RunDenied::Budget { denied } = &reason {
                    self.budget_hit(subject, &self.guard, denied);
                }
                Err(reason)
            }
        }
    }

    pub(in crate::llm::run_admission) fn receipt(
        &self,
        revision: u32,
        event: RunEvent,
    ) -> RunReceipt {
        RunReceipt {
            instance: self.instance,
            occurred_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs()),
            run: self.run.clone(),
            revision,
            event,
        }
    }

    pub(in crate::llm::run_admission) fn record(&self, revision: u32, event: RunEvent) {
        self.publish_receipt(self.receipt(revision, event));
    }

    pub(in crate::llm::run_admission) fn publish_receipt(&self, receipt: RunReceipt) {
        publish_receipt_to(&self.receipts, receipt);
    }
}

pub(in crate::llm::run_admission) fn publish_receipt_to(
    sink: &std::sync::Arc<dyn super::RunReceiptSink>,
    receipt: RunReceipt,
) {
    if !std::thread::panicking() {
        sink.record(receipt);
        return;
    }
    // A permit's or a dispatch's drop during an unwind: a sink that
    // panics again must not abort the host. The meters are settled by now.
    let run = receipt.run.clone();
    let recorded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sink.record(receipt);
    }));
    if recorded.is_err() {
        tracing::error!(%run, "run receipt sink panicked during an unwind");
    }
}
