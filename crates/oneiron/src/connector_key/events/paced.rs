//! Connector event wakes a full count-bound budget window paces (FIX 8686).
//! The wake is not refused: its event waits, uncharged, as one admission
//! item on the attempt queue, due when the window opens. The connector
//! settle pass claims due items and admits each wake again in one writer:
//! the charge, the Dreamer wake (or a new deferral, if the window is still
//! full) and the subscription's decision, which it overwrites. The item has
//! no deadline of its own; it lasts until it is admitted or its subscription
//! is gone.

use serde::{Deserialize, Serialize};

use super::{ConnectorEvent, ConnectorWakeDecision, subscriptions};
use crate::attempt_queue::{
    AttemptQueue, ClaimAttempt, ClaimOutcome, CompleteAttempt, CompleteOutcome, EnqueueAttempt,
    EnqueueOutcome,
};
use crate::{EntityId, Error, Result, Vault};

/// The attempt-queue kind of a paced connector wake's admission item.
pub(crate) const CONNECTOR_WAKE_ADMISSION_KIND: &str = "connector_key.wake_admission";
const CONNECTOR_WAKE_ADMISSION_LEASE_OWNER: &str = "connector-wake-admission";

/// One paced wake: the subscription it matched and the event, frozen.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PacedConnectorWake {
    #[serde(with = "crate::serialize::entity_ref")]
    subscription: EntityId,
    event: ConnectorEvent,
}

impl Vault {
    /// Keeps `event`'s wake of `subscription` as an admission item due at
    /// `due`, Unix seconds, in the ingress writer.
    pub(super) fn defer_connector_wake_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        subscription: EntityId,
        event: &ConnectorEvent,
        due: u64,
        now: u64,
    ) -> Result<()> {
        let payload = serde_json::to_vec(&PacedConnectorWake {
            subscription,
            event: event.clone(),
        })
        .map_err(|_| Error::InvariantViolation("paced connector wake did not encode"))?;
        let queue = AttemptQueue::new(self);
        let (EnqueueOutcome::Enqueued(record) | EnqueueOutcome::Existing(record)) = queue
            .enqueue_with_task_ref_and_dedupe_actor_in_txn(
                txn,
                EnqueueAttempt {
                    kind: CONNECTOR_WAKE_ADMISSION_KIND.to_owned(),
                    payload,
                    dedupe_key: None,
                    run_id: None,
                    now,
                },
                None,
                None,
            )?;
        queue.defer_enqueued_in_txn(txn, record, due)?;
        Ok(())
    }

    /// Admits again every paced connector wake whose window has opened, and
    /// returns how many it admitted (deferred again or not). Each claimed
    /// item completes in the writer that admits its wake, so a crash leaves
    /// it for the next pass.
    ///
    /// # Errors
    /// Storage faults.
    pub fn continue_paced_connector_wakes(&self) -> Result<usize> {
        let queue = AttemptQueue::new(self);
        let mut admitted = 0;
        loop {
            let now = crate::unix_seconds_now();
            let attempt = match queue.claim_kind(
                CONNECTOR_WAKE_ADMISSION_KIND,
                ClaimAttempt {
                    lease_owner: CONNECTOR_WAKE_ADMISSION_LEASE_OWNER.to_owned(),
                    now,
                },
            )? {
                ClaimOutcome::Empty => break,
                ClaimOutcome::Claimed(attempt) => attempt,
            };
            let decision = self.with_write_txn_grouped(|txn| {
                let completed = crate::ports::JobQueue::port_job_complete(
                    self,
                    txn,
                    CompleteAttempt {
                        id: attempt.id,
                        lease_owner: CONNECTOR_WAKE_ADMISSION_LEASE_OWNER.to_owned(),
                        attempt_count: attempt.attempt_count,
                        now,
                    },
                )?;
                if matches!(completed, CompleteOutcome::AlreadyCompleted(_)) {
                    return Ok(None);
                }
                // An item that does not decode, or whose subscription is
                // gone, inactive or awaiting its owner's confirmation,
                // completes with nothing to wake.
                let Ok(paced) = serde_json::from_slice::<PacedConnectorWake>(&attempt.payload)
                else {
                    return Ok(None);
                };
                let Some((id, row)) = subscriptions(&self.store, &*txn)?
                    .into_iter()
                    .find(|(id, row)| *id == paced.subscription && row.active)
                else {
                    return Ok(None);
                };
                if !crate::gate::claim_critical_confirm_settled_in_txn(&self.store, &*txn, &id)? {
                    return Ok(None);
                }
                let frozen = serde_json::to_vec(&paced.event).map_err(|_| {
                    Error::InvariantViolation("paced connector event did not encode")
                })?;
                let event_hash = blake3::hash(&frozen).to_hex().to_string();
                self.wake_subscription_in_txn(
                    txn,
                    id,
                    &row,
                    &paced.event,
                    &frozen,
                    &event_hash,
                    now,
                )
                .map(Some)
            })?;
            if let Some(decision) = decision {
                self.signal_connector_wakes(std::slice::from_ref::<ConnectorWakeDecision>(
                    &decision,
                ));
                admitted += 1;
            }
        }
        Ok(admitted)
    }
}
