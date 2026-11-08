//! One owner-requested sweep that joined running work (FIX 7552): a
//! manual run-now or an intake the owner's standing policy enabled.
//! Waiting work covers the request; running work owes one later ordinary
//! sweep. The native queue owns its state and dedupe, not this marker.

use super::COACH_FEEDBACK_SWEEP_FACET;
use crate::attempt_queue::{AttemptRecord, AttemptState};
use crate::dreamer_runner::maintenance::coach::COACH_HOST_QUEUE_KIND;
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerAttemptStatus, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    decode_dreamer_attempt_payload,
};
use crate::side_table::{self, Named, SideTable};
use crate::{Error, Result, Vault};

const PENDING: SideTable<(), (), Named> = SideTable::new(&side_table::COACH_FEEDBACK_SWEEP_PENDING);

fn enqueue(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<EnqueueDreamerAttemptOutcome> {
    DreamerRunnerStore::new(vault).enqueue_kind_in_txn(
        txn,
        COACH_HOST_QUEUE_KIND,
        DreamerAttemptPayload {
            attempt_type: COACH_FEEDBACK_SWEEP_FACET.into(),
            input: rmpv::Value::Nil,
            parent_attempt: None,
        },
        Some(COACH_FEEDBACK_SWEEP_FACET.into()),
        None,
        now,
    )
}

fn covers_request(outcome: &EnqueueDreamerAttemptOutcome) -> bool {
    match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(_) => true,
        EnqueueDreamerAttemptOutcome::Existing(status) => matches!(
            status.attempt.state,
            AttemptState::Queued | AttemptState::Paused | AttemptState::Scheduled
        ),
    }
}

/// The owner's ordinary enqueue, retaining only a request that running work
/// cannot cover. The same write revalidates a manual owner's proof or reads
/// the owner's enabled standing intake policy.
pub(super) fn requested_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    now: u64,
) -> Result<DreamerAttemptStatus> {
    let outcome = enqueue(vault, txn, now)?;
    if covers_request(&outcome) {
        PENDING.delete(&vault.store, txn, &())?;
    } else if let EnqueueDreamerAttemptOutcome::Existing(status) = &outcome
        && status.attempt.state.is_running()
    {
        PENDING.put(&vault.store, txn, &(), &())?;
    }
    Ok(match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
    })
}

fn drain(vault: &Vault, txn: &mut heed::RwTxn<'_>, now: u64) -> Result<bool> {
    if PENDING.get(&vault.store, txn, &())?.is_none() {
        return Ok(false);
    }
    let outcome = enqueue(vault, txn, now)?;
    let covered = covers_request(&outcome);
    if covered {
        PENDING.delete(&vault.store, txn, &())?;
    }
    Ok(covered)
}

impl Vault {
    /// Called by the queue's terminal notification after dedupe release.
    /// Retry and handoff retain their key and never consume this intent.
    /// A failed savepoint keeps the request and never fails settlement.
    pub(crate) fn redrive_feedback_sweep_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        settled: &AttemptRecord,
    ) {
        if settled.kind != COACH_HOST_QUEUE_KIND || !settled.state.is_terminal() {
            return;
        }
        let Ok(payload) = decode_dreamer_attempt_payload(&settled.payload) else {
            return;
        };
        if payload.attempt_type != COACH_FEEDBACK_SWEEP_FACET {
            return;
        }
        let queued = self
            .store
            .env
            .nested_write_txn(txn)
            .map_err(Error::from)
            .and_then(|mut savepoint| {
                let covered = drain(self, &mut savepoint, settled.updated_at)?;
                savepoint.commit().map_err(Error::from)?;
                Ok(covered)
            });
        match queued {
            Ok(true) => crate::batch::queue_proactivity_change(self, txn),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                attempt = %crate::entity_id::bytes_to_hex_lower(settled.id.as_bytes()),
                kind = ?error.kind(),
                "feedback sweep follow-up not queued"
            ),
        }
    }
}
