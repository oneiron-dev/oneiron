//! Atomic fire-once door from the due index to the Dreamer queue.

use heed::{RoTxn, RwTxn};

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::commitment::{
    CommitmentRecord, CommitmentStatus, CommitmentStrength, decode_commitment_claim,
};
use crate::dreamer_runner::{
    DreamerAttemptPayload, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome,
};
use crate::dreamer_wake::{WakeTrigger, request_wake_in_txn};
use crate::error::{Error, Result};

use super::wake_event::{CommitmentWakeDue, encode_commitment_wake_event};

// ---------------------------------------------------------------------------
// 2. Atomic fire-once door
// ---------------------------------------------------------------------------

/// The only shape of due-index access this module has.
///
/// ONE-1539 owns the rows and their keys; this trait is the narrow adapter
/// over its two crate-private transaction twins. Nothing here imports a key
/// prefix or writes a row directly.
pub(crate) trait CommitmentWakeIndexTxn {
    /// The earliest actionable `Lead`/`Due` phase, as a typed wake due.
    fn next_wake_due_in_txn(&self, txn: &RoTxn<'_>) -> Result<Option<CommitmentWakeDue>>;

    /// Acknowledges EXACTLY `due` — never "whatever is currently first".
    fn settle_wake_phase_in_txn(&self, txn: &mut RwTxn<'_>, due: &CommitmentWakeDue) -> Result<()>;
}

impl CommitmentWakeIndexTxn for Vault {
    fn next_wake_due_in_txn(&self, txn: &RoTxn<'_>) -> Result<Option<CommitmentWakeDue>> {
        let Some(entry) = self.next_actionable_wake_phase_in_txn(txn)? else {
            return Ok(None);
        };
        CommitmentWakeDue::from_due_entry(&entry)
    }

    fn settle_wake_phase_in_txn(&self, txn: &mut RwTxn<'_>, due: &CommitmentWakeDue) -> Result<()> {
        // Re-read rather than reconstruct: the owner's row carries a
        // `series_ref` and an occurrence this adapter's view deliberately does
        // not, so the only honest way to name the exact row is to read it and
        // check that it is still the one the caller was handed.
        let entry =
            self.next_actionable_wake_phase_in_txn(&*txn)?
                .ok_or(Error::InvariantViolation(
                    "commitment wake phase vanished inside its own transaction",
                ))?;
        if CommitmentWakeDue::from_due_entry(&entry)?.as_ref() != Some(due) {
            return Err(Error::InvariantViolation(
                "commitment wake phase changed inside its own transaction",
            ));
        }
        self.acknowledge_commitment_due_in_txn(txn, &entry)?;
        Ok(())
    }
}

/// What one [`fire_due_commitment_wake`] transaction did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommitmentWakeFireOutcome {
    /// A new durable Dreamer attempt exists and the phase is settled.
    Enqueued { attempt_id: AttemptId },
    /// The advisory dedupe key already named an attempt; the phase is settled
    /// in the same transaction, so this is progress, not a retry.
    Existing { attempt_id: AttemptId },
    /// Nothing was enqueued. Every variant but `Raced` settled the phase.
    Skipped(CommitmentWakeSkip),
}

/// Why a due phase produced no Dreamer attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommitmentWakeSkip {
    /// The exact due entry no longer matches the transaction's current
    /// minimum. Settles nothing and enqueues nothing; the competing writer
    /// owns progress and the caller simply re-reads.
    Raced,
    /// A missing instance acknowledges the exact stale phase before commit.
    MissingInstance,
    /// A non-open instance acknowledges the exact stale phase before commit.
    ClosedInstance,
    /// Retrieval-only strength acknowledges the exact phase without enqueueing.
    StatedIntention,
    /// Query-only strength acknowledges the exact phase without enqueueing.
    Decision,
}

/// Eligibility verdict for one instance, before any write happens.
pub(super) enum WakeEligibility {
    Eligible,
    Skip(CommitmentWakeSkip),
}

/// Fires ONE due commitment phase in ONE write transaction.
///
/// Order is load-bearing (blueprint §2):
///
/// 1. Re-read the current `Lead`/`Due` minimum. A miss is
///    [`CommitmentWakeSkip::Raced`]: it settles nothing and enqueues nothing,
///    because a stale caller must never settle a phase it did not see.
/// 2. Read the raw claim through the crate-private
///    `Vault::get_claim_in_txn` and type it with CMT-1's public
///    `decode_commitment_claim`. The PUBLIC `get_commitment_claim` opens a
///    nested read transaction, which is illegal under LMDB, and is therefore
///    never reachable from here.
/// 3. Ineligible instances acknowledge the exact phase and commit, so the
///    deadline-source read converges instead of busy-looping.
/// 4. An eligible instance enqueues one `Event`/MICRO attempt.
/// 5. The phase is acknowledged in the SAME transaction: any error before
///    commit persists neither the enqueue nor the phase advance.
///
/// This function never calls `schedule_outbound`. Its only eligible side
/// effect is the durable Dreamer enqueue.
pub fn fire_due_commitment_wake(
    vault: &Vault,
    due: CommitmentWakeDue,
    now: u64,
) -> Result<CommitmentWakeFireOutcome> {
    vault.with_write_txn(|wtxn| {
        if vault.next_wake_due_in_txn(&*wtxn)? != Some(due) {
            return Ok(CommitmentWakeFireOutcome::Skipped(
                CommitmentWakeSkip::Raced,
            ));
        }
        if let WakeEligibility::Skip(skip) = wake_eligibility_in_txn(vault, wtxn, &due)? {
            vault.settle_wake_phase_in_txn(wtxn, &due)?;
            return Ok(CommitmentWakeFireOutcome::Skipped(skip));
        }
        let outcome = enqueue_commitment_wake_in_txn(vault, wtxn, &due, now)?;
        vault.settle_wake_phase_in_txn(wtxn, &due)?;
        Ok(outcome)
    })
}

fn wake_eligibility_in_txn(
    vault: &Vault,
    wtxn: &RwTxn<'_>,
    due: &CommitmentWakeDue,
) -> Result<WakeEligibility> {
    let Some(body) = vault.get_claim_in_txn(wtxn, &due.instance_id)? else {
        return Ok(WakeEligibility::Skip(CommitmentWakeSkip::MissingInstance));
    };
    // A non-commitment claim at an instance ref is an index that outlived its
    // subject: the same fact a missing entity states, so it settles the same way.
    let Some(record) = decode_commitment_claim(&body)? else {
        return Ok(WakeEligibility::Skip(CommitmentWakeSkip::MissingInstance));
    };
    Ok(wake_eligibility(&record))
}

pub(super) fn wake_eligibility(record: &CommitmentRecord) -> WakeEligibility {
    if record.status != CommitmentStatus::Open {
        return WakeEligibility::Skip(CommitmentWakeSkip::ClosedInstance);
    }
    match record.strength {
        CommitmentStrength::Commitment => WakeEligibility::Eligible,
        CommitmentStrength::StatedIntention => {
            WakeEligibility::Skip(CommitmentWakeSkip::StatedIntention)
        }
        CommitmentStrength::Decision => WakeEligibility::Skip(CommitmentWakeSkip::Decision),
    }
}

fn enqueue_commitment_wake_in_txn(
    vault: &Vault,
    wtxn: &mut RwTxn<'_>,
    due: &CommitmentWakeDue,
    now: u64,
) -> Result<CommitmentWakeFireOutcome> {
    let key = due.idempotency_key();
    let payload = DreamerAttemptPayload {
        attempt_type: DreamerConsolidationScope::Micro.as_str().to_owned(),
        input: encode_commitment_wake_event(&due.event())?,
        parent_attempt: None,
    };
    // `WakeTrigger::Event` derives `DreamerConsolidationScope::Micro`: one due
    // phase is one small consolidation, never a Meso/Macro pass.
    let outcome = request_wake_in_txn(
        &DreamerRunnerStore::new(vault),
        wtxn,
        WakeTrigger::Event,
        payload,
        Some(key.clone()),
        Some(key),
        now,
    )?;
    Ok(match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(status) => CommitmentWakeFireOutcome::Enqueued {
            attempt_id: status.attempt.id,
        },
        EnqueueDreamerAttemptOutcome::Existing(status) => CommitmentWakeFireOutcome::Existing {
            attempt_id: status.attempt.id,
        },
    })
}
