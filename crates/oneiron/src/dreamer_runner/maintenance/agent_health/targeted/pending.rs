//! Retained live health wakes when both generation-pinned review slots run.

use serde::{Deserialize, Serialize};

use super::{
    COACH_AGENT_HEALTH_FACET, HealthReviewInput, LIVE_KEY, agent_work, decode, enqueue, skipped,
    soft,
};
use crate::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord};
use crate::dreamer_runner::maintenance::MAINTENANCE_QUEUE_KIND;
use crate::dreamer_runner::{EnqueueDreamerAttemptOutcome, decode_dreamer_attempt_payload};
use crate::entity_id::bytes_to_hex_lower;
use crate::side_table::{self, Named, SideTable};
use crate::{ErrorKind, Result, Vault};

type PendingKey = ([u8; 16], [u8; 4]);

#[derive(Serialize, Deserialize)]
struct PendingWake {
    wake: AttemptId,
    run_id: Option<String>,
}

const PENDING: SideTable<PendingKey, PendingWake, Named> =
    SideTable::new(&side_table::COACH_AGENT_HEALTH_LIVE_PENDING);

/// Queues or joins a waiting review, or retains the latest wake while both
/// slots run. The caller keeps this inside the wake's health savepoint.
pub(super) fn enqueue_or_retain(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    generation: u32,
    wake: &AttemptRecord,
    now: u64,
) -> Result<()> {
    let key = (*attempt.as_bytes(), generation.to_be_bytes());
    let wake = PendingWake {
        wake: wake.id,
        run_id: wake.run_id.clone(),
    };
    if queue_live(vault, txn, attempt, generation, &wake, now)? {
        PENDING.delete(&vault.store, txn, &key)?;
    } else {
        PENDING.put(vault, txn, &key, &wake)?;
    }
    Ok(())
}

/// Runs after the settling review releases its dedupe slot, in the same
/// writer. A waiting successor, not the old review's finish, covers the wake.
pub(super) fn drain(vault: &Vault, txn: &mut heed::RwTxn<'_>, settled: &AttemptRecord) {
    if settled.kind != MAINTENANCE_QUEUE_KIND {
        return;
    }
    let Ok(payload) = decode_dreamer_attempt_payload(&settled.payload) else {
        return;
    };
    if payload.attempt_type != COACH_AGENT_HEALTH_FACET {
        return;
    }
    let Ok(HealthReviewInput::Live {
        attempt,
        generation,
        ..
    }) = decode(&payload.input)
    else {
        return;
    };
    let key = (*attempt.as_bytes(), generation.to_be_bytes());
    let wake = match PENDING.get(&vault.store, txn, &key) {
        Ok(Some(wake)) => wake,
        Ok(None) => return,
        Err(error) => {
            skipped(attempt, &error);
            return;
        }
    };
    soft(vault, txn, attempt, |savepoint| {
        let live = match AttemptQueue::new(vault).get_in_txn(savepoint, attempt) {
            Ok(Some(record)) => {
                record.state.is_running()
                    && record.attempt_count == generation
                    && agent_work(&record)
            }
            Ok(None) => false,
            Err(error) if error.kind() == ErrorKind::ResponseErased => false,
            Err(error) => return Err(error),
        };
        if !live
            || queue_live(
                vault,
                savepoint,
                attempt,
                generation,
                &wake,
                settled.updated_at,
            )?
        {
            PENDING.delete(&vault.store, savepoint, &key)?;
        }
        Ok(())
    });
}

fn waiting(outcome: EnqueueDreamerAttemptOutcome) -> bool {
    match outcome {
        EnqueueDreamerAttemptOutcome::Enqueued(_) => true,
        EnqueueDreamerAttemptOutcome::Existing(status) => !status.attempt.state.is_running(),
    }
}

/// Uses only the two existing keys. A running row covers no new wake.
fn queue_live(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    generation: u32,
    wake: &PendingWake,
    now: u64,
) -> Result<bool> {
    let slot = format!(
        "{LIVE_KEY}:{}:{generation}",
        bytes_to_hex_lower(attempt.as_bytes())
    );
    let next = format!("{slot}:next");
    // FIX 9223: the waiting :next covers this wake; never queue ahead of it.
    if AttemptQueue::new(vault)
        .pending_dedupe_in_txn(txn, MAINTENANCE_QUEUE_KIND, &next)?
        .is_some_and(|pending| !pending.state.is_running())
    {
        return Ok(true);
    }
    let input = HealthReviewInput::Live {
        attempt,
        wake: wake.wake,
        generation,
    };
    let queue = |txn: &mut heed::RwTxn<'_>, key| {
        enqueue(
            vault,
            txn,
            &input,
            Some(wake.wake),
            key,
            wake.run_id.clone(),
            now,
        )
    };
    if waiting(queue(txn, slot)?) {
        return Ok(true);
    }
    Ok(waiting(queue(txn, next)?))
}
