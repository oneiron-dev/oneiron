//! The sends of a try the owner stopped (FIX 7188).
//!
//! The owner's Stop of a held program's try (`release`) marks that try's own
//! sends still Pending Abandoned (`owner_stopped`), in the Stop's writer. Each
//! keeps its row, payload, binding and accounting, and one that may have
//! crossed the wire keeps that as possible delivery: nothing calls it done or
//! undelivered. The abandon runs in a savepoint: a ledger that refuses it
//! rolls back the savepoint alone, is logged, and the Stop commits, with the
//! abandon it owes marked in the same write (`stop_recovery`), which every
//! wake host retries at the vault's pace until it lands (FIX 7352). In the
//! same savepoint each of the try's Deferred sends whose remote task the host
//! polls is asked to stop (L8-29): the host's next pass sends its connector
//! one `tasks/cancel`, and the send stays Deferred until a poll reads the
//! task's end. No other try's sends are touched.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::outbound_intent_ledger::{
    IntentEscalationReason, IntentLedgerError, abandon_attempt_pending_intents_in_txn,
    request_attempt_remote_task_cancels_in_txn,
};

use super::stop_recovery::owe_in_txn;

/// In the owner's Stop writer (a held program's release, or a parked try's
/// stop in `park_release`), marks `attempt`'s Pending sends Abandoned and
/// asks its polled remote tasks to stop, in a savepoint. Never fails the
/// Stop: a refused abandon rolls back alone, is logged, and is owed in the
/// Stop's own write for every wake host to retry. A try with no Pending or
/// Deferred send is left as it is.
pub(in crate::dreamer_runner) fn abandon_stopped_sends_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    now: u64,
) {
    let abandoned = (|| -> Result<usize> {
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        let abandoned = abandon_sends_in_txn(vault, &mut savepoint, attempt, now)?;
        savepoint.commit()?;
        Ok(abandoned)
    })();
    match abandoned {
        Ok(0) => {}
        Ok(abandoned) => tracing::info!(
            attempt = %bytes_to_hex_lower(attempt.as_bytes()),
            abandoned,
            "the owner's stop abandoned the try's pending sends"
        ),
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                attempt = %bytes_to_hex_lower(attempt.as_bytes()),
                "the owner's stop did not abandon the try's pending sends; the stop commits \
                 and the abandon stays owed"
            );
            owe_in_txn(vault, wtxn, attempt, now);
        }
    }
}

/// `attempt`'s Pending sends marked Abandoned for the owner's Stop, and the
/// stop of its Deferred sends' polled remote tasks asked (L8-29), in
/// `wtxn`: how many it abandoned. A ledger failure surfaces as the engine's
/// own, or as a corrupt ledger row.
pub(super) fn abandon_sends_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    now: u64,
) -> Result<usize> {
    let abandoned = abandon_attempt_pending_intents_in_txn(
        vault,
        wtxn,
        attempt,
        IntentEscalationReason::OwnerStopped,
        now.saturating_mul(1_000),
    )
    .map_err(ledger_fault)?;
    let cancelled =
        request_attempt_remote_task_cancels_in_txn(vault, wtxn, attempt).map_err(ledger_fault)?;
    if cancelled > 0 {
        tracing::info!(
            attempt = %bytes_to_hex_lower(attempt.as_bytes()),
            cancelled,
            "the owner's stop asked the try's remote tasks to stop"
        );
    }
    Ok(abandoned)
}

/// A ledger failure as the engine's own, or as a corrupt ledger row.
fn ledger_fault(error: IntentLedgerError) -> Error {
    match error {
        IntentLedgerError::Engine(error) => error,
        _ => Error::CorruptedIndex("outbound intent ledger row"),
    }
}

/// The owner's Stop writer's step for `attempt`'s sends, in a writer of
/// its own: the door `test_doors::remote_task_cancel` opens for
/// oneiron-server's `tests/remote_task_cancel.rs` (L8-29).
///
/// # Errors
/// Storage faults.
#[cfg(oneiron_test_support)]
pub(crate) fn stop_sends_in_own_writer(vault: &Vault, attempt: AttemptId, now: u64) -> Result<()> {
    let mut wtxn = vault.store.env.write_txn()?;
    abandon_stopped_sends_in_txn(vault, &mut wtxn, attempt, now);
    wtxn.commit()?;
    Ok(())
}
