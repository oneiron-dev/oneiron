//! The sends of a try the owner stopped (FIX 7188).
//!
//! The owner's Stop of a held program's try (`release`) marks that try's own
//! sends still Pending Abandoned (`owner_stopped`), in the Stop's writer. Each
//! keeps its row, payload, binding and accounting, and one that may have
//! crossed the wire keeps that as possible delivery: nothing calls it done or
//! undelivered. The abandon runs in a savepoint: a ledger that refuses it
//! rolls back the savepoint alone, is logged, and the Stop commits, with the
//! abandon it owes marked in the same write (`stop_recovery`), which every
//! wake host retries at the vault's pace until it lands (FIX 7352). No other
//! try's sends are touched.

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::outbound_intent_ledger::{
    IntentEscalationReason, IntentLedgerError, abandon_attempt_pending_intents_in_txn,
};

use super::stop_recovery::owe_in_txn;

/// In the owner's Stop writer, marks `attempt`'s Pending sends Abandoned in
/// a savepoint. Never fails the Stop: a refused abandon rolls back alone, is
/// logged, and is owed in the Stop's own write for every wake host to
/// retry.
pub(super) fn abandon_stopped_sends_in_txn(
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

/// `attempt`'s Pending sends marked Abandoned for the owner's Stop, in
/// `wtxn`. A ledger failure surfaces as the engine's own, or as a corrupt
/// ledger row.
pub(super) fn abandon_sends_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    attempt: AttemptId,
    now: u64,
) -> Result<usize> {
    abandon_attempt_pending_intents_in_txn(
        vault,
        wtxn,
        attempt,
        IntentEscalationReason::OwnerStopped,
        now.saturating_mul(1_000),
    )
    .map_err(|error| match error {
        IntentLedgerError::Engine(error) => error,
        _ => Error::CorruptedIndex("outbound intent ledger row"),
    })
}
