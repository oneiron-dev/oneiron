//! The sends of a try the owner stopped (FIX 7188).
//!
//! The owner's Stop of a held program's try (`release`) marks that try's own
//! sends still Pending Abandoned (`owner_stopped`), in the Stop's writer. Each
//! keeps its row, payload, binding and accounting, and one that may have
//! crossed the wire keeps that as possible delivery: nothing calls it done or
//! undelivered. The abandon runs in a savepoint: a ledger that refuses it
//! rolls back the savepoint alone, is logged, and the Stop commits, with the
//! abandon it owes marked in the same write. The program kind's admission
//! chain (`lease`), which resumes the runtime's ready holds before each
//! selection, retries each owed abandon there and clears its mark once it
//! lands. No other try's sends are touched.

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::outbound_intent_ledger::{
    IntentEscalationReason, IntentLedgerError, abandon_attempt_pending_intents_in_txn,
};
use crate::side_table::{self, Named, SideTable};

/// The abandon an owner Stop still owes its try's sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StopOwed {
    /// When the owner stopped the try.
    stopped_at: u64,
}

/// One stopped try whose sends' abandon is still owed, keyed by attempt.
const STOP_OWED: SideTable<AttemptId, StopOwed, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_STOP_OWED);

/// In the owner's Stop writer, marks `attempt`'s Pending sends Abandoned in
/// a savepoint. Never fails the Stop: a refused abandon rolls back alone, is
/// logged, and is owed in the Stop's own write for the admission chain to
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
                 and the program admission chain retries"
            );
            owe_in_txn(vault, wtxn, attempt, now);
        }
    }
}

/// In the program kind's admission writer, retries each owed abandon in a
/// savepoint of its own: one that lands clears its mark, one the ledger
/// refuses again is logged and stays owed. Never fails the chain.
pub(super) fn retry_owed_stop_abandons_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, now: u64) {
    let owed = match STOP_OWED.scan_keys(vault, &*wtxn, &[]) {
        Ok(owed) => owed,
        Err(error) => {
            tracing::warn!(
                kind = ?error.kind(),
                "the owed abandons of stopped turn program tries were not read; the next \
                 admission retries"
            );
            return;
        }
    };
    for attempt in owed {
        let retried = (|| -> Result<usize> {
            let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
            let abandoned = abandon_sends_in_txn(vault, &mut savepoint, attempt, now)?;
            STOP_OWED.delete(vault, &mut savepoint, &attempt)?;
            savepoint.commit()?;
            Ok(abandoned)
        })();
        match retried {
            Ok(abandoned) => tracing::info!(
                attempt = %bytes_to_hex_lower(attempt.as_bytes()),
                abandoned,
                "a stopped turn program try's owed abandon landed"
            ),
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                attempt = %bytes_to_hex_lower(attempt.as_bytes()),
                "a stopped turn program try's owed abandon did not land; it stays owed"
            ),
        }
    }
}

/// `attempt`'s Pending sends marked Abandoned for the owner's Stop, in
/// `wtxn`. A ledger failure surfaces as the engine's own, or as a corrupt
/// ledger row.
fn abandon_sends_in_txn(
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

/// Marks `attempt`'s abandon owed, in a savepoint of the Stop's writer. A
/// mark that is not written is logged; the Stop still commits.
fn owe_in_txn(vault: &Vault, wtxn: &mut heed::RwTxn<'_>, attempt: AttemptId, now: u64) {
    let owed = (|| -> Result<()> {
        let mut savepoint = vault.store.env.nested_write_txn(wtxn)?;
        STOP_OWED.put(
            vault,
            &mut savepoint,
            &attempt,
            &StopOwed { stopped_at: now },
        )?;
        savepoint.commit()?;
        Ok(())
    })();
    if let Err(error) = owed {
        tracing::warn!(
            kind = ?error.kind(),
            attempt = %bytes_to_hex_lower(attempt.as_bytes()),
            "a stopped turn program try's owed abandon was not marked; its pending sends stay \
             as they are"
        );
    }
}
