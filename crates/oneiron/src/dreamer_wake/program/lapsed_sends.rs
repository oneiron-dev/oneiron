//! The sends of a try that ended on its authority (FIX 11130).
//!
//! A turn program's try that ends Failed because its attested owner is no
//! longer the vault's live owner (FIX 11090), or because its original
//! authorization was positively withdrawn (FIX 11593), leaves no send of its
//! own still Pending: each is marked Abandoned for that reason, keeping what
//! it knew of its delivery, as the owner's Stop does for his (FIX 7188). The
//! abandon runs in its own writer. A ledger that refuses it is logged and
//! the try ends as it would have; each such send then meets the same check
//! at its next send (FIX 11591).

use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};
use crate::outbound_intent_ledger::{
    IntentEscalationReason, IntentLedgerError, abandon_attempt_pending_intents_in_txn,
};

/// Marks `attempt`'s Pending sends Abandoned for `reason`, in one writer.
/// Never fails the try's end: a refused abandon is logged.
pub(super) fn stop_lapsed_sends(
    vault: &Vault,
    attempt: AttemptId,
    reason: IntentEscalationReason,
    now_ms: u64,
) {
    let stopped = (|| -> Result<usize> {
        let mut wtxn = vault.store.env.write_txn()?;
        let stopped =
            abandon_attempt_pending_intents_in_txn(vault, &mut wtxn, attempt, reason, now_ms)
                .map_err(|error| match error {
                    IntentLedgerError::Engine(error) => error,
                    _ => Error::CorruptedIndex("outbound intent ledger row"),
                })?;
        wtxn.commit()?;
        Ok(stopped)
    })();
    match stopped {
        Ok(0) => {}
        Ok(stopped) => tracing::info!(
            attempt = %bytes_to_hex_lower(attempt.as_bytes()),
            stopped,
            ?reason,
            "a turn program's try ended on its authority; its pending sends stop"
        ),
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            attempt = %bytes_to_hex_lower(attempt.as_bytes()),
            ?reason,
            "a turn program's try ended on its authority; its pending sends did not stop \
             here and meet the same check at their next send"
        ),
    }
}
