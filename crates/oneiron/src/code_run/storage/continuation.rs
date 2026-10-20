//! A successor attempt's approved continuation of a failed run (FIX 3694,
//! OF-568): the run it forks from, the step it starts at, the owner's
//! approval and the exact prompt bytes approved, written once; and the one
//! transaction that seeds the child run's replay row from that fork.

use serde::{Deserialize, Serialize};

use super::super::replay::{CodeRunRawOutput, CodeRunReplayGeneration, CodeRunReplayRecord};
use crate::attempt_queue::AttemptId;
use crate::side_table::{self, Named, SideTable};
use crate::{EntityId, Error, Result, Vault};

/// Continuations. Key: id16(successor attempt).
const CONTINUATIONS: SideTable<EntityId, StoredRunContinuation, Named> =
    SideTable::new(&side_table::CODE_RUN_CONTINUATION);

/// One successor attempt's continuation, immutable once written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredRunContinuation {
    /// The Failed attempt the successor retries.
    pub(crate) predecessor: AttemptId,
    /// The predecessor's executor run, whose id is the predecessor's.
    pub(crate) source_run: EntityId,
    /// The step the child starts at: its prefix is the source's checkpoints
    /// `0..step`.
    pub(crate) step: u64,
    /// The owner's durable approval.
    pub(crate) approval: EntityId,
    /// The approved bytes, as the side-row wall stores them.
    pub(crate) prompt: String,
    /// BLAKE3 of `prompt`.
    pub(crate) prompt_digest: [u8; 32],
    /// BLAKE3 of the start body the child forks from.
    pub(crate) start_digest: [u8; 32],
    /// The lease generation of the capsule that holds that start.
    pub(crate) lease_generation: u32,
}

/// The continuation `successor` carries, read in the caller's transaction.
///
/// # Errors
///
/// Storage errors, and a row whose prompt is no longer its digest.
pub(crate) fn run_continuation_in_txn(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    successor: EntityId,
) -> Result<Option<StoredRunContinuation>> {
    let Some(row) = CONTINUATIONS.get(&vault.store, rtxn, &successor)? else {
        return Ok(None);
    };
    if *blake3::hash(row.prompt.as_bytes()).as_bytes() != row.prompt_digest {
        return Err(Error::CorruptedIndex("code-run continuation prompt digest"));
    }
    Ok(Some(row))
}

/// Writes `row` as `successor`'s continuation unless it holds one already,
/// in the caller's transaction. `row` becomes what the side-row wall stores
/// (a secret the approved text holds becomes its handle), its prompt digest
/// taken over those bytes. Answers the row already held, which stays as it
/// is, or `None` once `row` is written.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn put_run_continuation_row_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    successor: EntityId,
    row: &mut StoredRunContinuation,
) -> Result<Option<StoredRunContinuation>> {
    CONTINUATIONS.admit(vault, wtxn, &successor, row)?;
    row.prompt_digest = *blake3::hash(row.prompt.as_bytes()).as_bytes();
    if let Some(held) = run_continuation_in_txn(vault, wtxn, successor)? {
        return Ok(Some(held));
    }
    CONTINUATIONS.put(vault, wtxn, &successor, row)?;
    Ok(None)
}

/// Seeds `child`, the replay row of a run forked from `source`, in one
/// transaction: the row, only where none is stored yet, and the child's own
/// occurrence of each of `inherited`, the source's outputs the row names.
///
/// # Errors
///
/// [`Error::ConcurrentWrite`] when a row is already stored for the child,
/// and storage errors; nothing is written then.
pub(crate) fn seed_continuation_run(
    vault: &Vault,
    child: &CodeRunReplayRecord,
    source: EntityId,
    inherited: &[CodeRunRawOutput],
) -> Result<CodeRunReplayGeneration> {
    vault.put_code_run_replay_record_if_generation_with_heal_and(child, None, None, |txn| {
        for output in inherited {
            vault.retain_inherited_result_in_txn(txn, child.run_id, source, output)?;
        }
        // The child's replies are its source's actor's (FIX 5718).
        super::response_owners::inherit_response_owner_in_txn(vault, txn, child.run_id, &source)
    })
}
