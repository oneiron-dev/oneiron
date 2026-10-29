//! OF-506 (FIX 1712, 1857): a standing question reads inside the lane its
//! version was saved under. Every read site of a question's own work (its
//! unit, its neighbours and evidence, its media, a trial of its answers)
//! builds its reader here: the principal's own live key, as a question's
//! reads always built it, narrowed by the version's frozen lane
//! ([`crate::claim::FrozenReadLane::narrow_in_txn`]). A version saved as the
//! principal's own reads exactly as before; a narrowed one reads only inside
//! its narrowing, and nothing once its credential is no longer live.

use crate::claim::{FrozenReadLane, ScopedReadActorKey};
use crate::{EntityId, Result, Vault};

/// `principal`'s reader of a question version saved under `read_lane`, in
/// `txn`.
///
/// # Errors
/// A store, fold or clock failure building the key or judging the frozen
/// credential.
pub(super) fn saved_reader_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    read_lane: &FrozenReadLane,
) -> Result<ScopedReadActorKey> {
    let key = super::graph_ask::asker_reader_in_txn(vault, txn, principal)?;
    read_lane.narrow_in_txn(vault, txn, key)
}

/// [`saved_reader_in_txn`] in its own snapshot.
///
/// # Errors
/// As [`saved_reader_in_txn`].
pub(super) fn saved_reader(
    vault: &Vault,
    principal: EntityId,
    read_lane: &FrozenReadLane,
) -> Result<ScopedReadActorKey> {
    let txn = vault.store.env.read_txn()?;
    saved_reader_in_txn(vault, &txn, principal, read_lane)
}

/// The lane the version `answer` answered was saved under, read in `txn`;
/// the principal's own when that version is not `principal`'s.
///
/// # Errors
/// A store or decode failure reading the version.
pub(super) fn answer_lane_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    answer: &super::AnswerRecord,
) -> Result<FrozenReadLane> {
    let receipt = &answer.decision.receipt;
    Ok(super::store::read_question_in_txn(
        vault,
        txn,
        principal,
        receipt.question,
        Some(receipt.question_version),
    )?
    .map_or_else(FrozenReadLane::principal, |record| record.read_lane))
}
