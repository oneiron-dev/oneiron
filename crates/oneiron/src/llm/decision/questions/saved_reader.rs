//! OF-506 (FIX 1712, 1857, 2116): a standing question reads inside the lane
//! its version was saved under. Every read site of a question's own work (its
//! unit, its neighbours and evidence, its media, a trial of its answers, the
//! files an artifact ask or a wake's re-ask reads, the read a wake's carried
//! made_by is admitted through) builds its reader here:
//! the principal's own live key, as a question's reads always built it,
//! narrowed by the version's frozen lane
//! ([`crate::claim::FrozenReadLane::narrow_in_txn`]). A version saved as the
//! principal's own reads exactly as before; a narrowed one reads only inside
//! its narrowing, and nothing once its credential is no longer live.

use std::collections::BTreeSet;

use crate::claim::{FrozenReadLane, ScopedRead, ScopedReadActorKey};
use crate::llm::decision::DecisionQuestion;
use crate::secret_custody::SecretSight;
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

/// What a question's saved lane reads of the rows an artifact ask reads
/// (FIX 2116). The pump and a withdrawal wake hold no credential, so they
/// read through the lane the version was saved under, rebuilt now.
pub(crate) struct SavedArtifactReads {
    /// Of the rows asked, those the rebuilt lane reads, in one snapshot.
    pub(crate) readable: BTreeSet<EntityId>,
    /// The secret sight the rebuilt lane holds now, derived from its key:
    /// the scope is frozen, the sight never is.
    pub(crate) sight: SecretSight,
}

/// `ids` as `principal` reads them inside `read_lane`, in one snapshot: its
/// key as an artifact ask builds it (held to the principal's relationship
/// grants), narrowed by the saved lane and read with the principal's own
/// live owner authority.
///
/// # Errors
/// A store, fold or clock failure building or judging the lane.
pub(super) fn saved_artifact_reads(
    vault: &Vault,
    principal: EntityId,
    read_lane: &FrozenReadLane,
    ids: &[EntityId],
) -> Result<SavedArtifactReads> {
    let txn = vault.store.env.read_txn()?;
    let key = super::refresh::source_actor_key(vault, &txn, principal, None)?
        .require_access_grants(Some(principal));
    let key = read_lane.narrow_in_txn(vault, &txn, key)?;
    let sight = key.secret_sight();
    let read = super::reader_authority::question_lane(vault, key);
    let mut readable = BTreeSet::new();
    for id in ids {
        if read.entity_raw_live_in(&txn, id)?.is_some() {
            readable.insert(*id);
        }
    }
    Ok(SavedArtifactReads { readable, sight })
}

/// The lane a withdrawal wake's re-ask of `question`, asked for
/// `principal`, reads inside, read in `txn`: the lane of the version that
/// asked, or the principal's own when that version is no saved question of
/// the principal's (a one-off ask).
///
/// # Errors
/// A store or decode failure reading the version.
fn wake_read_lane_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    principal: EntityId,
    question: &DecisionQuestion,
) -> Result<FrozenReadLane> {
    Ok(super::store::read_question_in_txn(
        vault,
        txn,
        principal,
        question.id,
        Some(question.version),
    )?
    .map_or_else(FrozenReadLane::principal, |record| record.read_lane))
}

/// [`saved_artifact_reads`] for a withdrawal wake's re-ask of `question`,
/// asked for `principal`, inside [`wake_read_lane_in_txn`].
///
/// # Errors
/// As [`saved_artifact_reads`], and a store or decode failure reading the
/// version.
pub(crate) fn wake_artifact_reads(
    vault: &Vault,
    principal: EntityId,
    question: &DecisionQuestion,
    ids: &[EntityId],
) -> Result<SavedArtifactReads> {
    let read_lane = {
        let txn = vault.store.env.read_txn()?;
        wake_read_lane_in_txn(vault, &txn, principal, question)?
    };
    saved_artifact_reads(vault, principal, &read_lane, ids)
}

/// The read a withdrawal wake's carried made_by is admitted through as its
/// fresh proposal waits (FIX 1229, FIX 11831): `principal`'s key as a
/// question's reads build it, narrowed by the asking version's saved lane
/// ([`wake_read_lane_in_txn`]) in one snapshot, with the principal's own
/// live owner authority. A version saved as the principal's own admits
/// exactly as before.
///
/// # Errors
/// A store, fold or clock failure building or narrowing the key, and a
/// store or decode failure reading the version.
pub(crate) fn wake_lane<'v>(
    vault: &'v Vault,
    principal: EntityId,
    question: &DecisionQuestion,
) -> Result<ScopedRead<'v>> {
    let key = {
        let txn = vault.store.env.read_txn()?;
        let read_lane = wake_read_lane_in_txn(vault, &txn, principal, question)?;
        let key = super::refresh::source_actor_key(vault, &txn, principal, None)?
            .require_access_grants(Some(principal));
        read_lane.narrow_in_txn(vault, &txn, key)?
    };
    Ok(super::reader_authority::question_lane(vault, key))
}
