//! A saved question's two rebuilt readers (FIX 14344, Astra F2 on #8029),
//! as `questions::saved_reader` builds them for a live PERSON asker: the
//! asker's own key, narrowed by the version's frozen lane, and the lane
//! that reads with the asker's own live owner authority (FIX 7461). For an
//! asker of any row type, the reader the question's own reads build
//! (`saved_question_reader`), and the one its refresh, artifact and wake
//! reads build (`saved_source_reader`). A standing question stored in its own writer
//! with no caller's lane, as a review's dissent stores one, and a key under
//! the relationship-only grant gate (FIX
//! SAVED-PRINCIPAL-LANE-STORED-BEFORE-BASIS).

use crate::claim::{FrozenReadLane, ScopedRead, ScopedReadActorKey};
use crate::llm::decision::questions::{
    QuestionDefinitionInput, QuestionRecord, create_question_in_txn, question_lane, saved_reader,
    saved_source_key_in_txn,
};
use crate::{EntityId, Error, Result, Vault, WriteActor};

/// The reader a saved question's own reads build (`saved_reader`): the
/// asker's own live key, its class taken from its row's type
/// (`graph_ask::asker_reader_in_txn`), narrowed by `read_lane`.
///
/// # Errors
/// As `FrozenReadLane::narrow_in_txn`, and a store failure reading the
/// asker's row.
pub fn saved_question_reader(
    vault: &Vault,
    asker: EntityId,
    read_lane: &FrozenReadLane,
) -> Result<ScopedReadActorKey> {
    saved_reader(vault, asker, read_lane)
}

/// The reader a saved question's refresh, artifact and wake reads build
/// (`saved_reader::saved_source_key_in_txn`): the principal's own key, its
/// class taken from its row's type, with the owner's exemption while the
/// principal is the vault's live owner and otherwise under the access gate
/// on its own grants, narrowed by `read_lane`, in a snapshot of its own.
///
/// # Errors
/// As `saved_reader::saved_source_key_in_txn`, and a store failure opening
/// the snapshot.
pub fn saved_source_reader(
    vault: &Vault,
    principal: EntityId,
    read_lane: &FrozenReadLane,
) -> Result<ScopedReadActorKey> {
    let txn = vault.store.env.read_txn()?;
    saved_source_key_in_txn(vault, &txn, principal, read_lane)
}

/// The asker's own key, as `graph_ask::asker_reader_in_txn` builds it for a
/// live PERSON, narrowed by `read_lane` (`saved_reader::saved_reader`).
///
/// # Errors
/// As `FrozenReadLane::narrow`.
pub fn asker_reader(
    vault: &Vault,
    asker: EntityId,
    read_lane: &FrozenReadLane,
) -> Result<ScopedReadActorKey> {
    let key = ScopedReadActorKey::with_actor_class(asker.to_hex(), "human")
        .ok_or(Error::InvariantViolation("canonical ask principal"))?
        .exempt_while_owner(asker);
    read_lane.narrow(vault, key)
}

/// `asker`'s standing question from `definition`, stored in a writer of its
/// own with no caller's lane, as a review's dissent stores the question of
/// its overruled prediction (`critic::review::dissent`,
/// `questions::create_question_in_txn`): it keeps
/// [`FrozenReadLane::principal`].
///
/// # Errors
/// As `questions::create_question_in_txn`.
pub fn create_question_in_writer(
    vault: &Vault,
    asker: WriteActor,
    definition: QuestionDefinitionInput,
    now: u64,
) -> Result<QuestionRecord> {
    vault.with_write_txn_grouped(|txn| create_question_in_txn(vault, txn, asker, definition, now))
}

/// `key` under the relationship-only grant gate bound to `principal`, as a
/// delegate's credential key and the engine's own maintenance readers read:
/// a MESSAGE or SUMMARY that names no relationship stays readable.
#[must_use]
pub fn under_relationship_gate(key: ScopedReadActorKey, principal: EntityId) -> ScopedReadActorKey {
    key.require_relationship_grants(Some(principal))
}

/// Whether `key` reads under the relationship-only grant gate, which keeps
/// a MESSAGE or SUMMARY that names no relationship readable, rather than
/// the access gate, which closes it (Sol F7 on #8061).
#[must_use]
pub fn reads_under_relationship_gate(key: &ScopedReadActorKey) -> bool {
    key.uses_relationship_grants()
}

/// `key` read as a question's lane: with its reader's own live owner
/// authority once its own admission refuses (FIX 7461), as every saved
/// question read is.
#[must_use]
pub fn question_read(vault: &Vault, key: ScopedReadActorKey) -> ScopedRead<'_> {
    question_lane(vault, key)
}
