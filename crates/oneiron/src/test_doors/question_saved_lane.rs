//! A saved question's two rebuilt readers (FIX 14344, Astra F2 on #8029),
//! as `questions::saved_reader` builds them for a live PERSON asker: the
//! asker's own key, narrowed by the version's frozen lane, and the lane
//! that reads with the asker's own live owner authority (FIX 7461). For an
//! asker of any row type, the reader the question's own reads build
//! (`saved_question_reader`).

use crate::claim::{FrozenReadLane, ScopedRead, ScopedReadActorKey};
use crate::llm::decision::questions::{question_lane, saved_reader};
use crate::{EntityId, Error, Result, Vault};

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
