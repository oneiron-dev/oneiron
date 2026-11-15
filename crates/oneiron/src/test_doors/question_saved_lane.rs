//! A saved question's two rebuilt readers (FIX 14344, Astra F2 on #8029),
//! as `questions::saved_reader` builds them for a live PERSON asker: the
//! asker's own key, narrowed by the version's frozen lane, and the lane
//! that reads with the asker's own live owner authority (FIX 7461).

use crate::claim::{FrozenReadLane, ScopedRead, ScopedReadActorKey};
use crate::llm::decision::questions::question_lane;
use crate::{EntityId, Error, Result, Vault};

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

/// `key` read as a question's lane: with its reader's own live owner
/// authority once its own admission refuses (FIX 7461), as every saved
/// question read is.
#[must_use]
pub fn question_read(vault: &Vault, key: ScopedReadActorKey) -> ScopedRead<'_> {
    question_lane(vault, key)
}
