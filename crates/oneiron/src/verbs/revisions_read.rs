//! `vault.revisions.read`: each ref's entity view with its live revision,
//! under the caller's lane and a live Grant naming the verb.

use serde::{Deserialize, Serialize};

use crate::claim::ScopedReadResult;
use crate::memory::{EntityView, Memory, MemoryError, MemoryResult};
use crate::vault::RevisionRef;

#[doc(hidden)]
pub use oneiron_verb_wire::verbs::revisions_read::{RevisionEntry, RevisionsReadRequest};

/// `vault.revisions.read` on a handle: each ref's entity view with its live
/// revision under the caller's lane. The lane read refuses a caller with no
/// live owner Grant naming the verb, in the serving snapshot itself; a row
/// outside the caller's lane answers `None`, never an error.
pub fn vault_revisions_read_embedded(
    memory: &Memory<'_>,
    input: RevisionsReadRequest,
) -> MemoryResult<ScopedReadResult<Vec<Option<RevisionEntry>>>> {
    input.validate()?;
    let bound = memory.with_read_filter(input.filter.as_ref());
    let read = bound.revisions_read(&input.refs)?;
    Ok(ScopedReadResult {
        value: read
            .value
            .into_iter()
            .map(|slot| slot.map(|(view, revision)| RevisionEntry { view, revision }))
            .collect(),
        receipt: read.receipt,
    })
}
