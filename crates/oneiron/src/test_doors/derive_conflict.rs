//! A JSON `vault.derive.commit` door for the Conflict item tests: commits one
//! wire batch as a named actor, run and attempt, and answers the wire view.
//! The Conflict item has no typed door builder; the tests write it as JSON.

use serde_json::Value;

use crate::attempt_queue::AttemptId;
use crate::claim::ClaimSource;
use crate::derive::{DerivationStamp, DeriveCommitInput, DeriveCommitView};
use crate::memory::{MemoryError, MemoryResult};
use crate::write_envelope::{SourceLineage, WriteActor};
use crate::{EdgeActorClass, EntityId, Vault};

/// Commits the JSON `vault.derive.commit` batch `input` as `actor` of
/// `class`, in run `run` and `attempt`: the input is decoded as the served
/// door decodes it, the stamp is built as the derive doors build it, and the
/// answer is the wire view as JSON.
///
/// # Errors
///
/// A bad request for an input the wire form refuses, a malformed batch, and
/// the vault's.
pub fn commit(
    vault: &Vault,
    actor: EntityId,
    class: EdgeActorClass,
    run: &str,
    attempt: Option<AttemptId>,
    input: Value,
) -> MemoryResult<Value> {
    let input: DeriveCommitInput = serde_json::from_value(input)
        .map_err(|error| MemoryError::bad_request(error.to_string()))?;
    let batch = input.into_batch()?;
    let stamp = DerivationStamp {
        actor: WriteActor::new(actor, class),
        run: Some(run.to_owned()),
        attempt,
        lineage: SourceLineage::of(ClaimSource::Generated),
    };
    let view = DeriveCommitView::from(vault.derive_commit(&stamp, &batch)?);
    serde_json::to_value(view).map_err(|error| MemoryError::bad_request(error.to_string()))
}
