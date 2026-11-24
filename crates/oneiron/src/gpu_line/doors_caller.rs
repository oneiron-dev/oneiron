//! The GPU line doors' one call into the lane economy's door kit
//! (`verb_grant_caller`, `crate::memory::verb_grant_caller`): the owner under
//! their own proof, or an agent whose own live Grant names the verb.
use crate::EntityId;
use crate::consent::AuthenticatedOwner;
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{MEMORY_CODE_FORBIDDEN, Memory, MemoryError, MemoryResult};

/// Admits `memory`'s caller to `verb` in `txn`: `Some(owner actor)` when the
/// owner's own proof admitted it, `None` for an agent its Grant admitted.
///
/// # Errors
///
/// `forbidden` for a caller the kit does not admit; a store read failure.
pub(super) fn admit_in_txn(
    memory: &Memory<'_>,
    txn: &heed::RoTxn<'_>,
    owner: Option<&AuthenticatedOwner>,
    verb: &str,
) -> MemoryResult<Option<EntityId>> {
    Ok(
        match memory.verb_grant_caller_admits_in_txn(txn, owner, verb)? {
            VerbGrantCaller::Owner => Some(memory.actor()),
            VerbGrantCaller::Agent { .. } => None,
        },
    )
}

/// The refusal of an agent at an act that is the owner's alone.
pub(super) fn refused_owner_act(verb: &str, act: &str) -> MemoryError {
    MemoryError::new(
        MEMORY_CODE_FORBIDDEN,
        format!("{verb}: {act} is the vault owner's own act"),
        &["Call it as the vault owner."],
    )
}
