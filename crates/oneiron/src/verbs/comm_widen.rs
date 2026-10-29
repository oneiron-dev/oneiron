//! The owner's revoke row of a recorded stop-asking choice (FIX 11104):
//! `vault.tasks.comm_widen.revoke`, a host door over the one engine door
//! [`Memory::revoke_comm_widen_standing`] (FIX 10695). The owner's own
//! revoke ends that standing: the recorded choice stays as it was answered,
//! the asking run keeps the reach it was approved once, and its descendants
//! ask again. A server hands it the owner's in-request proof and his own
//! handle, as the neighbouring owner doors take them; an embedded handle
//! answers as its own owner. Nothing here revokes on its own.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::memory::{Memory, MemoryResult};
use crate::task_verb::CommWidenRevokeReceipt;

/// `vault.tasks.comm_widen.revoke`'s input: the run whose widen ask recorded
/// the stop-asking choice.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommWidenRevokeRequest {
    /// The asking run's attempt, 32 hex: the receipt's `attempt`.
    pub attempt: EntityId,
}

/// `vault.tasks.comm_widen.revoke`: ends the standing of the stop-asking
/// choice `input.attempt`'s widen ask recorded, as the owner proves on his
/// own handle. A second revoke answers the first.
///
/// # Errors
///
/// `FORBIDDEN` when the proof does not name the handle's human caller;
/// `NOT_FOUND` when the run recorded no stop-asking choice; storage errors.
pub fn revoke_comm_widen_as(
    memory: &Memory<'_>,
    owner: &AuthenticatedOwner,
    input: CommWidenRevokeRequest,
) -> MemoryResult<CommWidenRevokeReceipt> {
    let attempt = AttemptId::from_bytes(input.attempt.as_bytes())?;
    memory.revoke_comm_widen_standing(owner, attempt)
}
