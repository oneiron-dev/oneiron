//! The owner's per-call erase of an outbound call's frozen request (FIX
//! 11801): evidence only. The engine writer owns the erase, its delivery
//! accounting and its retirement finishers; this door only exposes that act
//! through the typed owner surface, with the owner's proof checked in the
//! erase's own writer.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::consent::AuthenticatedOwner;
use crate::memory::MemoryResult;

use super::connector_call_error;

/// `vault.outbound_calls.request.erase`'s input: the call's attempt and its
/// sequence within that attempt.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutboundCallRequestEraseRequest {
    /// The call's attempt, 32 hex.
    pub attempt: EntityId,
    pub call_seq: u64,
}

/// `vault.outbound_calls.request.erase`'s answer: `false` for a call with no
/// row here, or one whose request is already erased.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OutboundCallRequestErased {
    pub erased: bool,
}

/// `vault.outbound_calls.request.erase`: the owner's erase of one outbound
/// call's frozen request. The owner's proof is revalidated in the
/// erase's own writer; the writer keeps the row's id, attempt
/// binding, accounting, state and delivery knowledge and loses its request.
pub fn erase_outbound_call_request_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    input: OutboundCallRequestEraseRequest,
) -> MemoryResult<OutboundCallRequestErased> {
    let attempt_id = AttemptId::from_bytes(input.attempt.as_bytes())?;
    let erased = vault
        .erase_outbound_call_request_as_owner(owner, attempt_id, input.call_seq)
        .map_err(connector_call_error)?;
    Ok(OutboundCallRequestErased { erased })
}
