//! The owner-act `as_owner` the channel, code, codebase, code view, merge
//! queue and origin doors share (FIX 8922, FIX 10266).
//! `as_owner` is its call surface: the owner's proof, then the caller; a refusal lists no row.
//! `crate::api::facade::owner_binding` defines the owner proof; the support root the listing.

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{Memory, MemoryError, MemoryResult};

use super::{Listed, credential_listing};
use crate::api::facade::FacadeApiError;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

fn owner_proof(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<AuthenticatedOwner> {
    crate::api::facade::owner_binding::facade_owner(server, auth, verb)
}

pub(in crate::api::facade) async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&Memory<'_>, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    as_owner_paced(server, auth, verb, None, act).await
}

/// [`as_owner`] for a door a budget window paces (FIX 8753): the handle
/// carries the facade call's invocation and door, so a full window holds
/// the call in its caller's line, and the drain's run of it enters as its
/// turn. `None` (an MCP call) answers as [`as_owner`] does.
pub(in crate::api::facade) async fn as_owner_paced<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    paced: Option<crate::api::facade::FacadePacedCall>,
    act: impl FnOnce(&Memory<'_>, &AuthenticatedOwner) -> MemoryResult<T> + Send + 'static,
) -> Listed<T> {
    let admitted = || {
        let owner = owner_proof(server, auth, verb)?;
        let caller =
            super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
        Ok::<_, MemoryError>((owner, caller))
    };
    let (owner, caller) = match admitted() {
        Ok(admitted) => admitted,
        Err(error) => return (Err(error), Vec::new()),
    };
    // The agent an MCP call's verified credential registered, read here on
    // the async side: the blocking closure cannot see the call's task-local
    // (FIX 8960). Its per-file reads that say why may ask for real bytes.
    let recipient = crate::api::mcp_gateway::skill_execution::mcp_call_recipient();
    credential_listing(server, auth, caller, verb, move |_, _, memory| {
        let memory = match recipient {
            Some(recipient) => memory.for_repo_reveal_recipient(recipient),
            None => memory,
        };
        let (memory, _drain) = match &paced {
            Some(paced) => (paced.bind(memory), paced.enter_drain()),
            None => (memory, None),
        };
        act(&memory, &owner)
    })
    .await
}
