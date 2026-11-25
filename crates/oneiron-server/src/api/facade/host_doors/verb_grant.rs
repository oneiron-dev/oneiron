//! The host doors whose verb row names the proof `verb_grant_caller` (design
//! pass 32 section 5, the lane economy's doors): the vault owner under their
//! own proof, or an agent whose own live Grant from a live owner lists the
//! verb. The engine decides (`Memory::verb_grant_caller_admits`); the facade
//! admits the caller before the row's hooks fire, and the door's own act
//! admits it again in its read.

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{Memory, MemoryResult};

use super::super::FacadeApiError;
use super::support::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// A `verb_grant_caller` row's early authority check: the engine's admission
/// of the caller for `verb` (the owner's own proof on an owner-grade
/// credential, else an agent's own Grant listing the verb), judged before
/// the row's verb hooks fire.
pub(super) fn verb_grant_caller_admits(
    server: &SyncServer,
    auth: &CoreAuth,
    verb: &str,
) -> MemoryResult<()> {
    let (actor, class) = crate::api::facade::facade_actor(server, auth)
        .map_err(FacadeApiError::into_memory_error)?;
    let owner = if auth.is_owner_grade() {
        Some(owner_proof(auth, server, verb)?)
    } else {
        None
    };
    crate::api::credential_memory(&server.vault, Some(auth), actor, class)
        .at(auth.locality())
        .verb_grant_caller_admits(owner.as_ref(), verb)
        .map(drop)
}

/// `act` off the runtime on the caller's own handle, with the caller's own
/// owner proof when its credential is owner-grade. `act` admits the caller
/// to `verb` itself (`Memory::verb_grant_caller_admits`), in its own read.
pub(super) async fn verb_grant_door<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &Memory<'_>, Option<&AuthenticatedOwner>) -> MemoryResult<T>
    + Send
    + 'static,
) -> Listed<T> {
    let caller = match crate::api::facade::facade_actor(server, auth)
        .map_err(FacadeApiError::into_memory_error)
    {
        Ok(caller) => caller,
        Err(error) => return (Err(error), Vec::new()),
    };
    let owner = if auth.is_owner_grade() {
        match owner_proof(auth, server, verb) {
            Ok(owner) => Some(owner),
            Err(error) => return (Err(error), Vec::new()),
        }
    } else {
        None
    };
    credential_listing(server, auth, caller, verb, move |server, _, memory| {
        act(server, &memory, owner.as_ref())
    })
    .await
}
