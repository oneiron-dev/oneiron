//! The lane economy's door kit (design pass 32 section 5): every
//! `vault.gpu.lines.*`, `vault.arms.*` and `vault.planner.card` door whose
//! row proves `verb_grant_holder` admits the owner under their own proof, or
//! an agent whose own live owner Grant names the verb. The engine decides
//! (`oneiron::gpu_line::VerbGrantHolder`); the door admits the caller before
//! the row's hooks fire and again when it acts, and each act judges an agent
//! once more in its own write, against the line it reaches.

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::gpu_line::{VerbGrantAgent, VerbGrantHolder};
use oneiron::memory::MemoryResult;

use super::super::FacadeApiError;
use super::support::{Listed, credential_listing, owner_proof};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// A lane-economy door's caller, as the engine admitted it: the owner under
/// their own proof, or an agent under its own handle.
pub(in crate::api::facade) enum VerbGrantCaller {
    Owner(AuthenticatedOwner),
    Agent(VerbGrantAgent),
}

impl VerbGrantCaller {
    /// The caller as the engine's acts take it.
    pub(in crate::api::facade) fn holder(&self) -> VerbGrantHolder<'_> {
        match self {
            Self::Owner(owner) => VerbGrantHolder::Owner(owner),
            Self::Agent(agent) => VerbGrantHolder::Agent(agent),
        }
    }
}

/// `act` off the runtime on the caller's own handle, after the engine admits
/// the caller to `verb`: the caller's own owner proof when its credential is
/// owner-grade, its agent handle otherwise.
pub(in crate::api::facade) async fn verb_grant_door<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &VerbGrantCaller) -> MemoryResult<T> + Send + 'static,
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
        memory.verb_grant_holder_admits(owner.as_ref(), verb)?;
        let caller = match owner {
            Some(owner) => VerbGrantCaller::Owner(owner),
            None => VerbGrantCaller::Agent(memory.verb_grant_agent()),
        };
        act(server, &caller)
    })
    .await
}

/// The `verb_grant_holder` rows' early authority check: the engine's
/// admission of the caller for `verb` (the owner's own proof on an
/// owner-grade credential, else an agent's own Grant naming the verb),
/// judged before the row's verb hooks fire. The door admits the caller again
/// when it acts.
pub(super) fn verb_grant_holder_admits(
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
        .verb_grant_holder_admits(owner.as_ref(), verb)
}
