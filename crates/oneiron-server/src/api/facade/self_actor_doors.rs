//! `self.actor` (FIX 1047): the actor the caller's credential binds, as the
//! facade binds every write of his, and the person it acts for. A plugin
//! keeps what it learns about itself or about its person on those refs,
//! never on one session's conversation.
use std::sync::Arc;

use oneiron::memory::MemoryResult;
use oneiron::task_verb::sdk::{EmptyRequest, SelfActorRefs};

use super::FacadeApiError;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn self_actor(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _input: EmptyRequest,
) -> MemoryResult<SelfActorRefs> {
    let (actor, class) =
        super::facade_actor(server, auth).map_err(FacadeApiError::into_memory_error)?;
    oneiron::task_verb::sdk::self_actor_refs(server.vault(), actor, class)
}
