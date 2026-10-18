//! The generated context-bearing reply door, under the existing owner's inference authority.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_OFF_RECORD_SESSION_DOOR, MemoryError};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{AiReply, AiReplyRequest};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

pub(crate) async fn ai_reply(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    session: Option<EntityId>,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: AiReplyRequest,
) -> Listed<AiReply> {
    if let Err(error) = owner_proof(auth, server, "ai.reply") {
        return refused(error);
    }
    if session.is_some() {
        return refused(MemoryError::new(MEMORY_CODE_OFF_RECORD_SESSION_DOOR,
            "ai.reply retains its emit receipt in canonical storage", &[]));
    }
    crate::api::context_board::generate_reply(server, auth, caller, input).await
}
