//! The owner's typed host triggers. Every transport uses this door and
//! the ordinary verb boundary; the handler only supplies the live credential,
//! invocation and existing cheap compactor to the engine operation.

use std::sync::Arc;

use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::{MEMORY_CODE_MODEL_UNAVAILABLE, Memory, MemoryError, MemoryResult};
use oneiron::runtime_hooks::InvocationId;
use oneiron::runtime_hooks::host_doors::{self, *};
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing, owner_proof, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

async fn as_owner<T: Send + 'static>(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    verb: &'static str,
    act: impl FnOnce(&SyncServer, &Memory<'_>, &AuthenticatedOwner, InvocationId) -> MemoryResult<T>
    + Send
    + 'static,
) -> Listed<T> {
    let owner = match owner_proof(auth, server, verb) {
        Ok(owner) => owner,
        Err(error) => return refused(error),
    };
    let Some(invocation) = invocation else {
        return refused(MemoryError::bad_request(
            "a host trigger requires its logical invocation",
        ));
    };
    credential_listing(server, auth, caller, verb, move |server, _, memory| {
        let memory = memory.with_invocation(invocation);
        act(server, &memory, &owner, invocation)
    })
    .await
}

pub(crate) async fn host_compact(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: HostCompactRequest,
) -> Listed<HostCompactResult> {
    let mut rows = vec![input.session_ref];
    rows.extend(
        input
            .window
            .iter()
            .flat_map(|message| [message.turn_id, message.message_id]),
    );
    let (answer, mut listed) = as_owner(
        server,
        auth,
        caller,
        invocation,
        "host.compact",
        move |server, memory, owner, _| {
            let (backend, policy) = server.ai.host_compaction().ok_or_else(|| {
                MemoryError::new(
                    MEMORY_CODE_MODEL_UNAVAILABLE,
                    "no configured cheap compaction backend serves this host",
                    &["Configure the host's compaction seat and prompt package."],
                )
            })?;
            host_doors::compact_as_owner(memory, owner, input, backend.as_ref(), &policy)
        },
    )
    .await;
    listed.extend(rows);
    if let Ok(result) = &answer {
        listed.push(result.summary);
    }
    (answer, listed)
}

pub(crate) async fn host_wake(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: HostWakeRequest,
) -> Listed<HostWakeResult> {
    as_owner(
        server,
        auth,
        caller,
        invocation,
        "host.wake",
        move |_, memory, owner, invocation| {
            host_doors::wake_as_owner(memory, owner, invocation, input)
        },
    )
    .await
}

pub(crate) async fn host_budget_hit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    invocation: Option<InvocationId>,
    input: HostBudgetHitRequest,
) -> Listed<HostBudgetHitResult> {
    as_owner(
        server,
        auth,
        caller,
        invocation,
        "host.budget.hit",
        move |_, memory, owner, invocation| {
            host_doors::budget_hit_as_owner(memory, owner, invocation, input)
        },
    )
    .await
}
