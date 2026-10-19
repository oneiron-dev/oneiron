//! The host door of `vault.tasks.linear.mapping.edit` (OF-427 C6).
//! `host_doors` re-exports it, so the generated HTTP facade handler and the
//! MCP dispatcher run one mapping edit. The credential must read the TASK, as
//! the facade's readable-ref admission checks a plain row's `task_ref`; the
//! edit runs on the credential's own handle as its caller, whose Owner
//! standing the engine proves, and a link names the tracker team this host's
//! Linear webhook mapping configures. Beside the receipt, the door lists the
//! rows its handle's reads listed (`host_door_lists`).

use std::sync::Arc;

use oneiron::linear_sync::{LinearMappingEdit, LinearMappingEditReceipt};
use oneiron::memory::MemoryError;
use oneiron::runtime_hooks::InvocationId;
use oneiron::{EdgeActorClass, EntityId};

use super::host_doors::{Listed, credential_listing, refused};
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// `vault.tasks.linear.mapping.edit`: one link, unlink or mirror of a TASK
/// the credential reads, by its owner.
pub(crate) async fn vault_tasks_linear_mapping_edit(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: LinearMappingEdit,
) -> Listed<LinearMappingEditReceipt> {
    let readable = EntityId::from_hex(&input.task_ref)
        .and_then(|task| auth.can_read_entity(&server.vault, &task))
        .map_err(MemoryError::from);
    match readable {
        Ok(true) => {}
        Ok(false) => return refused(MemoryError::from(oneiron::Error::EntityNotFound)),
        Err(refusal) => return refused(refusal),
    }
    credential_listing(
        server,
        auth,
        caller,
        "vault.tasks.linear.mapping.edit",
        move |server, _, memory| {
            let team = crate::linear_host::webhook_tracker(server)
                .unwrap_or_else(|error| {
                    tracing::warn!(%error, "the Linear webhook mapping is unreadable");
                    None
                })
                .map(|tracker| tracker.team_id);
            memory.linear_mapping_edit(&input, team.as_deref())
        },
    )
    .await
}
