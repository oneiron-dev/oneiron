//! The credential door of `tasks.wave` (OF-427). A credential holds no lease
//! for a wave to run under, so its wave is root and the owner's, admitted as
//! `POST /v1/ai/waves` admits one; a pumped run's wave is served on its own
//! host door, bound to its lease. The generated HTTP facade handler and the
//! MCP dispatcher both call this through `host_doors`.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{TaskWaveReceipt, TaskWaveRequest};
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use super::host_doors::internal;
use crate::auth::CoreAuth;
use crate::server::{SyncServer, wave_plan, wave_receipt};

/// `tasks.wave`: the owner's root wave, planned for the credential's
/// principal, or the vault's own owner for one that names none.
pub(crate) async fn tasks_wave(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TaskWaveRequest,
) -> MemoryResult<TaskWaveReceipt> {
    const VERB: &str = "tasks.wave";
    let refused = |message: &str| {
        MemoryError::new(
            MEMORY_CODE_FORBIDDEN,
            format!("{VERB}: {message}"),
            &["Ask from inside an agent run, whose wave runs under its own lease."],
        )
    };
    if !auth.is_owner_grade() {
        return Err(refused("a credential's wave is root, so it is the owner's"));
    }
    let actor = match auth.principal_ref() {
        Some(reference) => EntityId::from_hex(reference).map_err(MemoryError::from)?,
        None => server.vault().ensure_embedded_owner_actor()?,
    };
    let class = match auth.actor_class() {
        Some("agent") => EdgeActorClass::Agent,
        Some("system") => EdgeActorClass::System,
        _ => EdgeActorClass::Human,
    };
    let server = Arc::clone(server);
    let auth = auth.clone();
    tokio::task::spawn_blocking(move || {
        let (epic, constraints) = wave_plan(
            &server,
            WriteActor::new(actor, class),
            |id| auth.can_read_entity(server.vault(), id),
            &input,
        )?;
        if !auth.credential_is_live(server.vault()) {
            return Err(refused("the credential is no longer live"));
        }
        wave_receipt(server.vault().enqueue_wave_plan(
            epic,
            &input.objective,
            constraints,
            oneiron_vault_contract::now_ts(),
        )?)
    })
    .await
    .map_err(|_| internal(VERB))?
}
