//! The credential door of `tasks.wave` (OF-427). A credential holds no lease
//! for a wave to run under, so its wave is root and the owner's, admitted as
//! `POST /v1/ai/waves` admits one; a pumped run's wave is served on its own
//! host door, bound to its lease. The generated HTTP facade handler and the
//! MCP dispatcher both call this through `host_doors`. Beside its receipt,
//! the door lists the epic and the planner it planned from
//! (`host_door_lists`); the planning attempt lives in the attempt queue,
//! which holds no row.
use std::sync::Arc;

use oneiron::memory::{MEMORY_CODE_FORBIDDEN, MemoryError, MemoryResult};
use oneiron::task_verb::sdk::{TaskWaveReceipt, TaskWaveRequest};
use oneiron::{EdgeActorClass, EntityId, WriteActor};

use super::host_doors::{Listed, hex_rows, internal, naming};
use crate::auth::CoreAuth;
use crate::server::{SyncServer, wave_plan, wave_receipt};

/// `tasks.wave`: the owner's root wave, planned for the credential's
/// principal, or the vault's own owner for one that names none. Beside it,
/// the epic TASK and the planner definition the wave was checked and
/// planned from.
pub(crate) async fn tasks_wave(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: TaskWaveRequest,
) -> Listed<TaskWaveReceipt> {
    let named = [input.epic_task_ref.clone(), input.planner_ref.clone()];
    naming(tasks_wave_answer(server, auth, input).await, |_| {
        hex_rows(&named)
    })
}

async fn tasks_wave_answer(
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
    // A self-hosted root or the dev mode plans as the owner its host action
    // names; a hosted operator's root plans for no one, and no request
    // creates an owner to plan as (FIX 2222).
    let (actor, class) = match crate::api::host_action::host_action_of(server.vault(), auth) {
        Some(action) => {
            let actor = action.map_err(MemoryError::from)?.actor();
            (actor.entity_ref(), actor.actor_class())
        }
        None => {
            let reference = auth
                .principal_ref()
                .ok_or_else(|| refused("the credential names no principal to plan as"))?;
            let class = match auth.actor_class() {
                Some("agent") => EdgeActorClass::Agent,
                Some("system") => EdgeActorClass::System,
                _ => EdgeActorClass::Human,
            };
            (
                EntityId::from_hex(reference).map_err(MemoryError::from)?,
                class,
            )
        }
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
