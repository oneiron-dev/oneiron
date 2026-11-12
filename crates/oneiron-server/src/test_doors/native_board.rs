//! Doors for `tests/room_pins_native.rs` (ROOM-SCOPED-PINS P2c): what a
//! pumped run's native board and self brief pin, built as the run's host
//! door builds them, with nothing delivered or recorded.

use std::sync::Arc;

use oneiron::context_board::{BriefWorkingHandle, StreamConnectionId};
use oneiron::{AttemptId, EdgeActorClass, EntityId, WriteActor};

use crate::server::SyncServer;

/// What the native board of agent `agent`'s run of dispatch `attempt` pins
/// now: the ids its MEMORIES pins receipt delivers, and every line of its
/// MEMORIES sections. The writer is bound to `attempt` as a pumped run's
/// door binds it; `None` builds the board of a run bound to no attempt.
///
/// # Errors
///
/// The board did not build; the text is the gateway error.
pub async fn run_board_pins(
    server: &Arc<SyncServer>,
    agent: EntityId,
    attempt: Option<AttemptId>,
) -> Result<(Vec<EntityId>, Vec<String>), String> {
    let actor = run_writer(agent, attempt);
    let connection = StreamConnectionId(format!("run:{}", agent.to_hex()));
    crate::api::run_board_pins_for_test(server, actor, &connection, attempt).await
}

/// The entities the self brief of agent `agent`'s run of dispatch `attempt`
/// names among its board pins now (no slip woke it); `None` when they did
/// not read.
#[must_use]
pub fn run_brief_pins(
    server: &SyncServer,
    agent: EntityId,
    attempt: Option<AttemptId>,
) -> Option<Vec<EntityId>> {
    let handles = crate::api::run_brief_pins(server, run_writer(agent, attempt), None)?;
    Some(
        handles
            .into_iter()
            .filter_map(|handle| match handle {
                BriefWorkingHandle::BoardPin { entity, .. } => Some(entity),
                _ => None,
            })
            .collect(),
    )
}

/// The writer a pumped run of `agent` writes as: the agent, bound to the
/// dispatch attempt it serves (FIX 10537).
fn run_writer(agent: EntityId, attempt: Option<AttemptId>) -> WriteActor {
    let actor = WriteActor::new(agent, EdgeActorClass::Agent);
    match attempt {
        Some(attempt) => actor.with_run_attempt(*attempt.as_bytes()),
        None => actor,
    }
}
