//! Public run-bound board STREAM doors: `self.focus.refresh`,
//! `self.focus.subscribe`, `self.focus.unsubscribe` and `self.focus.wakes`
//! on the caller's own attached live run.
//!
//! Each call holds the run through the same live-run attachment guard as
//! the fold and browser doors, then runs the engine's own board verb
//! dispatcher over the run's STREAM connection (`run:<run id>`, the
//! connection the run's host door serves), so one connection holds one
//! subscription set and one carrier epoch across both doors. A wake is
//! re-read under this credential at delivery and dropped when its TASK
//! no longer reads, exactly as the MCP wake handoff drops it.
use std::sync::Arc;

use oneiron::board_verb::BoardVerbCall;
use oneiron::context_board::{StreamConnectionId, SubscriptionScope, WakeEnvelope};
use oneiron::memory::MemoryResult;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::{
    BoardFrameReply, BoardRefreshRequest, BoardSubscriptionReply, BoardSubscriptionRequest,
    BoardWakeReply, BoardWakeRequest, LiveRunRequest,
};
use oneiron::{EdgeActorClass, EntityId, WriteActor};
use serde_json::Value;

use super::host_doors::internal;
use super::live_run_doors::hold_live_run;
use crate::auth::CoreAuth;
use crate::server::SyncServer;

/// The run's own board STREAM connection, as its host door names it.
fn run_connection(run_id: EntityId) -> StreamConnectionId {
    StreamConnectionId(format!("run:{}", run_id.to_hex()))
}

/// One board verb on the attached run, answered as the verb's wire value
/// and the writer it ran as. The hook blocks the answer shows are spent
/// once it clears, as a pumped run's own board row spends them.
async fn on_run_board(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    live_run: String,
    call: BoardVerbCall,
) -> MemoryResult<(WriteActor, StreamConnectionId, Value)> {
    let (writer, run, held) = hold_live_run(server, auth, None, &live_run).await?;
    let connection = run_connection(run.run_id());
    let mut hooks = None;
    let (value, _rows) =
        crate::api::execute_run_board_verb(server, writer, &connection, call, &mut hooks).await?;
    if let Some(hooks) = hooks {
        crate::api::deliver_run_board_hooks(server, hooks).await?;
    }
    drop(held);
    Ok((writer, connection, value))
}

pub(crate) async fn self_focus_refresh(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: LiveRunRequest<BoardRefreshRequest>,
) -> MemoryResult<BoardFrameReply> {
    let (_, _, value) = on_run_board(
        server,
        auth,
        input.live_run,
        BoardVerbCall::Refresh {
            frame_epoch: input.spec.frame_epoch,
        },
    )
    .await?;
    let frame = value
        .get("frame")
        .cloned()
        .ok_or_else(|| internal("self.focus.refresh"))?;
    let frame = serde_json::from_value(frame).map_err(|_| internal("self.focus.refresh"))?;
    Ok(BoardFrameReply { frame })
}

async fn subscription(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    verb: &'static str,
    input: LiveRunRequest<BoardSubscriptionRequest>,
    subscribe: bool,
) -> MemoryResult<BoardSubscriptionReply> {
    let scopes = input.spec.scopes;
    let call = if subscribe {
        BoardVerbCall::Subscribe { scopes }
    } else {
        BoardVerbCall::Unsubscribe { scopes }
    };
    let (_, connection, value) = on_run_board(server, auth, input.live_run, call).await?;
    let active = value.get("active").cloned().ok_or_else(|| internal(verb))?;
    let active = serde_json::from_value(active).map_err(|_| internal(verb))?;
    Ok(BoardSubscriptionReply {
        connection: connection.0,
        active,
    })
}

pub(crate) async fn self_focus_subscribe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: LiveRunRequest<BoardSubscriptionRequest>,
) -> MemoryResult<BoardSubscriptionReply> {
    subscription(server, auth, "self.focus.subscribe", input, true).await
}

pub(crate) async fn self_focus_unsubscribe(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: LiveRunRequest<BoardSubscriptionRequest>,
) -> MemoryResult<BoardSubscriptionReply> {
    subscription(server, auth, "self.focus.unsubscribe", input, false).await
}

/// The subscription scope one wake was minted under, from its envelope id
/// (`<task id>:<arrived|failed>:<revision>`), as the MCP wake handoff reads it.
fn wake_scope(wake: &WakeEnvelope) -> Option<SubscriptionScope> {
    let event = wake
        .event_ref
        .strip_prefix(&format!("{}:", wake.task_ref))?;
    match event.split_once(':') {
        Some(("failed", _)) => Some(SubscriptionScope::MyTasks),
        Some(("arrived", _)) => Some(SubscriptionScope::ConsultsToMe),
        _ => None,
    }
}

pub(crate) async fn self_focus_wakes(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    _caller: (EntityId, EdgeActorClass),
    _invocation: Option<InvocationId>,
    input: LiveRunRequest<BoardWakeRequest>,
) -> MemoryResult<BoardWakeReply> {
    let (writer, run, held) = hold_live_run(server, auth, None, &input.live_run).await?;
    let connection = run_connection(run.run_id());
    let (subscribed, wakes) = {
        let mut registry = server.mcp_registry.lock().await;
        let subscribed = registry
            .streams_mut()
            .connection_state(&connection)
            .map(|state| state.subscribed.clone())
            .unwrap_or_default();
        let wakes = registry.streams_mut().drain_wakes(&connection);
        (subscribed, wakes)
    };
    // An envelope is a notice, not a read grant: each TASK is read again
    // under this credential now, and a wake whose scope the connection no
    // longer holds, or whose TASK no longer reads, is dropped.
    let (server, auth) = (Arc::clone(server), auth.clone());
    let wakes = tokio::task::spawn_blocking(move || -> MemoryResult<Vec<WakeEnvelope>> {
        let memory = crate::api::credential_memory(
            server.vault(),
            Some(&auth),
            writer.entity_ref(),
            writer.actor_class(),
        )
        .at(auth.locality());
        let mut kept = Vec::new();
        for wake in wakes {
            if wake.actor_ref != writer.entity_ref().to_hex() {
                continue;
            }
            if !wake_scope(&wake).is_some_and(|scope| subscribed.contains(&scope)) {
                continue;
            }
            let Ok(task) = EntityId::from_hex(&wake.task_ref) else {
                continue;
            };
            if memory.get_entity(&task.to_hex())?.value.is_none() {
                continue;
            }
            kept.push(wake);
        }
        Ok(kept)
    })
    .await
    .map_err(|_| internal("self.focus.wakes"))??;
    drop(held);
    Ok(BoardWakeReply { wakes })
}
