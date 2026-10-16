//! The authenticated host handoff. No adapter policy lives in the engine.

use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use super::{McpCallContext, McpGatewayError, mcp_params};
use crate::server::SyncServer;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WakePoll {
    instance_key: String,
}

pub(super) async fn poll(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    params: Option<Value>,
) -> Result<Value, McpGatewayError> {
    let poll: WakePoll = mcp_params(params, "params")?;
    if poll.instance_key.len() != 64
        || !poll
            .instance_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "instance_key must be 64 lowercase hex characters",
        ));
    }
    let (connection, wakes) = {
        let mut registry = server.mcp_registry.lock().await;
        let connection = registry.bind_wake_instance(actor, &poll.instance_key);
        let wakes = registry.streams_mut().drain_wakes(&connection);
        (connection, wakes)
    };
    let server = Arc::clone(server);
    let actor = actor.clone();
    tokio::task::spawn_blocking(move || {
        let delivery =
            crate::wake_adapters::board_stream::coalesced(&server, &actor, &connection, wakes);
        let rows: Vec<_> = delivery
            .wakes
            .iter()
            .filter_map(|wake| oneiron::EntityId::from_hex(&wake.task_ref).ok())
            .collect();
        super::device_release::mcp_release_result(&server, &actor, &rows, false, json!(delivery))
    })
    .await
    .map_err(|_| McpGatewayError::new(-32603, "engine_error", "wake read did not finish"))?
}
