//! The authenticated host handoff. No adapter policy lives in the engine.

use std::collections::BTreeSet;
use std::sync::Arc;

use oneiron::context_board::WakeEnvelope;

use serde::Deserialize;
use serde_json::{Value, json};

use super::{McpCallContext, McpGatewayError, mcp_params};
use crate::server::SyncServer;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WakePoll {
    instance_key: String,
    #[serde(default)]
    retained: Vec<WakeEnvelope>,
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
        let mut retained: Vec<WakeEnvelope> = {
            let polled: BTreeSet<&str> = wakes.iter().map(|wake| wake.event_ref.as_str()).collect();
            poll.retained
                .into_iter()
                .filter(|wake| !polled.contains(wake.event_ref.as_str()))
                .collect()
        };
        retained.extend(wakes);
        let mut delivery =
            crate::wake_adapters::board_stream::coalesced(&server, &actor, &connection, retained);
        // FIX 15011: the surviving batch's wake opener, on the vault clock
        // at this handoff.
        delivery.opener = oneiron::context_board::wake_batch_opener(
            &delivery.wakes,
            server.vault().now_recorded_ms(),
        );
        // A review wake or a room wake names no TASK row to release; it
        // carries ids only.
        let rows: Vec<_> = delivery
            .wakes
            .iter()
            .filter(|wake| wake.review_ref.is_none() && wake.room_ref.is_none())
            .filter_map(|wake| oneiron::EntityId::from_hex(&wake.task_ref).ok())
            .collect();
        super::device_release::mcp_release_result(&server, &actor, &rows, false, json!(delivery))
    })
    .await
    .map_err(|_| McpGatewayError::new(-32603, "engine_error", "wake read did not finish"))?
}
