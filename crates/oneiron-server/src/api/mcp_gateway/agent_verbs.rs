//! Generated agent verbs retain facade identity and membership gates.
use super::{McpGatewayError, mcp_api_error, mcp_facade_error};
use crate::mcp::{McpPageSource, McpResolvedActor, McpVerbBinding, McpVerbToolArgs};
use crate::server::SyncServer;
use serde_json::{Value, json};
pub(super) fn execute(
    server: &SyncServer,
    args: &McpVerbToolArgs,
    actor: &McpResolvedActor,
) -> Result<(Value, McpPageSource), McpGatewayError> {
    let memory = server.vault.memory(actor.actor_ref, actor.actor_class);
    let a = &args.payload.arguments;
    let invalid = || {
        McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "invalid typed agent-verb argument",
        )
    };
    let parse = |s: Option<&str>, field: &'static str| {
        crate::api::parse_entity_id_param(s.ok_or_else(invalid)?, field).map_err(mcp_api_error)
    };
    let output = match args.tool.binding {
        McpVerbBinding::TasksAsk => {
            let spec: oneiron::task_verb::TaskAskSpec =
                serde_json::from_value(a.spec.clone().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            json!({"kind":"ask_receipt","receipt":memory.tasks_ask(&spec).map_err(mcp_facade_error)?})
        }
        McpVerbBinding::TasksWait => {
            let handle = oneiron::task_verb::TaskAskHandle {
                task_ref: parse(a.task_ref.as_deref(), "arguments.task_ref")?.to_hex(),
            };
            json!({"kind":"step_wait","receipt":memory.tasks_wait_external(&handle,a.key.as_deref().ok_or_else(invalid)?).map_err(mcp_facade_error)?})
        }
        McpVerbBinding::RoomsList => {
            let rooms = memory.rooms_list().map_err(mcp_facade_error)?;
            json!({"kind":"rooms","rows":rooms.into_iter().map(|(id,room)|json!({"id":id.to_hex(),"room":room})).collect::<Vec<_>>()})
        }
        McpVerbBinding::RoomsMessages => {
            json!({"kind":"room_turns","rows":memory.rooms_messages(parse(a.room_ref.as_deref(),"arguments.room_ref")?).map_err(mcp_facade_error)?})
        }
        McpVerbBinding::RoomsClaim => {
            let receipt = memory
                .rooms_claim(
                    parse(a.room_ref.as_deref(), "arguments.room_ref")?,
                    parse(a.turn_ref.as_deref(), "arguments.turn_ref")?,
                    crate::api::unix_seconds_now(),
                )
                .map_err(mcp_facade_error)?;
            use oneiron::workspace_roster::RoomClaimOutcome;
            match receipt {
                RoomClaimOutcome::Claimed(r) => json!({"kind":"claimed","receipt":r}),
                RoomClaimOutcome::HeldBy(r) => json!({"kind":"held_by","receipt":r}),
                RoomClaimOutcome::NotAddressed => json!({"kind":"not_addressed"}),
            }
        }
        McpVerbBinding::RoomsSpeak => {
            let room = parse(a.room_ref.as_deref(), "arguments.room_ref")?;
            let turn: oneiron::WitnessTurn =
                serde_json::from_value(a.spec.clone().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            if turn.conversation_ref != room.to_hex() {
                return Err(invalid());
            }
            json!({"kind":"speak_receipt","receipt":memory.rooms_speak(&turn).map_err(mcp_facade_error)?})
        }
        _ => return Err(invalid()),
    };
    let count = output
        .get("rows")
        .and_then(Value::as_array)
        .map_or(1, Vec::len);
    Ok((output, McpPageSource::complete(count)))
}
