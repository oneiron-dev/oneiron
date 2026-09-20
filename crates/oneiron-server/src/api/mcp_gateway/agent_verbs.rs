//! MCP framing over the same generated agent SDK dispatcher as every other wire.
use super::{McpGatewayError, mcp_facade_error};
use crate::mcp::{McpPageSource, McpResolvedActor, McpVerbBinding, McpVerbToolArgs};
use crate::server::SyncServer;
use serde_json::{Value, json};
pub(super) fn execute(
    server: &SyncServer,
    args: &McpVerbToolArgs,
    actor: &McpResolvedActor,
) -> Result<(Value, McpPageSource), McpGatewayError> {
    let a = &args.payload.arguments;
    let invalid = || {
        McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "invalid typed agent-verb argument",
        )
    };
    let input = match args.tool.binding {
        McpVerbBinding::TasksAsk | McpVerbBinding::TasksAnswer => {
            a.spec.clone().ok_or_else(invalid)?
        }
        McpVerbBinding::TasksWait => {
            json!({"handle":{"task_ref":a.task_ref.as_deref().ok_or_else(invalid)?},"step_key":a.key.as_deref().ok_or_else(invalid)?})
        }
        McpVerbBinding::TasksOutcomes => {
            json!({"task_ref":a.task_ref.as_deref().ok_or_else(invalid)?})
        }
        McpVerbBinding::RoomsList => json!({}),
        McpVerbBinding::RoomsMessages => {
            json!({"room_ref":a.room_ref.as_deref().ok_or_else(invalid)?,"after":a.turn_ref})
        }
        McpVerbBinding::RoomsClaim => {
            json!({"room_ref":a.room_ref.as_deref().ok_or_else(invalid)?,"turn_ref":a.turn_ref.as_deref().ok_or_else(invalid)?})
        }
        McpVerbBinding::RoomsSpeak => {
            let turn = a.spec.clone().ok_or_else(invalid)?;
            if turn.get("conversation_ref").and_then(Value::as_str) != a.room_ref.as_deref() {
                return Err(invalid());
            }
            turn
        }
        _ => return Err(invalid()),
    };
    let memory = server.vault.memory(actor.actor_ref, actor.actor_class);
    let result = oneiron::task_verb::sdk::invoke(&memory, args.tool.name, input)
        .map_err(mcp_facade_error)?;
    let output = match args.tool.binding {
        McpVerbBinding::TasksAsk => json!({"kind":"ask_receipt","receipt":result}),
        McpVerbBinding::TasksWait => json!({"kind":"step_wait","receipt":result}),
        McpVerbBinding::TasksAnswer => json!({"kind":"answer_receipt","receipt":result}),
        McpVerbBinding::TasksOutcomes => json!({"kind":"ask_outcomes","rows":result}),
        McpVerbBinding::RoomsList => json!({"kind":"rooms","rows":result}),
        McpVerbBinding::RoomsMessages => json!({"kind":"room_turns","rows":result}),
        McpVerbBinding::RoomsSpeak => json!({"kind":"speak_receipt","receipt":result}),
        McpVerbBinding::RoomsClaim => {
            if let Some(receipt) = result.get("Claimed") {
                json!({"kind":"claimed","receipt":receipt})
            } else if let Some(receipt) = result.get("HeldBy") {
                json!({"kind":"held_by","receipt":receipt})
            } else {
                json!({"kind":"not_addressed"})
            }
        }
        _ => return Err(invalid()),
    };
    let count = output
        .get("rows")
        .and_then(Value::as_array)
        .map_or(1, Vec::len);
    let source = if args.tool.binding == McpVerbBinding::RoomsMessages && count == 256 {
        // Storage caps the producer before MCP's response budget. Continue
        // with arguments.turn_ref set to the last returned turn id.
        McpPageSource::scoped_window(count, 0, 0, false)
    } else {
        McpPageSource::complete(count)
    };
    Ok((output, source))
}
