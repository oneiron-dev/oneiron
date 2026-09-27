//! Tasks verb and response shaping.

use super::{
    McpCallContext, McpCarrierPolicy, McpGatewayError, execute_mcp_board_verb, mcp_current_board,
    mcp_endpoint_result, mcp_facade_error, mcp_page_cursor_error, mcp_preflight_page,
    mcp_request_id, mcp_resolve_page, mcp_scoped_tasks_section,
};
use crate::error::{ApiError, ApiErrorDetails, ErrorCode};
use crate::mcp::McpActorClass;
use crate::mcp::McpPageBudget;
use crate::mcp::McpPageSnapshot;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpVerbToolArgs;
use crate::server::SyncServer;
use oneiron::ErrorKind;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;

fn mcp_tasks_section(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
    section: oneiron::context_board::TasksSection,
) -> Result<(Value, crate::mcp::McpPageSource), McpGatewayError> {
    let (section, scope_omitted) = mcp_scoped_tasks_section(server, actor, section)?;
    // The footer type is `oneiron::context_board::tasks::TasksOverflow`,
    // whose module is private and which `context_board` does not
    // re-export, so the method item cannot be named from this crate.
    // Matching states the same optional line without a closure.
    let overflow_line = match section.overflow {
        Some(overflow) => overflow.line(),
        None => None,
    };
    // The producer's OWN honesty bits decide the end marker and the
    // health: a capped scan is degraded and non-terminal, never a
    // hard-coded healthy/complete. The render cap's omissions are a
    // WINDOW fact and stay apart from the requested scope's filtering
    // (ONE-1704 repair), so a caller can tell which one withheld rows.
    let window_truncated = section
        .overflow
        .map_or(0, |overflow| overflow.known_omitted_rows);
    let exhausted = section
        .overflow
        .is_none_or(|overflow| overflow.source_exhausted);
    let rows = section
        .rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "line": row.line,
                "status": row.status.as_str(),
                "is_intent": row.is_intent,
            })
        })
        .collect::<Vec<_>>();
    let source = crate::mcp::McpPageSource::scoped_window(
        rows.len(),
        scope_omitted,
        window_truncated,
        exhausted,
    );
    Ok((
        json!({
            "kind": "tasks_section",
            "count": rows.len(),
            "rows": rows,
            "overflow": overflow_line,
        }),
        source,
    ))
}

/// `describe`'s MCP result: the section arm through the scoped TASKS
/// projection above, the card arm as the engine encodes it, one page of lines.
fn mcp_describe_result(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
    description: oneiron::task_verb::TaskDescription,
) -> Result<(Value, crate::mcp::McpPageSource), McpGatewayError> {
    match description {
        oneiron::task_verb::TaskDescription::Section(section) => {
            mcp_tasks_section(server, actor, section)
        }
        oneiron::task_verb::TaskDescription::Card { lines } => {
            let source = crate::mcp::McpPageSource::complete(lines.len());
            let value = serde_json::to_value(oneiron::task_verb::TaskDescription::Card { lines })
                .map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source))
        }
    }
}

/// One GENERATED verb tool call.
pub(crate) async fn execute_mcp_generated_verb(
    server: &Arc<SyncServer>,
    args: McpVerbToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    let argument_digest = crate::mcp::mcp_page_argument_digest(&args.payload);
    // Every continuable READ producer, and only those: a mutating or one-row
    // verb refuses a cursor at the pre-dispatch door below. A `describe` card is
    // a read whose lines are an enumerable set, so it continues under the same
    // retained-snapshot protocol as the board/task pages (ONE-1704 repair).
    let continuable = args.tool.continuable();
    // This is deliberately before the board/tasks producer. A cursor presented
    // to a mutating or one-row verb is refused here, so it cannot hide a write
    // behind a later ToolMismatch/ArgumentsMismatch response.
    let mut dispatch = mcp_preflight_page(
        server,
        actor,
        args.tool.name,
        argument_digest,
        args.payload.page.as_ref(),
        continuable,
    )
    .await?;
    let (mut output, health, carrier, snapshot, producer_epoch) =
        if let Some(continuation) = dispatch.continuation.as_ref() {
            let snapshot = continuation.snapshot.clone().ok_or_else(|| {
                mcp_page_cursor_error(crate::mcp::McpPageCursorError::SnapshotMismatch)
            })?;
            let carrier = match snapshot.keyframe.clone() {
                Some(keyframe) => McpCarrierPolicy::FreshKeyframe(Some(keyframe)),
                None => McpCarrierPolicy::Drain,
            };
            (
                snapshot.output.clone(),
                snapshot.health,
                carrier,
                snapshot,
                None,
            )
        } else {
            let (output, source, carrier, producer_epoch) = if args.tool.memory_method().is_some() {
                let (output, capabilities) =
                    super::memory_response::execute(server, &args, actor).await?;
                // One native response, with its own bounded query/batch
                // semantics. Do not invent an MCP cursor over nested DTOs.
                (
                    output,
                    crate::mcp::McpPageSource::complete(1),
                    McpCarrierPolicy::DrainWithCapabilities(capabilities),
                    None,
                )
            } else {
                // Establish the board epoch before reading a continuable
                // task set. The result itself is retained below, so a
                // later continuation never re-reads mutable task rows.
                let task_epoch = if matches!(
                    args.tool.family,
                    crate::mcp::McpVerbFamily::Tasks | crate::mcp::McpVerbFamily::Handle
                ) && continuable
                {
                    Some(mcp_current_board(server, actor).await?.epoch)
                } else {
                    None
                };
                let (output, source, carrier, epoch) =
                    execute_mcp_agent_verb(server, &args, actor).await?;
                (output, source, carrier, epoch.or(task_epoch))
            };
            let snapshot = McpPageSnapshot {
                output: output.clone(),
                source,
                health: source.health(),
                keyframe: None,
            };
            (output, source.health(), carrier, snapshot, producer_epoch)
        };
    dispatch.producer_epoch = producer_epoch;
    let page = mcp_resolve_page(
        server,
        actor,
        args.tool.name,
        argument_digest,
        args.payload.page.as_ref(),
        &dispatch,
        &snapshot,
    )
    .await?;
    // The granted budget is ENFORCED here, not merely reported.
    mcp_cap_verb_rows(&mut output, &page);
    let structured = json!({
        "tool": args.tool.name,
        "family": args.tool.family.as_str(),
        "verb": args.tool.verb,
        "output": output,
        "actor": mcp_actor_result(actor),
        "meta": actor.metadata(
            health,
            page,
            vec!["call setup_oneiron on the primary endpoint for the whole grammar".to_owned()],
            args.payload.cache,
        ),
    });
    Ok(mcp_endpoint_result(
        server,
        actor,
        format!("{} completed", args.tool.name),
        structured,
        carrier,
    )
    .await)
}

/// Caps whichever row array this verb result pages over, in place.
///
/// A result that states `granted` and then ships more rows than that is the
/// fail-open this closes; the row count it reports is the count it returned.
fn mcp_cap_verb_rows(output: &mut Value, page: &McpPageBudget) {
    if let Some(rows) = output.as_array_mut() {
        *rows = page.cap(std::mem::take(rows));
        return;
    }
    for key in ["rows", "lines"] {
        let Some(rows) = output.get(key).and_then(Value::as_array).cloned() else {
            continue;
        };
        let capped = page.cap(rows);
        let Some(object) = output.as_object_mut() else {
            return;
        };
        if object.contains_key("count") {
            object.insert("count".to_owned(), Value::from(capped.len()));
        }
        object.insert(key.to_owned(), Value::Array(capped));
        return;
    }
}

pub(crate) fn mcp_scoped_read<'a>(
    vault: &'a oneiron::Vault,
    actor: &McpResolvedActor,
) -> Result<oneiron::claim::ScopedRead<'a>, McpGatewayError> {
    let key = actor
        .auth
        .as_ref()
        .and_then(crate::auth::CoreAuth::verified_slip)
        .and_then(oneiron::claim::ScopedReadActorKey::from_verified_slip)
        .ok_or_else(|| {
            McpGatewayError::new(
                -32001,
                "mcp_auth_required",
                "scoped reads require the authenticated connector proof",
            )
        })?;
    Ok(vault.scoped_read(key))
}

pub(crate) fn mcp_actor_result(actor: &McpResolvedActor) -> Value {
    json!({
        "actor_ref": actor.actor_ref.to_hex(),
        "actor_class": actor.gate_actor_class,
        "gate_actor_ref": actor.gate_actor_ref,
        "gate_actor_class": actor.gate_actor_class,
        "scope": {
            "world_ref": actor.scope.world_ref.map(|id| id.to_hex()),
            "facet_ref": actor.scope.facet_ref.map(|id| id.to_hex()),
        },
    })
}

pub(crate) fn mcp_actor_class_wire(actor_class: McpActorClass) -> &'static str {
    match actor_class {
        McpActorClass::Human => "human",
        McpActorClass::Agent => "agent",
    }
}

pub(crate) fn mcp_text_content(text: impl Into<String>) -> Value {
    json!({
        "type": "text",
        "text": text.into(),
    })
}

pub(crate) fn mcp_api_error(error: ApiError) -> McpGatewayError {
    let code = match error.code() {
        ErrorCode::BadRequest => -32602,
        ErrorCode::NotFound => -32004,
        ErrorCode::InvalidState => -32020,
        ErrorCode::InternalServerError => -32603,
        _ => -32000,
    };
    let mut gateway = McpGatewayError::new(code, error.code().as_str(), error.message());
    if let ApiErrorDetails::BadRequest { field } = error.details()
        && let Some(field) = field
    {
        gateway = gateway.with_field(field.clone());
    }
    gateway
}

pub(crate) fn mcp_engine_error(context: &'static str, error: oneiron::Error) -> McpGatewayError {
    // ONE-1936: a stale write-verb target gets its own stable kind, not the
    // generic engine_error bucket, and carries the current head as data. The
    // caller re-gets that ref and decides again; nothing was written.
    if let oneiron::Error::Claim(oneiron::error::ClaimError::WriteVerbTargetStale {
        successor_short_id,
        ..
    }) = &error
    {
        return McpGatewayError::new(-32020, "write_verb_target_stale", error.to_string())
            .with_successor_short_id(successor_short_id.clone());
    }
    match error.kind() {
        ErrorKind::GateWriteRejected => {
            McpGatewayError::new(-32020, "gate_write_rejected", error.to_string())
        }
        ErrorKind::GateConsentStale => {
            McpGatewayError::new(-32020, "gate_consent_stale", error.to_string())
        }
        ErrorKind::EntityNotFound => {
            McpGatewayError::new(-32004, "entity_not_found", error.to_string())
        }
        _ => McpGatewayError::new(-32603, "engine_error", format!("{context}: {error}")),
    }
}

/// Every structured refusal states the same four things: the machine code, the
/// human sentence, what to do next, and which request under which scope.
pub(crate) fn mcp_error_response(id: Value, error: McpGatewayError) -> Value {
    let mut data = json!({
        "kind": error.kind,
        "error_code": error.kind,
        "human_message": error.message,
        "recovery_suggestions": crate::mcp::mcp_recovery_suggestions(error.kind),
        "request_id": mcp_request_id(&id),
    });
    if let Some(field) = error.field
        && let Some(object) = data.as_object_mut()
    {
        object.insert("field".to_owned(), Value::String(field));
    }
    if let Some(native) = error.vault_read
        && let Some(object) = data.as_object_mut()
    {
        object.insert("vault_read".to_owned(), json!(*native));
    }
    if let Some(successor_short_id) = error.successor_short_id
        && let Some(object) = data.as_object_mut()
    {
        object.insert(
            "successor_short_id".to_owned(),
            Value::String(successor_short_id),
        );
    }
    if let Some(effective_scope) = error.effective_scope
        && let Some(object) = data.as_object_mut()
    {
        object.insert("effective_scope".to_owned(), *effective_scope);
    }
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": error.code,
            "message": error.message,
            "data": data,
        },
    })
}

// BEGIN GENERATED MCP DISPATCH
async fn execute_mcp_agent_verb(
    server: &Arc<SyncServer>,
    args: &McpVerbToolArgs,
    actor: &McpCallContext,
) -> Result<
    (
        Value,
        crate::mcp::McpPageSource,
        McpCarrierPolicy,
        Option<u64>,
    ),
    McpGatewayError,
> {
    let a = &args.payload.arguments;
    let invalid = || {
        McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "invalid typed agent-verb argument",
        )
    };
    let memory = server.vault.memory(actor.actor_ref, actor.actor_class);
    match args.tool.name {
        "board.expand" => {
            let input: oneiron::task_verb::sdk::BoardExpandRequest = serde_json::from_value(json!({"key":a.key.clone().ok_or_else(invalid)?,"frame_epoch":a.frame_epoch.clone()})).map_err(|_| invalid())?;

            execute_mcp_board_verb(server, actor, |context| {
                oneiron::task_verb::sdk::board_expand(context, input)
            })
            .await
        }
        "board.refresh" => {
            let input: oneiron::task_verb::sdk::BoardRefreshRequest =
                serde_json::from_value(json!({"frame_epoch":a.frame_epoch.clone()}))
                    .map_err(|_| invalid())?;

            execute_mcp_board_verb(server, actor, |context| {
                oneiron::task_verb::sdk::board_refresh(context, input)
            })
            .await
        }
        "board.subscribe" => {
            let input: oneiron::task_verb::sdk::BoardSubscriptionRequest =
                serde_json::from_value(json!({"scopes":a.scopes.clone().ok_or_else(invalid)?}))
                    .map_err(|_| invalid())?;

            execute_mcp_board_verb(server, actor, |context| {
                oneiron::task_verb::sdk::board_subscribe(context, input)
            })
            .await
        }
        "board.unsubscribe" => {
            let input: oneiron::task_verb::sdk::BoardSubscriptionRequest =
                serde_json::from_value(json!({"scopes":a.scopes.clone().ok_or_else(invalid)?}))
                    .map_err(|_| invalid())?;

            execute_mcp_board_verb(server, actor, |context| {
                oneiron::task_verb::sdk::board_unsubscribe(context, input)
            })
            .await
        }
        "cancel" => {
            let input: oneiron::task_verb::sdk::TaskRequest =
                serde_json::from_value(json!({"task_ref":a.task_ref.clone().ok_or_else(invalid)?}))
                    .map_err(|_| invalid())?;

            let output =
                oneiron::task_verb::sdk::cancel(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "describe" => {
            let input: oneiron::task_verb::sdk::DescribeRequest =
                serde_json::from_value(json!({"task_ref":a.task_ref.clone()}))
                    .map_err(|_| invalid())?;

            let output =
                oneiron::task_verb::sdk::describe(&memory, input).map_err(mcp_facade_error)?;
            let (value, source) = mcp_describe_result(server, actor, output)?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "tasks.create" => {
            let input: oneiron::task_verb::sdk::TaskCreateRequest = serde_json::from_value(
                json!({"spec":a.spec.clone().ok_or_else(invalid)?,"label":a.label.clone()}),
            )
            .map_err(|_| invalid())?;

            let output =
                oneiron::task_verb::sdk::tasks_create(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "tasks.update" => {
            let input: oneiron::task_verb::sdk::TaskRequest =
                serde_json::from_value(json!({"task_ref":a.task_ref.clone().ok_or_else(invalid)?}))
                    .map_err(|_| invalid())?;

            let output =
                oneiron::task_verb::sdk::tasks_update(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "tasks.ask" => {
            let input: oneiron::task_verb::sdk::TaskAskRequest =
                serde_json::from_value(a.spec.clone().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;

            let output =
                oneiron::task_verb::sdk::tasks_ask(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "tasks.wait" => {
            let input: oneiron::task_verb::sdk::TaskWaitRequest =
                serde_json::from_value(a.spec.clone().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;

            let output =
                oneiron::task_verb::sdk::tasks_wait(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "tasks.answer" => {
            let input: oneiron::task_verb::sdk::TaskAnswerRequest =
                serde_json::from_value(a.spec.clone().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;

            let output =
                oneiron::task_verb::sdk::tasks_answer(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "tasks.outcomes" => {
            let input: oneiron::task_verb::TaskAskHandle =
                serde_json::from_value(a.spec.clone().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;

            let output = oneiron::task_verb::sdk::tasks_outcomes(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "rooms.list" => {
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(json!({})).map_err(|_| invalid())?;

            let output =
                oneiron::task_verb::sdk::rooms_list(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "rooms.messages" => {
            let input: oneiron::task_verb::sdk::RoomRequest = serde_json::from_value(json!({"room_ref":a.room_ref.clone().ok_or_else(invalid)?,"after":a.turn_ref.clone()})).map_err(|_| invalid())?;

            let output = oneiron::task_verb::sdk::rooms_messages(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::scoped_window(
                output.rows.len(),
                0,
                0,
                output.next_after.is_none(),
            );
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "rooms.claim" => {
            let input: oneiron::task_verb::sdk::RoomClaimRequest = serde_json::from_value(json!({"room_ref":a.room_ref.clone().ok_or_else(invalid)?,"turn_ref":a.turn_ref.clone().ok_or_else(invalid)?})).map_err(|_| invalid())?;

            let output =
                oneiron::task_verb::sdk::rooms_claim(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "rooms.speak" => {
            let input: oneiron::memory::WitnessTurn =
                serde_json::from_value(a.spec.clone().ok_or_else(invalid)?)
                    .map_err(|_| invalid())?;
            if a.room_ref.as_deref() != Some(input.conversation_ref.as_str()) {
                return Err(invalid());
            }
            let output =
                oneiron::task_verb::sdk::rooms_speak(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            let value = serde_json::to_value(output).map_err(|_| {
                McpGatewayError::new(
                    -32603,
                    "engine_error",
                    "typed agent result cannot be encoded",
                )
            })?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        _ => Err(invalid()),
    }
}

// END GENERATED MCP DISPATCH
