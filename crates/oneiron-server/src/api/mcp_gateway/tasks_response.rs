//! Tasks verb and response shaping.

use super::{
    McpCallContext, McpCarrierPolicy, McpGatewayError, execute_mcp_board_verb, mcp_current_board,
    mcp_endpoint_result, mcp_facade_error, mcp_page_cursor_error, mcp_preflight_page,
    mcp_request_id, mcp_resolve_page, mcp_scoped_tasks_section, mcp_verb_family_error,
};
use crate::api::parse_entity_id_param;
use crate::api::unix_seconds_now;
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

/// `tasks.*`: dispatched through the engine's gated TASKS facades, under the
/// credential's own world/facet ceiling.
fn execute_mcp_tasks_verb(
    server: &Arc<SyncServer>,
    args: &crate::mcp::McpVerbToolArgs,
    actor: &McpResolvedActor,
) -> Result<(Value, crate::mcp::McpPageSource), McpGatewayError> {
    let facade = server.vault.memory(actor.actor_ref, actor.actor_class);
    let arguments = &args.payload.arguments;
    match args.tool.binding {
        crate::mcp::McpVerbBinding::TasksCheck => {
            let section = facade.tasks_check().map_err(mcp_facade_error)?;
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
        // A direct expand by id is a READ producer with an enumerable row set,
        // so its whole result is retained and paged like any other continuable
        // read (ONE-1704 repair). It inherits no board scan cap, so it states
        // its own set complete.
        crate::mcp::McpVerbBinding::TasksExpand => {
            let lines = facade
                .tasks_expand(mcp_task_ref(arguments)?)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(lines.len());
            Ok((json!({ "kind": "expanded", "lines": lines }), source))
        }
        crate::mcp::McpVerbBinding::TasksAck => {
            let receipt = facade
                .tasks_ack(mcp_task_ref(arguments)?)
                .map_err(mcp_facade_error)?;
            Ok((
                json!({
                    "kind": "ack_receipt",
                    "task_ref": receipt.task_ref.to_hex(),
                    "acked": receipt.acked,
                }),
                crate::mcp::McpPageSource::complete(1),
            ))
        }
        crate::mcp::McpVerbBinding::TasksCancel => {
            let receipt = facade
                .tasks_cancel(oneiron::task_verb::TaskCancelTarget::Task(mcp_task_ref(
                    arguments,
                )?))
                .map_err(mcp_facade_error)?;
            Ok((
                json!({
                    "kind": "cancel_receipt",
                    "approval": receipt.approval.as_str(),
                    "effected": receipt.effected,
                    "proposal_ref": receipt.proposal_ref.map(|id| id.to_hex()),
                    "gate_decision_ref": receipt.gate_decision_ref,
                    "status": receipt
                        .status
                        .as_ref()
                        .map(|status| format!("{status:?}").to_ascii_lowercase()),
                }),
                crate::mcp::McpPageSource::complete(1),
            ))
        }
        crate::mcp::McpVerbBinding::TasksCreate => {
            let spec = arguments.spec.as_ref().ok_or_else(|| {
                McpGatewayError::new(-32602, "tool_args_invalid", "spec is required")
                    .with_field("arguments.spec")
            })?;
            let spec = oneiron::task_verb::TaskCreateSpec::new(
                oneiron::companion_value_from_json(spec).map_err(|error| {
                    mcp_engine_error("mcp tasks.create spec conversion failed", error)
                })?,
                arguments.label.clone(),
                Some(actor.actor_ref),
                Some(unix_seconds_now()),
            );
            let receipt = facade.tasks_create(&spec).map_err(mcp_facade_error)?;
            Ok((
                json!({
                    "kind": "create_receipt",
                    "task_ref": receipt.task_ref.map(|id| id.to_hex()),
                    "proposal_ref": receipt.proposal_ref.map(|id| id.to_hex()),
                    "approval": receipt.approval.as_str(),
                    "effected": receipt.effected,
                }),
                crate::mcp::McpPageSource::complete(1),
            ))
        }
        _ => Err(mcp_verb_family_error(args)),
    }
}

fn mcp_task_ref(
    arguments: &crate::mcp::McpVerbArguments,
) -> Result<oneiron::EntityId, McpGatewayError> {
    let task_ref = arguments.task_ref.as_deref().ok_or_else(|| {
        McpGatewayError::new(-32602, "tool_args_invalid", "task_ref is required")
            .with_field("arguments.task_ref")
    })?;
    parse_entity_id_param(task_ref, "arguments.task_ref").map_err(mcp_api_error)
}

/// One GENERATED verb tool call.
pub(crate) async fn execute_mcp_generated_verb(
    server: &Arc<SyncServer>,
    args: McpVerbToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    let argument_digest = crate::mcp::mcp_page_argument_digest(&args.payload);
    // Every continuable READ producer, and only those: a mutating or one-row
    // verb refuses a cursor at the pre-dispatch door below. `tasks.expand` is a
    // read whose rows are an enumerable set, so it continues under the same
    // retained-snapshot protocol as the board/task pages (ONE-1704 repair).
    let continuable = matches!(
        args.tool.binding,
        crate::mcp::McpVerbBinding::BoardExpand
            | crate::mcp::McpVerbBinding::TasksCheck
            | crate::mcp::McpVerbBinding::TasksExpand
    );
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
            let (output, source, carrier, producer_epoch) = match args.tool.family {
                crate::mcp::McpVerbFamily::Board => {
                    let (output, source, carrier, epoch) =
                        execute_mcp_board_verb(server, &args, actor).await?;
                    (output, source, carrier, Some(epoch))
                }
                crate::mcp::McpVerbFamily::Tasks => {
                    // Establish the board epoch before reading a continuable
                    // task set. The result itself is retained below, so a
                    // later continuation never re-reads mutable task rows.
                    let producer_epoch = if continuable {
                        Some(mcp_current_board(server, actor).await?.epoch)
                    } else {
                        None
                    };
                    let (output, source) = execute_mcp_tasks_verb(server, &args, actor)?;
                    (output, source, McpCarrierPolicy::Drain, producer_epoch)
                }
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
    let key = oneiron::claim::ScopedReadActorKey::with_actor_class(
        &actor.gate_actor_ref,
        actor.gate_actor_class,
    )
    .ok_or_else(|| {
        McpGatewayError::new(
            -32003,
            "mcp_actor_invalid",
            "resolved actor cannot be used as a scoped read key",
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
