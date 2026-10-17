//! Tasks verb and response shaping.

use super::{
    McpCallContext, McpCarrierPolicy, McpGatewayError, execute_mcp_board_verb, mcp_current_board,
    mcp_endpoint_result, mcp_page_cursor_error, mcp_preflight_page, mcp_release_result,
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
    rows: oneiron::context_board::TasksSectionRows,
    served: &mut Vec<oneiron::EntityId>,
) -> Result<(Value, crate::mcp::McpPageSource), McpGatewayError> {
    let (section, scope_omitted) = mcp_scoped_tasks_section(server, actor, rows, &[], served)?;
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
    )
    .rows_at("rows");
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

/// `describe`'s MCP result for one card, as the engine encodes it, one page
/// of lines. The section is narrowed from its rows (`mcp_tasks_section`),
/// never from a section the engine already capped.
fn mcp_describe_result(
    description: oneiron::task_verb::TaskDescription,
) -> Result<(Value, crate::mcp::McpPageSource), McpGatewayError> {
    match description {
        oneiron::task_verb::TaskDescription::Section(_) => Err(McpGatewayError::new(
            -32603,
            "engine_error",
            "describe of one task returned the TASKS section",
        )),
        oneiron::task_verb::TaskDescription::SelfCard { tail } => {
            let value =
                serde_json::to_value(oneiron::task_verb::TaskDescription::SelfCard { tail })
                    .map_err(|_| {
                        McpGatewayError::new(
                            -32603,
                            "engine_error",
                            "typed agent result cannot be encoded",
                        )
                    })?;
            Ok((value, crate::mcp::McpPageSource::complete(1)))
        }
        oneiron::task_verb::TaskDescription::Card { lines } => {
            let source = crate::mcp::McpPageSource::complete(lines.len()).rows_at("lines");
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
    let mut served = Vec::new();
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
                let (output, capabilities, producers) =
                    super::memory_response::execute(server, &args, actor).await?;
                served.extend(producers);
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
                let produced = execute_mcp_agent_verb(server, &args, actor, &mut served).await;
                let produced = match produced {
                    // A verb hook's stop is a result the client reads, not a
                    // refusal (ARCH-0080 §3).
                    Err(McpGatewayError {
                        hook: Some(stop), ..
                    }) => return mcp_hook_stop_result(server, &args, actor, *stop, &served),
                    produced => produced,
                };
                // A refusal is released by the rows its verb served first.
                let (output, source, carrier, epoch) = produced.map_err(|error| {
                    super::device_release::mcp_release_error(
                        server,
                        actor,
                        Some(served.as_slice()),
                        error,
                    )
                })?;
                (output, source, carrier, epoch.or(task_epoch))
            };
            let snapshot = McpPageSnapshot {
                output: output.clone(),
                source,
                health: source.health(),
                keyframe: None,
                rows: served,
            };
            (output, source.health(), carrier, snapshot, producer_epoch)
        };
    dispatch.producer_epoch = producer_epoch;
    let mut page = mcp_resolve_page(
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
    mcp_cap_verb_rows(&mut output, &mut page, snapshot.source);
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
    let continued = dispatch.continuation.is_some();
    let result = mcp_endpoint_result(
        server,
        actor,
        format!("{} completed", args.tool.name),
        structured,
        carrier,
    )
    .await;
    mcp_release_result(server, actor, &snapshot.rows, continued, result)
}

/// Caps the row array this verb result pages over, in place: the output itself
/// when it is an array, else the key its producer names (a generated verb's
/// comes from its manifest `page`). A single record has none and passes whole.
///
/// A result that states `granted` and then ships more rows than that is the
/// fail-open this closes; the row count it reports is the count it returned.
/// A producer's own continuation is named only on the page that ends the
/// retained window. Inside it the opaque cursor is the way on, and the
/// producer's continuation would skip the rows still retained, so the output
/// carries none there.
fn mcp_cap_verb_rows(
    output: &mut Value,
    page: &mut McpPageBudget,
    source: crate::mcp::McpPageSource,
) {
    if let Some(rows) = output.as_array_mut() {
        *rows = page.cap(std::mem::take(rows));
        return;
    }
    let Some(object) = output.as_object_mut() else {
        return;
    };
    if let Some(Value::Array(rows)) = source.rows.and_then(|key| object.get_mut(key)) {
        *rows = page.cap(std::mem::take(rows));
        let count = rows.len();
        if object.contains_key("count") {
            object.insert("count".to_owned(), Value::from(count));
        }
    }
    if let Some(resume) = source.resume {
        if page.successor_position().is_some() {
            object.insert(resume.field.to_owned(), Value::Null);
        } else if let Some(value) = object.get(resume.field).filter(|value| !value.is_null()) {
            page.resume_with(resume.argument, value.clone());
        }
    }
}

pub(crate) fn mcp_scoped_read<'a>(
    vault: &'a oneiron::Vault,
    actor: &McpResolvedActor,
) -> Result<oneiron::claim::ScopedRead<'a>, McpGatewayError> {
    let refused = || {
        McpGatewayError::new(
            -32001,
            "mcp_auth_required",
            "scoped reads require the authenticated connector proof",
        )
    };
    let proof = actor
        .auth
        .as_ref()
        .and_then(crate::auth::CoreAuth::verified_slip)
        .ok_or_else(refused)?;
    let key = vault
        .credential_read_key(proof)
        .map_err(|error| McpGatewayError::new(-32603, "engine_error", error.to_string()))?
        .ok_or_else(refused)?;
    Ok(vault.scoped_read(key.at(actor.locality())))
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

/// Maps a typed engine facade error onto the gateway's JSON-RPC vocabulary.
pub(crate) fn mcp_facade_error(error: oneiron::MemoryError) -> McpGatewayError {
    if let Some(stop) = error.hook {
        return mcp_hook_stop(*stop);
    }
    if let Some(correction) = error.wrong_root {
        let mut refusal = McpGatewayError::new(-32601, "wrong_root", error.message);
        refusal.wrong_root = Some(correction);
        return refusal;
    }
    let code = match error.code.as_str() {
        oneiron::MEMORY_CODE_NOT_FOUND => -32004,
        // OF-123: an effect whose person is not settled yet is a typed
        // refusal like these, never an argument error; its kind below names it.
        oneiron::MEMORY_CODE_FORBIDDEN
        | oneiron::memory::MEMORY_CODE_OWNER_BINDING_REQUIRED
        | oneiron::memory::MEMORY_CODE_BUDGET_SPENT
        | oneiron::memory::MEMORY_CODE_IDENTITY_UNSETTLED
        | oneiron::MEMORY_CODE_INVALID_STATE => -32020,
        oneiron::MEMORY_CODE_INTERNAL | oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE => -32603,
        _ => -32602,
    };
    // A paid call's own refusals keep their names: a client tells a spent
    // line from a model that did not answer without reading the sentence.
    let kind = match error.code.as_str() {
        oneiron::memory::MEMORY_CODE_BUDGET_SPENT => Some("budget_spent"),
        oneiron::memory::MEMORY_CODE_MODEL_UNAVAILABLE => Some("model_unavailable"),
        // OF-123: an effect whose person is not settled yet keeps its name
        // too, so an agent reads it as `error.data.error_code`, not prose.
        oneiron::memory::MEMORY_CODE_IDENTITY_UNSETTLED => Some("identity_unsettled"),
        _ => None,
    };
    if let Some(kind) = kind {
        return McpGatewayError::new(code, kind, error.message);
    }
    // A facade refusal carrying a successor keeps the same stable kind and
    // typed data the engine-error path emits (ONE-1936) — one vocabulary for
    // one condition, whichever door reported it.
    match error.successor_short_id {
        Some(successor_short_id) => {
            McpGatewayError::new(code, "write_verb_target_stale", error.message)
                .with_successor_short_id(successor_short_id)
        }
        None => McpGatewayError::new(code, "facade_error", error.message),
    }
}

/// A verb hook's stop as a gateway refusal (ARCH-0080 §3): its stable kind,
/// and the typed stop a code-mode door hands back to its run.
pub(crate) fn mcp_hook_stop(stop: oneiron::runtime_hooks::VerbHookStop) -> McpGatewayError {
    use oneiron::runtime_hooks::VerbHookStop;
    let kind = match &stop {
        VerbHookStop::Skipped { .. } => "verb_hook_skipped",
        VerbHookStop::Pending { .. } => "verb_hook_pending",
        VerbHookStop::Hidden { .. } => "verb_hook_hidden",
        // The call ran once its ask settled; the stop carries its outcome.
        VerbHookStop::Completed { .. } => "verb_hook_completed",
        VerbHookStop::CompletedWithError { .. } => "verb_hook_completed_with_error",
    };
    let mut error = McpGatewayError::new(-32020, kind, stop.to_string());
    error.hook = Some(Box::new(stop));
    error
}

/// A verb hook's stop as the tool result a client reads (ARCH-0080 §3): the
/// verb gave no output, so `isError` is set, and `structuredContent.hook`
/// carries the typed stop, a pending ask's invocation and handle included.
fn mcp_hook_stop_result(
    server: &Arc<SyncServer>,
    args: &McpVerbToolArgs,
    actor: &McpCallContext,
    stop: oneiron::runtime_hooks::VerbHookStop,
    served: &[oneiron::EntityId],
) -> Result<Value, McpGatewayError> {
    let text = stop.to_string();
    let structured = json!({
        "tool": args.tool.name,
        "family": args.tool.family.as_str(),
        "verb": args.tool.verb,
        "hook": stop,
        "actor": mcp_actor_result(actor),
    });
    let result = json!({
        "content": [mcp_text_content(text)],
        "structuredContent": structured,
        "isError": true,
    });
    mcp_release_result(server, actor, served, false, result)
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
    if let Some(bound) = error.byte_bound
        && let Some(object) = data.as_object_mut()
    {
        let (max_bytes, received_bytes) = *bound;
        object.insert("max_bytes".to_owned(), json!(max_bytes));
        object.insert("received_bytes".to_owned(), json!(received_bytes));
    }
    if let Some(correction) = error.wrong_root
        && let Some(object) = data.as_object_mut()
    {
        object.insert("attempted".to_owned(), Value::String(correction.attempted));
        object.insert(
            "replacement".to_owned(),
            Value::String(correction.replacement),
        );
        object.insert("schemaRef".to_owned(), Value::String(correction.schema_ref));
    }
    if let Some(stamp) = error.call_receipt
        && let Some(object) = data.as_object_mut()
    {
        stamp.stamp_json(object);
    }
    if let Some(stop) = error.hook
        && let Some(object) = data.as_object_mut()
    {
        object.insert("hook".to_owned(), json!(*stop));
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
/// A `tools/call` of one generated verb: its arguments assemble the verb's typed
/// input, which then takes the one dispatcher every MCP door shares.
async fn execute_mcp_agent_verb(
    server: &Arc<SyncServer>,
    args: &McpVerbToolArgs,
    actor: &McpCallContext,
    served: &mut Vec<oneiron::EntityId>,
) -> Result<
    (
        Value,
        crate::mcp::McpPageSource,
        McpCarrierPolicy,
        Option<u64>,
    ),
    McpGatewayError,
> {
    let input = mcp_agent_verb_input(args.tool.name, &args.payload.arguments)?;
    execute_agent_verb_input(server, args.tool.name, input, actor, None, served).await
}

fn mcp_agent_verb_input(
    tool: &str,
    a: &crate::mcp::McpVerbArguments,
) -> Result<Value, McpGatewayError> {
    let invalid = || {
        McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "invalid typed agent-verb argument",
        )
    };
    match tool {
        "report" => a.spec.clone().ok_or_else(invalid),
        "self.focus.refresh" => {
            let mut map = serde_json::Map::new();
            if let Some(value) = &a.frame_epoch {
                map.insert("frame_epoch".to_owned(), json!(value));
            }
            Ok(Value::Object(map))
        }
        "self.focus.subscribe" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "scopes".to_owned(),
                json!(a.scopes.as_ref().ok_or_else(invalid)?),
            );
            Ok(Value::Object(map))
        }
        "self.focus.unsubscribe" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "scopes".to_owned(),
                json!(a.scopes.as_ref().ok_or_else(invalid)?),
            );
            Ok(Value::Object(map))
        }
        "self.focus.scratchpad.recall" => a.spec.clone().ok_or_else(invalid),
        "self.memory.diary" => a.spec.clone().ok_or_else(invalid),
        "self.memory.diary.reads" => a.spec.clone().ok_or_else(invalid),
        "self.memory.diary.review" => a.spec.clone().ok_or_else(invalid),
        "self.identity.answer" => a.spec.clone().ok_or_else(invalid),
        "self.identity.settle" => a.spec.clone().ok_or_else(invalid),
        "self.inbox.list" => a.spec.clone().ok_or_else(invalid),
        "self.inbox.mark" => a.spec.clone().ok_or_else(invalid),
        "self.inbox.concern" => a.spec.clone().ok_or_else(invalid),
        "self.inbox.concern.outcome" => a.spec.clone().ok_or_else(invalid),
        "self.inbox.concern.move" => a.spec.clone().ok_or_else(invalid),
        "vault.people.list" => a.spec.clone().ok_or_else(invalid),
        "vault.people.get" => a.spec.clone().ok_or_else(invalid),
        "vault.shape.read" => a.spec.clone().ok_or_else(invalid),
        "vault.shape.plan" => a.spec.clone().ok_or_else(invalid),
        "vault.shape.apply" => a.spec.clone().ok_or_else(invalid),
        "self.message" => a.spec.clone().ok_or_else(invalid),
        "self.grants.ask" => a.spec.clone().ok_or_else(invalid),
        "self.memory.diary.query" => a.spec.clone().ok_or_else(invalid),
        "cancel" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "task_ref".to_owned(),
                json!(a.task_ref.as_ref().ok_or_else(invalid)?),
            );
            Ok(Value::Object(map))
        }
        "steer" => a.spec.clone().ok_or_else(invalid),
        "describe" => {
            let mut map = serde_json::Map::new();
            if let Some(value) = &a.task_ref {
                map.insert("task_ref".to_owned(), json!(value));
            }
            if let Some(value) = &a.self_target {
                map.insert("self".to_owned(), json!(value));
            }
            if let Some(value) = &a.session_id {
                map.insert("session_id".to_owned(), json!(value));
            }
            if let Some(value) = &a.key {
                map.insert("key".to_owned(), json!(value));
            }
            if let Some(value) = &a.frame_epoch {
                map.insert("frame_epoch".to_owned(), json!(value));
            }
            Ok(Value::Object(map))
        }
        "tasks.create" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "spec".to_owned(),
                json!(a.spec.as_ref().ok_or_else(invalid)?),
            );
            if let Some(value) = &a.label {
                map.insert("label".to_owned(), json!(value));
            }
            if let Some(value) = &a.assignee {
                map.insert("assignee".to_owned(), json!(value));
            }
            Ok(Value::Object(map))
        }
        "tasks.wave" => a.spec.clone().ok_or_else(invalid),
        "tasks.update" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "task_ref".to_owned(),
                json!(a.task_ref.as_ref().ok_or_else(invalid)?),
            );
            Ok(Value::Object(map))
        }
        "vault.witness" => a.spec.clone().ok_or_else(invalid),
        "vault.claims.upsert" => a.spec.clone().ok_or_else(invalid),
        "vault.recall" => a.spec.clone().ok_or_else(invalid),
        "vault.export" => a.spec.clone().ok_or_else(invalid),
        "vault.receipts" => a.spec.clone().ok_or_else(invalid),
        "vault.images.view" => a.spec.clone().ok_or_else(invalid),
        "vault.receipts.get" => a.spec.clone().ok_or_else(invalid),
        "vault.kv.get" => a.spec.clone().ok_or_else(invalid),
        "vault.kv.put" => a.spec.clone().ok_or_else(invalid),
        "vault.kv.delete" => a.spec.clone().ok_or_else(invalid),
        "vault.kv.search" => a.spec.clone().ok_or_else(invalid),
        "vault.kv.namespaces" => a.spec.clone().ok_or_else(invalid),
        "vault.weave.report" => a.spec.clone().ok_or_else(invalid),
        "vault.weave.digest" => a.spec.clone().ok_or_else(invalid),
        "vault.weave.lens" => a.spec.clone().ok_or_else(invalid),
        "vault.weave.link.wrong" => a.spec.clone().ok_or_else(invalid),
        "vault.packs.put" => a.spec.clone().ok_or_else(invalid),
        "vault.packs.setup.prepare" => a.spec.clone().ok_or_else(invalid),
        "vault.packs.setup.get" => a.spec.clone().ok_or_else(invalid),
        "vault.packs.setup.answer" => a.spec.clone().ok_or_else(invalid),
        "vault.packs.setup.verify" => a.spec.clone().ok_or_else(invalid),
        "vault.authority.audit" => a.spec.clone().ok_or_else(invalid),
        "vault.inspection.resolve" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.propose_delete" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.propose_transfer" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.propose_remove_owner" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.execute" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.receipt" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.outcomes" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.deletion" => Ok(Value::Object(serde_json::Map::new())),
        "vault.members.add" => a.spec.clone().ok_or_else(invalid),
        "vault.members.invitation_slip" => a.spec.clone().ok_or_else(invalid),
        "vault.members.change" => a.spec.clone().ok_or_else(invalid),
        "vault.members.remove" => a.spec.clone().ok_or_else(invalid),
        "vault.members.leave" => a.spec.clone().ok_or_else(invalid),
        "vault.members.invitations" => a.spec.clone().ok_or_else(invalid),
        "vault.members.accept" => a.spec.clone().ok_or_else(invalid),
        "vault.members.decline" => a.spec.clone().ok_or_else(invalid),
        "vault.members.withdraw_invitation" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.object" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.withdraw_objection" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.started" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.matured" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.erase_ask" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.erase_asks" => a.spec.clone().ok_or_else(invalid),
        "vault.shared.close_erase_ask" => a.spec.clone().ok_or_else(invalid),
        "vault.guests.revoke" => a.spec.clone().ok_or_else(invalid),
        "vault.guests.mint_slip" => a.spec.clone().ok_or_else(invalid),
        "vault.records.erase_preview" => a.spec.clone().ok_or_else(invalid),
        "vault.records.erase_confirm" => a.spec.clone().ok_or_else(invalid),
        "vault.authority.handoff_alarms" => Ok(Value::Object(serde_json::Map::new())),
        "vault.authority.handoff_alarms.acknowledge" => a.spec.clone().ok_or_else(invalid),
        "vault.legal_holds.place" => a.spec.clone().ok_or_else(invalid),
        "vault.legal_holds.widen" => a.spec.clone().ok_or_else(invalid),
        "vault.legal_holds.list" => Ok(Value::Object(serde_json::Map::new())),
        "vault.legal_holds.log" => Ok(Value::Object(serde_json::Map::new())),
        "vault.legal_holds.lift_and_erase" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.list" => Ok(Value::Object(serde_json::Map::new())),
        "vault.embedding_spaces.declare" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.bind" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.one_space" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.retire" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.move" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.move_check" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.move_approve" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.move_undo" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.move_abandon" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.probes.list" => Ok(Value::Object(serde_json::Map::new())),
        "vault.embedding_spaces.probes.put" => a.spec.clone().ok_or_else(invalid),
        "vault.embedding_spaces.probes.delete" => a.spec.clone().ok_or_else(invalid),
        "vault.settings.learning" => a.spec.clone().ok_or_else(invalid),
        "vault.settings.learning.put" => a.spec.clone().ok_or_else(invalid),
        "vault.settings.learning.clear" => a.spec.clone().ok_or_else(invalid),
        "vault.widen_proposals" => a.spec.clone().ok_or_else(invalid),
        "vault.widen_proposals.approve" => a.spec.clone().ok_or_else(invalid),
        "vault.widen_proposals.decline" => a.spec.clone().ok_or_else(invalid),
        "vault.settings.wake_policy.set" => a.spec.clone().ok_or_else(invalid),
        "vault.settings.inference_defaults" => Ok(Value::Object(serde_json::Map::new())),
        "vault.settings.inference_defaults.replace" => a.spec.clone().ok_or_else(invalid),
        "vault.lenses.propose" => a.spec.clone().ok_or_else(invalid),
        "vault.lenses.activate" => a.spec.clone().ok_or_else(invalid),
        "vault.lenses.deactivate" => a.spec.clone().ok_or_else(invalid),
        "vault.lenses.list" => a.spec.clone().ok_or_else(invalid),
        "vault.lenses.default" => a.spec.clone().ok_or_else(invalid),
        "vault.disclosure.offer" => a.spec.clone().ok_or_else(invalid),
        "reveal" => a.spec.clone().ok_or_else(invalid),
        "reveal.wait" => a.spec.clone().ok_or_else(invalid),
        "reveal.describe" => a.spec.clone().ok_or_else(invalid),
        "vault.shares.create" => a.spec.clone().ok_or_else(invalid),
        "vault.shares.revoke" => a.spec.clone().ok_or_else(invalid),
        "vault.shares.view" => a.spec.clone().ok_or_else(invalid),
        "vault.hooks.replay" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.view" => a.spec.clone().ok_or_else(invalid),
        "vault.code.diff" => a.spec.clone().ok_or_else(invalid),
        "vault.code.blame" => a.spec.clone().ok_or_else(invalid),
        "vault.code.proposal_view" => a.spec.clone().ok_or_else(invalid),
        "vault.code.repo_diff" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.export" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.born_from" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.proposals" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.waits" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.release_wait" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.review_slides" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.propose_deck" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.propose_output" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.keep" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.discard" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.undo" => a.spec.clone().ok_or_else(invalid),
        "can" => a.spec.clone().ok_or_else(invalid),
        "peek" => a.spec.clone().ok_or_else(invalid),
        "ask" => a.spec.clone().ok_or_else(invalid),
        "wait" => a.spec.clone().ok_or_else(invalid),
        "tasks.answer" => a.spec.clone().ok_or_else(invalid),
        "tasks.outcomes" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.list" => Ok(Value::Object(serde_json::Map::new())),
        "vault.rooms.messages" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "room_ref".to_owned(),
                json!(a.room_ref.as_ref().ok_or_else(invalid)?),
            );
            if let Some(value) = &a.turn_ref {
                map.insert("after".to_owned(), json!(value));
            }
            Ok(Value::Object(map))
        }
        "vault.rooms.participants" => {
            let mut input = a.spec.clone().ok_or_else(invalid)?;
            let map = input.as_object_mut().ok_or_else(invalid)?;
            if a.room_ref.as_deref() != map.get("room").and_then(Value::as_str) {
                return Err(invalid());
            }
            Ok(input)
        }
        "vault.rooms.render" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "room_ref".to_owned(),
                json!(a.room_ref.as_ref().ok_or_else(invalid)?),
            );
            Ok(Value::Object(map))
        }
        "vault.rooms.find" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "room_ref".to_owned(),
                json!(a.room_ref.as_ref().ok_or_else(invalid)?),
            );
            if let Some(value) = &a.turn_ref {
                map.insert("after".to_owned(), json!(value));
            }
            Ok(Value::Object(map))
        }
        "vault.rooms.get" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "room_ref".to_owned(),
                json!(a.room_ref.as_ref().ok_or_else(invalid)?),
            );
            map.insert(
                "turn_ref".to_owned(),
                json!(a.turn_ref.as_ref().ok_or_else(invalid)?),
            );
            Ok(Value::Object(map))
        }
        "vault.rooms.trunk" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "room_ref".to_owned(),
                json!(a.room_ref.as_ref().ok_or_else(invalid)?),
            );
            map.insert(
                "turn_ref".to_owned(),
                json!(a.turn_ref.as_ref().ok_or_else(invalid)?),
            );
            Ok(Value::Object(map))
        }
        "vault.rooms.reply_strips" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.claim" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "room_ref".to_owned(),
                json!(a.room_ref.as_ref().ok_or_else(invalid)?),
            );
            map.insert(
                "turn_ref".to_owned(),
                json!(a.turn_ref.as_ref().ok_or_else(invalid)?),
            );
            Ok(Value::Object(map))
        }
        "vault.rooms.speak" => {
            let mut input = a.spec.clone().ok_or_else(invalid)?;
            let map = input.as_object_mut().ok_or_else(invalid)?;
            if a.room_ref.as_deref() != map.get("conversation_ref").and_then(Value::as_str) {
                return Err(invalid());
            }
            Ok(input)
        }
        "vault.projects.propose" => a.spec.clone().ok_or_else(invalid),
        "vault.projects.proposals" => a.spec.clone().ok_or_else(invalid),
        "vault.projects.dismiss_card" => a.spec.clone().ok_or_else(invalid),
        "vault.projects.confirm" => a.spec.clone().ok_or_else(invalid),
        "vault.projects.roster.write" => a.spec.clone().ok_or_else(invalid),
        "vault.projects.goal.intake" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.join" => {
            let mut input = a.spec.clone().ok_or_else(invalid)?;
            let map = input.as_object_mut().ok_or_else(invalid)?;
            if a.room_ref.as_deref() != map.get("room").and_then(Value::as_str) {
                return Err(invalid());
            }
            Ok(input)
        }
        "vault.rooms.consent" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.offer" => {
            let mut input = a.spec.clone().ok_or_else(invalid)?;
            let map = input.as_object_mut().ok_or_else(invalid)?;
            if a.room_ref.as_deref() != map.get("room").and_then(Value::as_str) {
                return Err(invalid());
            }
            Ok(input)
        }
        "vault.rooms.offer.answer" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.offer.vote" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.offer.reopen" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.offers" => {
            let mut input = a.spec.clone().ok_or_else(invalid)?;
            let map = input.as_object_mut().ok_or_else(invalid)?;
            if a.room_ref.as_deref() != map.get("room").and_then(Value::as_str) {
                return Err(invalid());
            }
            Ok(input)
        }
        "vault.projects.goal.revisions" => a.spec.clone().ok_or_else(invalid),
        "vault.projects.goal.dismiss" => a.spec.clone().ok_or_else(invalid),
        "vault.projects.route_tradeoff" => a.spec.clone().ok_or_else(invalid),
        "vault.conversations.turn.continue" => a.spec.clone().ok_or_else(invalid),
        "vault.conversations.turn.retry" => a.spec.clone().ok_or_else(invalid),
        "vault.messages.react" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.host" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.host.pin" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.host.hand" => a.spec.clone().ok_or_else(invalid),
        "vault.rooms.sharing" => {
            let mut map = serde_json::Map::new();
            map.insert(
                "room_ref".to_owned(),
                json!(a.room_ref.as_ref().ok_or_else(invalid)?),
            );
            Ok(Value::Object(map))
        }
        "vault.companions.sharing.get" => a.spec.clone().ok_or_else(invalid),
        "vault.companions.sharing.set" => a.spec.clone().ok_or_else(invalid),
        "vault.workspace.work_companion.get" => a.spec.clone().ok_or_else(invalid),
        "vault.workspace.work_companion.set" => a.spec.clone().ok_or_else(invalid),
        "self.skills.save" => a.spec.clone().ok_or_else(invalid),
        "self.skills.fork" => a.spec.clone().ok_or_else(invalid),
        "self.skills.callables" => Ok(Value::Object(serde_json::Map::new())),
        "ai.options" => a.spec.clone().ok_or_else(invalid),
        "ai.image" => a.spec.clone().ok_or_else(invalid),
        "ai.speech" => a.spec.clone().ok_or_else(invalid),
        "ai.transcribe" => a.spec.clone().ok_or_else(invalid),
        "ai.embed" => a.spec.clone().ok_or_else(invalid),
        "ai.video" => a.spec.clone().ok_or_else(invalid),
        "ai.video.poll" => a.spec.clone().ok_or_else(invalid),
        "ai.video.cancel" => a.spec.clone().ok_or_else(invalid),
        "ai.verdict" => a.spec.clone().ok_or_else(invalid),
        "vault.graph.ask" => a.spec.clone().ok_or_else(invalid),
        "vault.questions.create" => a.spec.clone().ok_or_else(invalid),
        "vault.questions.edit" => a.spec.clone().ok_or_else(invalid),
        "vault.questions.pause" => a.spec.clone().ok_or_else(invalid),
        "vault.questions.backfill" => a.spec.clone().ok_or_else(invalid),
        "vault.questions.read" => a.spec.clone().ok_or_else(invalid),
        "vault.questions.answers" => a.spec.clone().ok_or_else(invalid),
        "vault.decisions.asks.answer" => a.spec.clone().ok_or_else(invalid),
        "vault.decisions.asks.climb" => a.spec.clone().ok_or_else(invalid),
        "self.decisions.asks" => a.spec.clone().ok_or_else(invalid),
        "connector.list" => a.spec.clone().ok_or_else(invalid),
        "connector.status" => a.spec.clone().ok_or_else(invalid),
        "connector.call" => a.spec.clone().ok_or_else(invalid),
        "connector.schema" => a.spec.clone().ok_or_else(invalid),
        "vault.commit" => a.spec.clone().ok_or_else(invalid),
        "vault.remember" => a.spec.clone().ok_or_else(invalid),
        "vault.claims.retract" => a.spec.clone().ok_or_else(invalid),
        "vault.forget" => a.spec.clone().ok_or_else(invalid),
        "vault.claims.list" => a.spec.clone().ok_or_else(invalid),
        "vault.claims.history" => a.spec.clone().ok_or_else(invalid),
        "vault.delete" => a.spec.clone().ok_or_else(invalid),
        "vault.writes.pending" => a.spec.clone().ok_or_else(invalid),
        "vault.hydrate" => a.spec.clone().ok_or_else(invalid),
        "vault.get" => a.spec.clone().ok_or_else(invalid),
        "vault.refs.resolve" => a.spec.clone().ok_or_else(invalid),
        "vault.refs.links" => a.spec.clone().ok_or_else(invalid),
        "vault.search.bm25" => a.spec.clone().ok_or_else(invalid),
        "vault.neighbors" => a.spec.clone().ok_or_else(invalid),
        "vault.structural.put" => a.spec.clone().ok_or_else(invalid),
        "vault.habits.checkin" => a.spec.clone().ok_or_else(invalid),
        "vault.claims.admit" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.create" => a.spec.clone().ok_or_else(invalid),
        "vault.conversations.create" => a.spec.clone().ok_or_else(invalid),
        "vault.conversations.turns.create" => a.spec.clone().ok_or_else(invalid),
        "vault.conversations.records.append" => a.spec.clone().ok_or_else(invalid),
        "vault.batch" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.put" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.import" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.head" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.read" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.commits" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.edit" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.fork.open" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.fork.edit" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.fork.diff" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.fork.merge" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.fork.discard" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.export" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.body.preview" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.append" => a.spec.clone().ok_or_else(invalid),
        "vault.artifacts.read" => a.spec.clone().ok_or_else(invalid),
        "vault.consolidation.enqueue" => a.spec.clone().ok_or_else(invalid),
        "vault.consolidation.status" => a.spec.clone().ok_or_else(invalid),
        "vault.claims.seed" => a.spec.clone().ok_or_else(invalid),
        "connector.outbound.schedule" => a.spec.clone().ok_or_else(invalid),
        "vault.notes.create" => a.spec.clone().ok_or_else(invalid),
        "vault.notes.from_entity" => a.spec.clone().ok_or_else(invalid),
        "vault.notes.edit" => a.spec.clone().ok_or_else(invalid),
        "vault.notes.seal" => a.spec.clone().ok_or_else(invalid),
        "vault.notes.lifecycle" => a.spec.clone().ok_or_else(invalid),
        _ => Err(invalid()),
    }
}
/// The `tools/call` arguments one verb input projects onto, so a call that
/// arrives as a whole input meets the admission a tool call of that verb meets.
pub(crate) fn mcp_agent_verb_arguments(
    tool: &str,
    input: &Value,
) -> Result<crate::mcp::McpVerbArguments, McpGatewayError> {
    let invalid = || {
        McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "invalid typed agent-verb argument",
        )
    };
    let mut arguments = serde_json::Map::new();
    match tool {
        "report" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.focus.refresh" => {
            if let Some(value) = input.get("frame_epoch") {
                arguments.insert("frame_epoch".to_owned(), value.clone());
            }
        }
        "self.focus.subscribe" => {
            if let Some(value) = input.get("scopes") {
                arguments.insert("scopes".to_owned(), value.clone());
            }
        }
        "self.focus.unsubscribe" => {
            if let Some(value) = input.get("scopes") {
                arguments.insert("scopes".to_owned(), value.clone());
            }
        }
        "self.focus.scratchpad.recall" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.memory.diary" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.memory.diary.reads" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.memory.diary.review" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.identity.answer" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.identity.settle" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.inbox.list" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.inbox.mark" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.inbox.concern" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.inbox.concern.outcome" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.inbox.concern.move" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.people.list" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.people.get" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shape.read" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shape.plan" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shape.apply" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.message" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.grants.ask" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.memory.diary.query" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "cancel" => {
            if let Some(value) = input.get("task_ref") {
                arguments.insert("task_ref".to_owned(), value.clone());
            }
        }
        "steer" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "describe" => {
            if let Some(value) = input.get("task_ref") {
                arguments.insert("task_ref".to_owned(), value.clone());
            }
            if let Some(value) = input.get("self") {
                arguments.insert("self".to_owned(), value.clone());
            }
            if let Some(value) = input.get("session_id") {
                arguments.insert("session_id".to_owned(), value.clone());
            }
            if let Some(value) = input.get("key") {
                arguments.insert("key".to_owned(), value.clone());
            }
            if let Some(value) = input.get("frame_epoch") {
                arguments.insert("frame_epoch".to_owned(), value.clone());
            }
        }
        "tasks.create" => {
            if let Some(value) = input.get("spec") {
                arguments.insert("spec".to_owned(), value.clone());
            }
            if let Some(value) = input.get("label") {
                arguments.insert("label".to_owned(), value.clone());
            }
            if let Some(value) = input.get("assignee") {
                arguments.insert("assignee".to_owned(), value.clone());
            }
        }
        "tasks.wave" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "tasks.update" => {
            if let Some(value) = input.get("task_ref") {
                arguments.insert("task_ref".to_owned(), value.clone());
            }
        }
        "vault.witness" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.claims.upsert" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.recall" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.export" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.receipts" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.images.view" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.receipts.get" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.kv.get" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.kv.put" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.kv.delete" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.kv.search" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.kv.namespaces" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.weave.report" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.weave.digest" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.weave.lens" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.weave.link.wrong" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.packs.put" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.packs.setup.prepare" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.packs.setup.get" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.packs.setup.answer" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.packs.setup.verify" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.authority.audit" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.inspection.resolve" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.propose_delete" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.propose_transfer" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.propose_remove_owner" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.execute" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.receipt" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.outcomes" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.deletion" => {}
        "vault.members.add" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.members.invitation_slip" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.members.change" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.members.remove" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.members.leave" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.members.invitations" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.members.accept" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.members.decline" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.members.withdraw_invitation" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.object" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.withdraw_objection" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.started" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.matured" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.erase_ask" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.erase_asks" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shared.close_erase_ask" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.guests.revoke" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.guests.mint_slip" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.records.erase_preview" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.records.erase_confirm" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.authority.handoff_alarms" => {}
        "vault.authority.handoff_alarms.acknowledge" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.legal_holds.place" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.legal_holds.widen" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.legal_holds.list" => {}
        "vault.legal_holds.log" => {}
        "vault.legal_holds.lift_and_erase" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.list" => {}
        "vault.embedding_spaces.declare" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.bind" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.one_space" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.retire" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.move" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.move_check" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.move_approve" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.move_undo" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.move_abandon" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.probes.list" => {}
        "vault.embedding_spaces.probes.put" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.embedding_spaces.probes.delete" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.settings.learning" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.settings.learning.put" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.settings.learning.clear" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.widen_proposals" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.widen_proposals.approve" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.widen_proposals.decline" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.settings.wake_policy.set" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.settings.inference_defaults" => {}
        "vault.settings.inference_defaults.replace" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.lenses.propose" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.lenses.activate" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.lenses.deactivate" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.lenses.list" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.lenses.default" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.disclosure.offer" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "reveal" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "reveal.wait" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "reveal.describe" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shares.create" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shares.revoke" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.shares.view" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.hooks.replay" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.view" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.code.diff" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.code.blame" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.code.proposal_view" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.code.repo_diff" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.export" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.born_from" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.proposals" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.waits" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.release_wait" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.review_slides" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.propose_deck" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.propose_output" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.keep" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.discard" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.undo" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "can" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "peek" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "ask" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "wait" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "tasks.answer" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "tasks.outcomes" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.list" => {}
        "vault.rooms.messages" => {
            if let Some(value) = input.get("room_ref") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
            if let Some(value) = input.get("after") {
                arguments.insert("turn_ref".to_owned(), value.clone());
            }
        }
        "vault.rooms.participants" => {
            arguments.insert("spec".to_owned(), input.clone());
            if let Some(value) = input.get("room") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
        }
        "vault.rooms.render" => {
            if let Some(value) = input.get("room_ref") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
        }
        "vault.rooms.find" => {
            if let Some(value) = input.get("room_ref") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
            if let Some(value) = input.get("after") {
                arguments.insert("turn_ref".to_owned(), value.clone());
            }
        }
        "vault.rooms.get" => {
            if let Some(value) = input.get("room_ref") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
            if let Some(value) = input.get("turn_ref") {
                arguments.insert("turn_ref".to_owned(), value.clone());
            }
        }
        "vault.rooms.trunk" => {
            if let Some(value) = input.get("room_ref") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
            if let Some(value) = input.get("turn_ref") {
                arguments.insert("turn_ref".to_owned(), value.clone());
            }
        }
        "vault.rooms.reply_strips" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.claim" => {
            if let Some(value) = input.get("room_ref") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
            if let Some(value) = input.get("turn_ref") {
                arguments.insert("turn_ref".to_owned(), value.clone());
            }
        }
        "vault.rooms.speak" => {
            arguments.insert("spec".to_owned(), input.clone());
            if let Some(value) = input.get("conversation_ref") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
        }
        "vault.projects.propose" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.projects.proposals" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.projects.dismiss_card" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.projects.confirm" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.projects.roster.write" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.projects.goal.intake" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.join" => {
            arguments.insert("spec".to_owned(), input.clone());
            if let Some(value) = input.get("room") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
        }
        "vault.rooms.consent" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.offer" => {
            arguments.insert("spec".to_owned(), input.clone());
            if let Some(value) = input.get("room") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
        }
        "vault.rooms.offer.answer" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.offer.vote" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.offer.reopen" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.offers" => {
            arguments.insert("spec".to_owned(), input.clone());
            if let Some(value) = input.get("room") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
        }
        "vault.projects.goal.revisions" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.projects.goal.dismiss" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.projects.route_tradeoff" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.conversations.turn.continue" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.conversations.turn.retry" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.messages.react" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.host" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.host.pin" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.host.hand" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.rooms.sharing" => {
            if let Some(value) = input.get("room_ref") {
                arguments.insert("room_ref".to_owned(), value.clone());
            }
        }
        "vault.companions.sharing.get" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.companions.sharing.set" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.workspace.work_companion.get" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.workspace.work_companion.set" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.skills.save" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.skills.fork" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.skills.callables" => {}
        "ai.options" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "ai.image" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "ai.speech" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "ai.transcribe" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "ai.embed" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "ai.video" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "ai.video.poll" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "ai.video.cancel" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "ai.verdict" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.graph.ask" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.questions.create" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.questions.edit" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.questions.pause" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.questions.backfill" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.questions.read" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.questions.answers" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.decisions.asks.answer" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.decisions.asks.climb" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "self.decisions.asks" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "connector.list" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "connector.status" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "connector.call" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "connector.schema" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.commit" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.remember" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.claims.retract" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.forget" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.claims.list" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.claims.history" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.delete" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.writes.pending" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.hydrate" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.get" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.refs.resolve" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.refs.links" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.search.bm25" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.neighbors" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.structural.put" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.habits.checkin" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.claims.admit" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.create" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.conversations.create" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.conversations.turns.create" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.conversations.records.append" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.batch" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.put" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.import" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.head" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.read" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.commits" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.edit" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.fork.open" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.fork.edit" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.fork.diff" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.fork.merge" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.fork.discard" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.export" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.body.preview" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.append" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.artifacts.read" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.consolidation.enqueue" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.consolidation.status" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.claims.seed" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "connector.outbound.schedule" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.notes.create" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.notes.from_entity" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.notes.edit" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.notes.seal" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        "vault.notes.lifecycle" => {
            arguments.insert("spec".to_owned(), input.clone());
        }
        _ => return Err(invalid()),
    }
    serde_json::from_value(Value::Object(arguments)).map_err(|_| invalid())
}
/// Runs one verb from its whole typed input, with the actor ceiling and
/// gate every other door applies. Every MCP door reaches the verb table here.
/// The input names only fields the verb's advertised closed schema lists, and
/// a code-mode call's claims are written under its run's host `origin`.
/// Every row the result was derived from is listed in `served`: those its
/// input names, and those the verb's reads picked themselves.
pub(crate) async fn execute_agent_verb_input(
    server: &Arc<SyncServer>,
    tool: &str,
    input: Value,
    actor: &McpCallContext,
    origin: Option<oneiron::memory::HostWriteOrigin>,
    served: &mut Vec<oneiron::EntityId>,
) -> Result<
    (
        Value,
        crate::mcp::McpPageSource,
        McpCarrierPolicy,
        Option<u64>,
    ),
    McpGatewayError,
> {
    let producers = oneiron::memory::ProducerRows::default();
    let produced =
        execute_agent_verb_listing(server, tool, input, actor, origin, &producers, served).await;
    served.extend(producers.take());
    produced
}

/// [`execute_agent_verb_input`], its surface listing in `producers` the rows
/// its reads pick. Every MCP and code-mode row crosses its verb hooks here,
/// once (ARCH-0080 §3), under the invocation the call carried or a fresh
/// one: the pre chain before the row, the post chain over its result.
async fn execute_agent_verb_listing(
    server: &Arc<SyncServer>,
    tool: &str,
    input: Value,
    actor: &McpCallContext,
    origin: Option<oneiron::memory::HostWriteOrigin>,
    producers: &oneiron::memory::ProducerRows,
    served: &mut Vec<oneiron::EntityId>,
) -> Result<
    (
        Value,
        crate::mcp::McpPageSource,
        McpCarrierPolicy,
        Option<u64>,
    ),
    McpGatewayError,
> {
    let invalid = || {
        McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "invalid typed agent-verb argument",
        )
    };
    if let Some(field) = crate::mcp::verb_input_unknown_field(tool, &input) {
        return Err(McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            format!("{tool} input names unknown field `{field}`"),
        ));
    }
    if !oneiron::task_verb::sdk::AgentVerb::from_name(tool)
        .is_some_and(oneiron::task_verb::sdk::AgentVerb::is_mcp)
    {
        return Err(invalid());
    }
    // A narrowed connector's TASKs are born in its own world and in the
    // facet its writes land in (its session's, or its own write facet).
    let mut position = actor.scope.birth_position();
    if let Ok(Some(facet)) = actor.landing {
        position.facet = Some(facet);
    }
    let invocation = actor
        .invocation
        .unwrap_or_else(oneiron::runtime_hooks::InvocationId::mint);
    let memory = crate::api::credential_memory(
        &server.vault,
        actor.auth.as_ref(),
        actor.actor_ref,
        actor.actor_class,
    )
    .at(actor.locality())
    .with_birth_position(position)
    .listing_producers(producers)
    .with_invocation(invocation);
    let memory = match origin {
        Some(origin) => memory.with_host_origin(origin),
        None => memory,
    };
    // OF-063: the off-record session the request named; inside an anonymous
    // one a reference refusal writes no receipt (Engine ruling 10-17).
    let memory = match actor.off_record_session.as_deref() {
        Some(session) => memory.in_off_record_session(session),
        None => memory,
    };
    // Rule 5: a task-work row takes its one turn here, for MCP and code mode
    // alike, and holds it through its hooks and its row.
    let _turn = if oneiron::task_verb::sdk::AgentVerb::from_name(tool)
        .is_some_and(oneiron::task_verb::sdk::AgentVerb::is_task_work)
    {
        Some(server.admit_task_work(actor.actor_ref).await)
    } else {
        None
    };
    let hooks = super::verb_hooks::mcp_row_hooks_pre(server, tool, actor, &memory, input).await?;
    let (output, source, carrier, epoch) =
        execute_agent_verb_row(server, tool, hooks.args.clone(), actor, memory, served).await?;
    let output = crate::api::facade::row_hooks_post(server, hooks, output)
        .await
        .map_err(mcp_facade_error)?;
    Ok((output, source, carrier, epoch))
}

/// One row of [`execute_agent_verb_listing`], on the args its pre chain left.
async fn execute_agent_verb_row(
    server: &Arc<SyncServer>,
    tool: &str,
    input: Value,
    actor: &McpCallContext,
    memory: oneiron::Memory<'_>,
    served: &mut Vec<oneiron::EntityId>,
) -> Result<
    (
        Value,
        crate::mcp::McpPageSource,
        McpCarrierPolicy,
        Option<u64>,
    ),
    McpGatewayError,
> {
    let invalid = || {
        McpGatewayError::new(
            -32602,
            "tool_args_invalid",
            "invalid typed agent-verb argument",
        )
    };
    match tool {
        "report" => {
            oneiron::task_verb::sdk::validate_input("report", &input).map_err(mcp_facade_error)?;
            let input: oneiron::feedback::ReportRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let proof = actor
                .auth
                .as_ref()
                .and_then(crate::auth::CoreAuth::verified_slip)
                .cloned();
            let (output, listed) = server
                .report_off_runtime_listing(
                    actor.actor_ref,
                    actor.actor_class,
                    proof,
                    actor.locality(),
                    None,
                    input,
                )
                .await;
            // Derived from these rows too, though it names none of them.
            served.extend(listed);
            let output = output.map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.focus.refresh" => {
            let input: oneiron::task_verb::sdk::BoardRefreshRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            execute_mcp_board_verb(server, actor, served, |context| {
                oneiron::task_verb::sdk::self_focus_refresh(context, input)
            })
            .await
        }
        "self.focus.subscribe" => {
            let input: oneiron::task_verb::sdk::BoardSubscriptionRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            execute_mcp_board_verb(server, actor, served, |context| {
                oneiron::task_verb::sdk::self_focus_subscribe(context, input)
            })
            .await
        }
        "self.focus.unsubscribe" => {
            let input: oneiron::task_verb::sdk::BoardSubscriptionRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            execute_mcp_board_verb(server, actor, served, |context| {
                oneiron::task_verb::sdk::self_focus_unsubscribe(context, input)
            })
            .await
        }
        "self.focus.scratchpad.recall" => {
            let input: oneiron::task_verb::sdk::ScratchpadRecallRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_focus_scratchpad_recall(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.memory.diary" => {
            let input: oneiron::task_verb::sdk::DiaryEntryRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_memory_diary(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.memory.diary.reads" => {
            let input: oneiron::memory::DiaryReadsRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_memory_diary_reads(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.memory.diary.review" => {
            let input: oneiron::memory::DiaryReviewAnswer =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_memory_diary_review(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.identity.answer" => {
            let input: oneiron::dreamer_runner::maintenance::identity::IdentityAnswerRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_identity_answer(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.identity.settle" => {
            let input: oneiron::dreamer_runner::maintenance::identity::IdentityActNowRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_identity_settle(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.inbox.list" => {
            let input: oneiron::task_verb::sdk::InboxListRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_inbox_list(&memory, input)
                .map_err(mcp_facade_error)?;
            served.extend(
                output
                    .rows
                    .iter()
                    .filter_map(|row| oneiron::EntityId::from_hex(&row.id).ok()),
            );
            let source = crate::mcp::McpPageSource::scoped_window(
                output.rows.len(),
                0,
                usize::from(output.next_after.is_some()),
                true,
            )
            .rows_at("rows");
            mcp_agent_verb_output(output, source)
        }
        "self.inbox.mark" => {
            let input: oneiron::task_verb::sdk::InboxMarkRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_inbox_mark(&memory, input)
                .map_err(mcp_facade_error)?;
            served.extend(oneiron::EntityId::from_hex(&output.id).ok());
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.inbox.concern" => {
            let input: oneiron::dreamer_runner::maintenance::agent_health::ConcernCardRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_inbox_concern(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.inbox.concern.outcome" => {
            let input: oneiron::dreamer_runner::maintenance::agent_health::ConcernOutcomeRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_inbox_concern_outcome(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.inbox.concern.move" => {
            let input: oneiron::dreamer_runner::maintenance::agent_health::ConcernMoveRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_inbox_concern_move(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.people.list" => {
            let input: oneiron::memory::PeopleListRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_people_list(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.people.get" => {
            let input: oneiron::memory::PersonRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_people_get(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shape.read" => {
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_shape_read(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shape.plan" => {
            let input: oneiron::vault_shape::ShapePlanRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_shape_plan(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shape.apply" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shape.apply", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::vault_shape::ShapeApplyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shape_apply(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.message" => {
            let input: oneiron::memory::MessagePersonRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::self_message(&memory, input).map_err(mcp_facade_error)?;
            server
                .ai
                .turn_landed_by(server.vault(), actor.actor_ref, actor.actor_class);
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.grants.ask" => {
            let input: oneiron::memory::GrantAskRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_grants_ask(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.memory.diary.query" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("self.memory.diary.query", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::DiaryQueryRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::self_memory_diary_query(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "cancel" => {
            let input: oneiron::task_verb::sdk::TaskRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            served.extend(oneiron::EntityId::from_hex(&input.task_ref).ok());
            let output =
                oneiron::task_verb::sdk::cancel(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "steer" => {
            let input: oneiron::task_verb::sdk::SteerRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::steer(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "describe" => {
            if input.get("self").and_then(Value::as_bool) == Some(true) {
                let auth = actor.auth.as_ref().ok_or_else(invalid)?;
                let value = crate::api::context_board::describe_self_for_auth(server, auth, &input)
                    .await
                    .map_err(|_| invalid())?;
                let output: oneiron::task_verb::TaskDescription =
                    serde_json::from_value(value).map_err(|_| invalid())?;
                let (value, source) = mcp_describe_result(output)?;
                return Ok((value, source, McpCarrierPolicy::Drain, None));
            }
            let input: oneiron::task_verb::sdk::DescribeRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            if let Some(key) = input.key.clone() {
                let frame_epoch = input.frame_epoch;
                return execute_mcp_board_verb(server, actor, served, |context| {
                    oneiron::board_verb::dispatch_board_verb(
                        context,
                        oneiron::board_verb::BoardVerbCall::Expand { key, frame_epoch },
                    )
                })
                .await;
            }
            if input.task_ref.is_none() && !input.self_target {
                // The section is narrowed to this credential before its
                // render cap, so its counts are the credential's rows alone.
                let rows = memory.describe_rows().map_err(mcp_facade_error)?;
                let (value, source) = mcp_tasks_section(server, actor, rows, served)?;
                return Ok((value, source, McpCarrierPolicy::Drain, None));
            }
            served.extend(
                input
                    .task_ref
                    .as_deref()
                    .and_then(|id| oneiron::EntityId::from_hex(id).ok()),
            );
            let output =
                oneiron::task_verb::sdk::describe(&memory, input).map_err(mcp_facade_error)?;
            let (value, source) = mcp_describe_result(output)?;
            Ok((value, source, McpCarrierPolicy::Drain, None))
        }
        "tasks.create" => {
            let input: oneiron::task_verb::sdk::TaskCreateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::tasks_create(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "tasks.wave" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("tasks.wave", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::TaskWaveRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::tasks_wave(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "tasks.update" => {
            let input: oneiron::task_verb::sdk::TaskUpdateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            served.extend(oneiron::EntityId::from_hex(&input.task_ref).ok());
            let output =
                oneiron::task_verb::sdk::tasks_update(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.witness" => {
            let input: oneiron::memory::WitnessTurn =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::vault_witness(&memory, input).map_err(mcp_facade_error)?;
            server
                .ai
                .turn_landed_by(server.vault(), actor.actor_ref, actor.actor_class);
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.claims.upsert" => {
            let input: oneiron::memory::ClaimInput =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_claims_upsert(&memory, input)
                .map_err(mcp_facade_error)?;
            served.extend(
                [
                    Some(output.claim_short_id.as_str()),
                    output.superseded_short_id.as_deref(),
                ]
                .into_iter()
                .flatten()
                .filter_map(|reference| {
                    oneiron::memory::resolve_entity_ref(&server.vault, reference).ok()
                }),
            );
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.recall" => {
            oneiron::task_verb::sdk::validate_input("vault.recall", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::RecallRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let proof = actor
                .auth
                .as_ref()
                .and_then(crate::auth::CoreAuth::verified_slip)
                .cloned();
            let (output, listed) = server
                .recall_off_runtime_listing(
                    actor.actor_ref,
                    actor.actor_class,
                    proof,
                    actor.locality(),
                    None,
                    input,
                )
                .await;
            // Derived from these rows too, though it names none of them.
            served.extend(listed);
            let output = output.map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.export" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            if !auth.is_owner_grade() {
                return Err(McpGatewayError::new(
                    -32020,
                    "forbidden",
                    "full-vault export requires owner authority",
                ));
            }
            oneiron::task_verb::sdk::validate_input("vault.export", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::memory::ExportOptions =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let proof = auth.verified_slip().ok_or_else(|| {
                McpGatewayError::new(
                    -32020,
                    "forbidden",
                    "full-vault export requires verified owner authority",
                )
            })?;
            let output = if proof.claims().holder_ref == "host" {
                server
                    .vault
                    .export_with_verified_host_owner(&input, proof, actor.locality())
            } else {
                memory.export_with_verified_owner(&input, proof)
            }
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.receipts" => {
            let input: oneiron::task_verb::sdk::VaultReceiptsRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_receipts(&memory, input)
                .map_err(mcp_facade_error)?;
            served.extend(
                output
                    .iter()
                    .filter_map(|receipt| receipt.claim_ref.as_deref())
                    .filter_map(|id| oneiron::EntityId::from_hex(id).ok()),
            );
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.images.view" => {
            let input: oneiron::memory::ImageViewRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_images_view(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.receipts.get" => {
            let input: oneiron::receipt::CallReceiptRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_receipts_get(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.kv.get" => {
            let input: oneiron::memory::KeyValueAddress =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::vault_kv_get(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.kv.put" => {
            let input: oneiron::memory::KeyValuePut =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::vault_kv_put(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.kv.delete" => {
            let input: oneiron::memory::KeyValueAddress =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_kv_delete(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.kv.search" => {
            let input: oneiron::memory::KeyValueSearch =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_kv_search(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.kv.namespaces" => {
            let input: oneiron::memory::KeyValueNamespaces =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_kv_namespaces(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.weave.report" => {
            let input: oneiron::claim::WeaveReportRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_weave_report(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.weave.digest" => {
            let input: oneiron::claim::WeaveDigestRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_weave_digest(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.weave.lens" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.weave.lens", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::claim::WeaveReportRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_weave_lens(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.weave.link.wrong" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.weave.link.wrong", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::claim::WeaveWrongLinkRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_weave_link_wrong(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.packs.put" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.packs.put", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::PackPutRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_packs_put(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.packs.setup.prepare" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.packs.setup.prepare", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::PackSetupRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_packs_setup_prepare(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.packs.setup.get" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.packs.setup.get", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::PackSetupRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_packs_setup_get(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.packs.setup.answer" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.packs.setup.answer", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::PackSetupAnswerRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_packs_setup_answer(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.packs.setup.verify" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.packs.setup.verify", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::PackSetupVerifyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_packs_setup_verify(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.authority.audit" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.authority.audit", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::receipt::AuthorityAuditQuery =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_authority_audit(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.inspection.resolve" => {
            let input: oneiron::lens::InspectionResolveRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_inspection_resolve(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.propose_delete" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.propose_delete", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedVaultRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_shared_propose_delete(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.propose_transfer" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.propose_transfer", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedTransferRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_shared_propose_transfer(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.propose_remove_owner" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.propose_remove_owner", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedRemoveOwnerRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shared_propose_remove_owner(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.execute" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.execute", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedActRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shared_execute(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.receipt" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.receipt", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedReceiptRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shared_receipt(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.outcomes" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.outcomes", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedVaultRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shared_outcomes(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.deletion" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.deletion", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shared_deletion(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.members.add" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.members.add", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedMemberAddRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_members_add(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.members.invitation_slip" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.members.invitation_slip", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::InvitationSlipRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_members_invitation_slip(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.members.change" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.members.change", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedMemberRoleRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_members_change(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.members.remove" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.members.remove", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedMemberRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_members_remove(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.members.leave" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.members.leave", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedVaultRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_members_leave(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.members.invitations" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.members.invitations", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedVaultRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_members_invitations(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.members.accept" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.members.accept", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedInvitationRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_members_accept(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.members.decline" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.members.decline", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedInvitationRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_members_decline(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.members.withdraw_invitation" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.members.withdraw_invitation", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedInvitationWithdrawRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_members_withdraw_invitation(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.object" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.object", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedActRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shared_object(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.withdraw_objection" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.withdraw_objection", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedActRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shared_withdraw_objection(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.started" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.started", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedVaultRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shared_started(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.matured" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.matured", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedVaultRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shared_matured(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.erase_ask" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.erase_ask", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedEraseAskRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_shared_erase_ask(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.erase_asks" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.erase_asks", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedVaultRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_shared_erase_asks(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.shared.close_erase_ask" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shared.close_erase_ask", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::SharedEraseAskCloseRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_shared_close_erase_ask(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.guests.revoke" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.guests.revoke", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::GuestRevokeRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_guests_revoke(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.guests.mint_slip" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.guests.mint_slip", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::GuestSlipMintRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_guests_mint_slip(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.records.erase_preview" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.records.erase_preview", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::RecordEraseRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_records_erase_preview(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.records.erase_confirm" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.records.erase_confirm", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::RecordEraseConfirmRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_records_erase_confirm(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.authority.handoff_alarms" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.authority.handoff_alarms", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_authority_handoff_alarms(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.authority.handoff_alarms.acknowledge" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input(
                "vault.authority.handoff_alarms.acknowledge",
                &input,
            )
            .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::HandoffAlarmRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_authority_handoff_alarms_acknowledge(
                    server, auth, input,
                )
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.legal_holds.place" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.legal_holds.place", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::LegalHoldPlaceRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_legal_holds_place(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.legal_holds.widen" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.legal_holds.widen", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::LegalHoldWidenRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_legal_holds_widen(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.legal_holds.list" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.legal_holds.list", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_legal_holds_list(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.legal_holds.log" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.legal_holds.log", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_legal_holds_log(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.legal_holds.lift_and_erase" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.legal_holds.lift_and_erase", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::LegalHoldLiftAndEraseRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_legal_holds_lift_and_erase(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.list" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.list", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_embedding_spaces_list(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.declare" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.declare", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceDeclareRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_embedding_spaces_declare(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.bind" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.bind", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceBindRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_embedding_spaces_bind(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.one_space" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.one_space", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_embedding_spaces_one_space(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.retire" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.retire", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_embedding_spaces_retire(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.move" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.move", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceMoveRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_embedding_spaces_move(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.move_check" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.move_check", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceCandidateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_embedding_spaces_move_check(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.move_approve" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.move_approve", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceCandidateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_embedding_spaces_move_approve(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.move_undo" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.move_undo", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceCandidateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_embedding_spaces_move_undo(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.move_abandon" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.move_abandon", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceCandidateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_embedding_spaces_move_abandon(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.probes.list" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.probes.list", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_embedding_spaces_probes_list(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.probes.put" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.probes.put", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceProbePutRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_embedding_spaces_probes_put(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.embedding_spaces.probes.delete" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.embedding_spaces.probes.delete", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmbeddingSpaceProbeDeleteRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_embedding_spaces_probes_delete(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.settings.learning" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.settings.learning", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::learning_setting_doors::LearningSettingsRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_settings_learning(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.settings.learning.put" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.settings.learning.put", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::learning_setting_doors::LearningSettingPut =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_settings_learning_put(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.settings.learning.clear" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.settings.learning.clear", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::learning_setting_doors::LearningSettingClear =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_settings_learning_clear(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.widen_proposals" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.widen_proposals", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::agent_dispatch::widen_doors::WidenProposalsRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_widen_proposals(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.widen_proposals.approve" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.widen_proposals.approve", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::agent_dispatch::widen_doors::WidenProposalAnswer =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_widen_proposals_approve(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.widen_proposals.decline" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.widen_proposals.decline", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::agent_dispatch::widen_doors::WidenProposalAnswer =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_widen_proposals_decline(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.settings.wake_policy.set" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.settings.wake_policy.set", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::policy_setting_doors::WakePolicySetRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_settings_wake_policy_set(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.settings.inference_defaults" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.settings.inference_defaults", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_settings_inference_defaults(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.settings.inference_defaults.replace" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input(
                "vault.settings.inference_defaults.replace",
                &input,
            )
            .map_err(mcp_facade_error)?;
            let input: oneiron::policy_setting_doors::InferenceDefaultsReplaceRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_settings_inference_defaults_replace(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.lenses.propose" => {
            let input: oneiron::lens::LensProposeRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_lenses_propose(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.lenses.activate" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.lenses.activate", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::lens::LensActivateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_lenses_activate(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.lenses.deactivate" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.lenses.deactivate", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::lens::LensDeactivateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_lenses_deactivate(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.lenses.list" => {
            let input: oneiron::lens::LensListRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_lenses_list(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.lenses.default" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.lenses.default", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::lens::LensDefaultRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let (output, listed) =
                crate::api::facade::host_doors::vault_lenses_default(server, auth, input).await;
            // Derived from the rows its reads listed.
            served.extend(listed);
            let output = output.map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.disclosure.offer" => {
            let input: oneiron::task_verb::sdk::DisclosureOfferRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_disclosure_offer(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "reveal" => {
            let input: oneiron::task_verb::sdk::RevealRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::reveal(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "reveal.wait" => {
            let input: oneiron::task_verb::sdk::RevealWaitRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::reveal_wait(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "reveal.describe" => {
            let input: oneiron::task_verb::sdk::RevealDescribeRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::reveal_describe(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shares.create" => {
            let input: oneiron::task_verb::sdk::ShareCreateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_shares_create(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shares.revoke" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shares.revoke", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::ShareRevokeRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shares_revoke(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.shares.view" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.shares.view", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::ShareViewRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_shares_view(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.hooks.replay" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.hooks.replay", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::HooksReplayRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_hooks_replay(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.view" => {
            let input: oneiron::blob_artifact::ArtifactRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_view(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.code.diff" => {
            let input: oneiron::code_document::CodeDiffRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_code_diff(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.code.blame" => {
            let input: oneiron::code_document::CodeStateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_code_blame(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.code.proposal_view" => {
            let input: oneiron::code_document::CodeProposalViewRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_code_proposal_view(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.code.repo_diff" => {
            let input: oneiron::code_document::CodeRepoDiffRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_code_repo_diff(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.export" => {
            let input: oneiron::blob_artifact::ArtifactExportRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_export(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.born_from" => {
            let input: oneiron::blob_artifact::BornFromRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_born_from(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.proposals" => {
            let input: oneiron::blob_artifact::ArtifactRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_proposals(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.waits" => {
            let input: oneiron::blob_artifact::ArtifactRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_waits(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.release_wait" => {
            let input: oneiron::blob_artifact::ProposalSettleRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_release_wait(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.review_slides" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.artifacts.review_slides", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::blob_artifact::SlideReviewSubmit =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_artifacts_review_slides(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.propose_deck" => {
            let input: oneiron::blob_artifact::DeckProposeRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_propose_deck(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.propose_output" => {
            let input: oneiron::blob_artifact::NativeOutputRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_propose_output(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.keep" => {
            let input: oneiron::blob_artifact::ProposalSettleRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_keep(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.discard" => {
            let input: oneiron::blob_artifact::ProposalSettleRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_discard(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.undo" => {
            let input: oneiron::blob_artifact::ProposalSettleRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_undo(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "can" => {
            let input: oneiron::task_verb::sdk::TaskCanAskRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::can(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "peek" => {
            let input: oneiron::task_verb::TaskAskHandle =
                serde_json::from_value(input).map_err(|_| invalid())?;
            served.extend([input.group_ref]);
            let output = oneiron::task_verb::sdk::peek(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "ask" => {
            let input: oneiron::task_verb::sdk::TaskAskRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::ask(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "wait" => {
            let input: oneiron::task_verb::sdk::TaskWaitRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            served.extend([input.handle.group_ref]);
            let output = oneiron::task_verb::sdk::wait(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "tasks.answer" => {
            let input: oneiron::task_verb::sdk::TaskAnswerRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            served.extend([input.handle.group_ref]);
            let output =
                oneiron::task_verb::sdk::tasks_answer(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "tasks.outcomes" => {
            let input: oneiron::task_verb::TaskAskHandle =
                serde_json::from_value(input).map_err(|_| invalid())?;
            served.extend([input.group_ref]);
            let output = oneiron::task_verb::sdk::tasks_outcomes(&memory, input)
                .map_err(mcp_facade_error)?;
            served.extend(
                output
                    .iter()
                    .flat_map(|pair| pair.derived_from.iter().copied()),
            );
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.list" => {
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_list(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.messages" => {
            let input: oneiron::task_verb::sdk::RoomRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_messages(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::scoped_window(
                output.rows.len(),
                0,
                usize::from(output.next_after.is_some()),
                true,
            )
            .rows_at("rows")
            .resumed_by("next_after", "turn_ref");
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.participants" => {
            let input: oneiron::workspace_roster::ParticipantsRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_participants(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::scoped_window(
                output.rows.len(),
                0,
                usize::from(output.next_after.is_some()),
                true,
            )
            .rows_at("rows");
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.render" => {
            let input: oneiron::task_verb::sdk::RoomRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_render(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.find" => {
            let input: oneiron::task_verb::sdk::RoomRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_find(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::scoped_window(
                output.rows.len(),
                0,
                usize::from(output.next_after.is_some()),
                true,
            )
            .rows_at("rows")
            .resumed_by("next_after", "turn_ref");
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.get" => {
            let input: oneiron::task_verb::sdk::RoomTurnRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_get(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.trunk" => {
            let input: oneiron::task_verb::sdk::RoomTurnRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_trunk(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.reply_strips" => {
            let input: oneiron::conversation_dag::ReplyStripsRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_reply_strips(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::scoped_window(
                output.groups.len(),
                0,
                usize::from(output.next_after.is_some()),
                true,
            )
            .rows_at("groups");
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.claim" => {
            let input: oneiron::task_verb::sdk::RoomClaimRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_claim(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.speak" => {
            let input: oneiron::memory::WitnessTurn =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_speak(&memory, input)
                .map_err(mcp_facade_error)?;
            server
                .ai
                .turn_landed_by(server.vault(), actor.actor_ref, actor.actor_class);
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.projects.propose" => {
            let input: oneiron::workspace_roster::ProjectProposalRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_projects_propose(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.projects.proposals" => {
            let input: oneiron::task_verb::sdk::ProjectConversationRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_projects_proposals(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.projects.dismiss_card" => {
            let input: oneiron::task_verb::sdk::ProjectCardRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_projects_dismiss_card(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.projects.confirm" => {
            let input: oneiron::workspace_roster::ProjectCardConfirmRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_projects_confirm(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.projects.roster.write" => {
            let input: oneiron::workspace_roster::ProjectRosterWriteRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_projects_roster_write(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.projects.goal.intake" => {
            let input: oneiron::task_verb::sdk::ProjectRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_projects_goal_intake(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.join" => {
            let input: oneiron::workspace_roster::JoinRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_join(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.consent" => {
            let input: oneiron::workspace_roster::ConsentAnswer =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_consent(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.offer" => {
            let input: oneiron::workspace_roster::OfferDraft =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_offer(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.offer.answer" => {
            let input: oneiron::workspace_roster::OfferAnswerRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_offer_answer(&memory, input)
                .map_err(mcp_facade_error)?;
            server
                .ai
                .turn_landed_by(server.vault(), actor.actor_ref, actor.actor_class);
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.offer.vote" => {
            let input: oneiron::workspace_roster::OfferVoteRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_offer_vote(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.offer.reopen" => {
            let input: oneiron::workspace_roster::OfferReopenRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_offer_reopen(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.offers" => {
            let input: oneiron::workspace_roster::OffersRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_offers(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::scoped_window(
                output.rows.len(),
                0,
                usize::from(output.next_after.is_some()),
                true,
            )
            .rows_at("rows");
            mcp_agent_verb_output(output, source)
        }
        "vault.projects.goal.revisions" => {
            let input: oneiron::task_verb::sdk::ProjectRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_projects_goal_revisions(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.projects.goal.dismiss" => {
            let input: oneiron::task_verb::sdk::ProjectGoalDismissRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_projects_goal_dismiss(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.projects.route_tradeoff" => {
            let input: oneiron::task_verb::sdk::ProjectTradeoffRouteRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_projects_route_tradeoff(&memory, input)
                .map_err(mcp_facade_error)?;
            server
                .ai
                .turn_landed_by(server.vault(), actor.actor_ref, actor.actor_class);
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.conversations.turn.continue" => {
            let input: oneiron::conversation::TurnActionRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_conversations_turn_continue(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.conversations.turn.retry" => {
            let input: oneiron::conversation::TurnActionRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_conversations_turn_retry(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.messages.react" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.messages.react", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::reaction::MessageReactionRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_messages_react(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.host" => {
            let input: oneiron::task_verb::sdk::RoomHostRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_host(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.host.pin" => {
            let input: oneiron::workspace_roster::RoomHostPin =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_host_pin(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.host.hand" => {
            let input: oneiron::workspace_roster::RoomHostHand =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_host_hand(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.rooms.sharing" => {
            let input: oneiron::task_verb::sdk::RoomRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_rooms_sharing(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.companions.sharing.get" => {
            let input: oneiron::task_verb::sdk::CompanionSharingRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_companions_sharing_get(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.companions.sharing.set" => {
            let input: oneiron::task_verb::sdk::CompanionSharingSetRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_companions_sharing_set(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.workspace.work_companion.get" => {
            let input: oneiron::task_verb::sdk::WorkspaceRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::vault_workspace_work_companion_get(&memory, input)
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.workspace.work_companion.set" => {
            let input: oneiron::task_verb::sdk::WorkCompanionSetRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::vault_workspace_work_companion_set(&memory, input)
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.skills.save" => {
            let input: oneiron::skill::helper::SkillSaveRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_skills_save(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.skills.fork" => {
            let input: oneiron::skill::helper::SkillForkRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_skills_fork(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.skills.callables" => {
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::self_skills_callables(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "ai.options" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("ai.options", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::AiOptionsRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::ai_options(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "ai.image" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("ai.image", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::AiCallRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::ai_image(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "ai.speech" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("ai.speech", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::AiCallRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::ai_speech(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "ai.transcribe" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("ai.transcribe", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::AiCallRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::ai_transcribe(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "ai.embed" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("ai.embed", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::AiCallRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::ai_embed(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "ai.video" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("ai.video", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::AiCallRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::ai_video(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "ai.video.poll" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("ai.video.poll", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::AiVideoJobRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::ai_video_poll(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "ai.video.cancel" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("ai.video.cancel", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::AiVideoJobRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::ai_video_cancel(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "ai.verdict" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("ai.verdict", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::AiVerdictRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::ai_verdict(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.graph.ask" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.graph.ask", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::receipt::GraphAskRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_graph_ask(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.questions.create" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.questions.create", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::receipt::QuestionCreateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_questions_create(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.questions.edit" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.questions.edit", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::receipt::QuestionEditRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_questions_edit(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.questions.pause" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.questions.pause", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::receipt::QuestionPauseRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_questions_pause(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.questions.backfill" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.questions.backfill", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::receipt::QuestionBackfillRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_questions_backfill(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.questions.read" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.questions.read", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::receipt::QuestionReadRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_questions_read(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.questions.answers" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.questions.answers", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::receipt::QuestionAnswersRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_questions_answers(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.decisions.asks.answer" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.decisions.asks.answer", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::receipt::DecisionAskAnswerRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_decisions_asks_answer(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.decisions.asks.climb" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.decisions.asks.climb", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::receipt::DecisionAskClimbRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                crate::api::facade::host_doors::vault_decisions_asks_climb(server, auth, input)
                    .await
                    .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "self.decisions.asks" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("self.decisions.asks", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::task_verb::sdk::EmptyRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::self_decisions_asks(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "connector.list" => {
            let input: oneiron::task_verb::sdk::ConnectorListRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::connector_list(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "connector.status" => {
            let input: oneiron::task_verb::sdk::ConnectorNameRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::connector_status(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "connector.call" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("connector.call", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::outbound_consent::ConnectorCallRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::connector_call(
                server,
                auth,
                (actor.actor_ref, actor.actor_class),
                memory.invocation(),
                input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "connector.schema" => {
            let input: oneiron::task_verb::sdk::ConnectorSchemaRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::connector_schema(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.commit" => {
            let input: oneiron::task_verb::sdk::CommitRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::vault_commit(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.remember" => {
            let input: oneiron::memory::ClaimInput =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_remember(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.claims.retract" => {
            let input: oneiron::task_verb::sdk::ClaimRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_claims_retract(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.forget" => {
            let input: oneiron::task_verb::sdk::ForgetRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::vault_forget(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.claims.list" => {
            let input: oneiron::memory::ClaimListFilter =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_claims_list(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.claims.history" => {
            let input: oneiron::task_verb::sdk::ClaimRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_claims_history(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.delete" => {
            let input: oneiron::task_verb::sdk::SafeDeleteRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::vault_delete(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.writes.pending" => {
            let input: oneiron::task_verb::sdk::ReceiptsRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_writes_pending(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.hydrate" => {
            let input: oneiron::task_verb::sdk::HydrateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::vault_hydrate(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.get" => {
            let input: oneiron::task_verb::sdk::EntityRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output =
                oneiron::task_verb::sdk::vault_get(&memory, input).map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.refs.resolve" => {
            let input: oneiron::lens::ResolveRecordRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_refs_resolve(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.refs.links" => {
            let input: oneiron::lens::RecordLinksRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_refs_links(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.search.bm25" => {
            let input: oneiron::task_verb::sdk::QueryBm25Request =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_search_bm25(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.neighbors" => {
            let input: oneiron::task_verb::sdk::NeighborsRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_neighbors(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.structural.put" => {
            let input: oneiron::memory::StructuralPutInput =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_structural_put(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.habits.checkin" => {
            let input: oneiron::memory::HabitCheckinInput =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_habits_checkin(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.claims.admit" => {
            let input: oneiron::memory::AdmitImportedClaimInput =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_claims_admit(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.create" => {
            let input: oneiron::blob_artifact::ArtifactCreateRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_create(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.conversations.create" => {
            let input: oneiron::core_write::ConversationCreateInput =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_conversations_create(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.conversations.turns.create" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.conversations.turns.create", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::core_write::ConversationTurnCreateInput =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_conversations_turns_create(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.conversations.records.append" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.conversations.records.append", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::core_write::DagRecordAppendInput =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_conversations_records_append(
                server, auth, input,
            )
            .await
            .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.batch" => {
            let auth = actor.auth.as_ref().ok_or_else(invalid)?;
            oneiron::task_verb::sdk::validate_input("vault.batch", &input)
                .map_err(mcp_facade_error)?;
            let input: oneiron::core_write::CoreBatchWriteInput =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = crate::api::facade::host_doors::vault_batch(server, auth, input)
                .await
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.put" => {
            let input: oneiron::memory::BlobArtifactInput =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_put(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.import" => {
            let input: oneiron::office_body::OfficeBodyImportRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_import(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.head" => {
            let input: oneiron::office_body::OfficeBodyArtifactRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_head(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.read" => {
            let input: oneiron::office_body::OfficeBodyReadRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_read(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.commits" => {
            let input: oneiron::office_body::OfficeBodyArtifactRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_commits(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.edit" => {
            let input: oneiron::office_body::OfficeBodyEditRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_edit(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.fork.open" => {
            let input: oneiron::office_body::OfficeBodyForkOpenRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_fork_open(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.fork.edit" => {
            let input: oneiron::office_body::OfficeBodyForkEditRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_fork_edit(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.fork.diff" => {
            let input: oneiron::office_body::OfficeBodyForkRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_fork_diff(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.fork.merge" => {
            let input: oneiron::office_body::OfficeBodyForkMergeRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_fork_merge(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.fork.discard" => {
            let input: oneiron::office_body::OfficeBodyForkRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_fork_discard(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.export" => {
            let input: oneiron::office_body::OfficeBodyExportVerbRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_export(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.body.preview" => {
            let input: oneiron::office_body::OfficeBodyArtifactRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_body_preview(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.append" => {
            let input: oneiron::task_verb::sdk::AppendBlobVersionRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_append(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.artifacts.read" => {
            let input: oneiron::task_verb::sdk::ReadBlobVersionRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_artifacts_read(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.consolidation.enqueue" => {
            let input: oneiron::task_verb::sdk::ConsolidationEnqueueRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_consolidation_enqueue(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.consolidation.status" => {
            let input: oneiron::task_verb::sdk::ConsolidationStatusRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_consolidation_status(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.claims.seed" => {
            let input: oneiron::task_verb::sdk::CommitRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_claims_seed(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(output.len());
            mcp_agent_verb_output(output, source)
        }
        "connector.outbound.schedule" => {
            let input: oneiron::task_verb::sdk::OutboundScheduleRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::connector_outbound_schedule(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.notes.create" => {
            let input: oneiron::task_verb::sdk::CreateNoteRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_notes_create(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.notes.from_entity" => {
            let input: oneiron::task_verb::sdk::CreateNoteFromEntityRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_notes_from_entity(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.notes.edit" => {
            let input: oneiron::task_verb::sdk::EditNoteRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_notes_edit(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.notes.seal" => {
            let input: oneiron::note::NoteRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_notes_seal(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        "vault.notes.lifecycle" => {
            let input: oneiron::note::NoteRefRequest =
                serde_json::from_value(input).map_err(|_| invalid())?;
            let output = oneiron::task_verb::sdk::vault_notes_lifecycle(&memory, input)
                .map_err(mcp_facade_error)?;
            let source = crate::mcp::McpPageSource::complete(1);
            mcp_agent_verb_output(output, source)
        }
        _ => Err(invalid()),
    }
}
/// One typed verb result, drained in a single frame.
fn mcp_agent_verb_output(
    output: impl serde::Serialize,
    source: crate::mcp::McpPageSource,
) -> Result<
    (
        Value,
        crate::mcp::McpPageSource,
        McpCarrierPolicy,
        Option<u64>,
    ),
    McpGatewayError,
> {
    let value = serde_json::to_value(output).map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            "typed agent result cannot be encoded",
        )
    })?;
    Ok((value, source, McpCarrierPolicy::Drain, None))
}

// END GENERATED MCP DISPATCH

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_cap_reads_the_rows_key_the_manifest_names() {
        let source = crate::mcp::McpPageSource::complete(3).rows_at("items");
        let request = crate::mcp::McpPageRequest {
            limit: Some(2),
            forceful_override: false,
            cursor: None,
        };
        let mut page = McpPageBudget::resolve_page(Some(&request), source, 0);
        let mut output = json!({"count": 3, "items": [1, 2, 3], "rows": [1, 2, 3]});
        mcp_cap_verb_rows(&mut output, &mut page, source);
        assert_eq!(output["items"], json!([1, 2]));
        assert_eq!(output["count"], 2);
        // Only the list the producer names is its page.
        assert_eq!(output["rows"], json!([1, 2, 3]));
    }
}
