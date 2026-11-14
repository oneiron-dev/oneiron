//! Tasks verb and response shaping.

use super::served_rows::stop_release_rows;
use super::{
    McpCallContext, McpCarrierPolicy, McpGatewayError, McpServed, execute_mcp_board_verb,
    mcp_current_board, mcp_endpoint_result, mcp_facade_error, mcp_page_cursor_error,
    mcp_preflight_page, mcp_release_listed, mcp_request_id, mcp_resolve_page,
    mcp_scoped_tasks_section,
};
use crate::error::{ApiError, ApiErrorDetails, ErrorCode};
use crate::mcp::McpActorClass;
use crate::mcp::McpPageBudget;
use crate::mcp::McpPageSnapshot;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpVerbToolArgs;
use crate::server::SyncServer;
use oneiron::ErrorKind;
use oneiron::runtime_hooks::verb::VerbAskDrainPermit;
use serde_json::Value;
use serde_json::json;
use std::ops::ControlFlow;
use std::sync::Arc;

fn mcp_tasks_section(
    server: &Arc<SyncServer>,
    actor: &McpResolvedActor,
    rows: oneiron::context_board::TasksSectionRows,
    served: &mut Vec<oneiron::EntityId>,
) -> Result<(Value, crate::mcp::McpPageSource), McpGatewayError> {
    let (section, scope_omitted) =
        mcp_scoped_tasks_section(server, actor, rows, &[], served, &Default::default())?;
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
        description @ (oneiron::task_verb::TaskDescription::SelfCard { .. }
        | oneiron::task_verb::TaskDescription::VaultCard { .. }
        | oneiron::task_verb::TaskDescription::Status { .. }) => {
            let value = serde_json::to_value(description).map_err(|_| {
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
    // Held content counts as it arrived (FIX 22074).
    let argument_digest = args.page_argument_digest();
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
    // It tracks whether a producer's path listed none (FIX 5988).
    let mut served = McpServed::default();
    // The hook blocks a fresh board read's answer shows; a continuation
    // restates a retained answer and spends nothing again.
    let mut hooks = None;
    let mut hook_notice = None;
    let (mut output, health, carrier, mut snapshot, producer_epoch) =
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
                let read = native_read::execute_mcp_native_read(server, &args, actor, &mut served);
                match read.await? {
                    ControlFlow::Continue(produced) => produced,
                    // A verb hook's stop is a result the client reads (FIX 1435).
                    ControlFlow::Break(stopped) => return Ok(stopped),
                }
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
                // The generated verb table's fan-out, on the heap (FIX 12072).
                let produced = Box::pin(execute_mcp_agent_verb(
                    server,
                    &args,
                    actor,
                    &mut served,
                    &mut hooks,
                ))
                .await;
                let produced = match produced {
                    // A verb hook's stop is a result the client reads, not a
                    // refusal (ARCH-0080 §3), released by its saved answer's
                    // rows on a drained call's retry (FIX 21054).
                    Err(McpGatewayError {
                        hook: Some(stop),
                        hook_notice,
                        ..
                    }) => {
                        let stop = *stop;
                        let rows = stop_release_rows(server, actor, &stop, &mut served);
                        let owner_whole_vault_export =
                            super::device_release::owner_whole_vault_export_call(
                                server,
                                actor,
                                args.tool.name,
                            );
                        if super::served_rows::drained_rows_lapsed(
                            server,
                            actor,
                            &stop,
                            rows,
                            owner_whole_vault_export,
                        ) {
                            return Ok(super::claimed_release::details_on_device_result());
                        }
                        return mcp_hook_stop_result(server, &args, actor, stop, rows, hook_notice);
                    }
                    produced => produced,
                };
                // A refusal is released by the rows its verb served first.
                let (output, source, carrier, epoch, notice) = produced.map_err(|error| {
                    super::device_release::mcp_release_error(server, actor, served.rows(), error)
                })?;
                hook_notice = notice;
                (output, source, carrier, epoch.or(task_epoch))
            };
            // An act whose rows are unknown (FIX 5988), or held (FIX 8171), answers
            // off this device only that it ran; a read releases as before.
            let (output, rows) =
                super::served_rows::held_act_answer(server, args.tool.name, actor, output, served)?;
            let snapshot = McpPageSnapshot {
                output: output.clone(),
                source,
                health: source.health(),
                keyframe: None,
                rows,
            };
            (output, source.health(), carrier, snapshot, producer_epoch)
        };
    let hook_notice = mcp_hook_notice(server, actor, hook_notice, &mut snapshot.rows);
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
    // A continuation that goes back inside the call's own argument (FIX 9175).
    if let Some(resume) = snapshot
        .source
        .resume
        .filter(|resume| resume.within.is_some())
    {
        let arguments = serde_json::to_value(&args.payload.arguments).unwrap_or_default();
        page.resume_within(resume, arguments.get(resume.argument));
    }
    // A step's type feedback leaves on its own release (FIX 10390).
    let feedback = super::type_feedback_release::hold_verb_feedback(args.tool.name, &mut output);
    let mut structured = json!({
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
    if let Some(notice) = hook_notice {
        structured["meta"]["hook_notice"] = notice;
    }
    // A board read records the receipt its hook rows owe before it goes out
    // and spends their blocks once it has, as setup's page one does (OF-579).
    if let Some(hooks) = &mut hooks {
        hooks.record_receipt(server).await?;
    }
    let continued = dispatch.continuation.is_some();
    let result = mcp_endpoint_result(
        server,
        actor,
        format!("{} completed", args.tool.name),
        structured,
        carrier,
    )
    .await;
    let rows = snapshot.rows.as_deref();
    // The owner's own whole-vault export, as this call's route and his fresh
    // proof name it, is released as his will (owner ruling 1-EXPORT = B).
    let owner_whole_vault_export =
        super::device_release::owner_whole_vault_export_call(server, actor, args.tool.name);
    let result = mcp_release_listed(
        server,
        actor,
        rows,
        continued,
        result,
        owner_whole_vault_export,
    )
    .map(|result| {
        super::type_feedback_release::attach_verb_feedback(server, actor, rows, feedback, result)
    });
    if result.is_ok()
        && let Some(hooks) = &hooks
    {
        hooks.spend(server);
    }
    result
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
    // A managed vault's attested owner carries no slip: he reads with his
    // own key, held to this request's owner proof (WILL-PLAN L14 row 01).
    if let Some(auth) = actor
        .auth
        .as_ref()
        .filter(|auth| auth.managed_owner().is_some())
    {
        return crate::api::scoped_read_for_core_auth(vault, auth).map_err(mcp_api_error);
    }
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
    // A host credential's refusal (FIX 2222) keeps its typed kind.
    let key = vault
        .credential_read_key(proof)
        .map_err(|error| mcp_engine_error("credential read key failed", error))?
        .ok_or_else(refused)?;
    Ok(vault.scoped_read(key.for_destination(&actor.destination())))
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
    if let Some(legal_hold) = error.legal_hold().cloned().map(Box::new) {
        return McpGatewayError::new(-32020, "legal_hold", error.message())
            .with_legal_hold(legal_hold);
    }
    // The typed 403 refusals answer as the facade's copy of each does: one
    // MCP code and stable kind, whichever door reported it (FIX 11434).
    let typed = match error.code() {
        ErrorCode::HostActionRequiresSupportGrant => Some(MCP_HOST_ACTION_REFUSED),
        ErrorCode::OwnerBindingRequired => Some(MCP_OWNER_BINDING_REQUIRED),
        _ => None,
    };
    if let Some(kind) = typed {
        return McpGatewayError::new(-32020, kind, error.message());
    }
    let code = match error.code() {
        ErrorCode::BadRequest => -32602,
        ErrorCode::NotFound => -32004,
        ErrorCode::InvalidState => -32020,
        ErrorCode::InternalServerError => -32603,
        _ => -32000,
    };
    let mut gateway = McpGatewayError::new(code, error.code().as_str(), error.message());
    gateway.room_join_hold = error.room_join_hold().cloned().map(Box::new);
    if let ApiErrorDetails::BadRequest { field } = error.details()
        && let Some(field) = field
    {
        gateway = gateway.with_field(field.clone());
    }
    gateway
}

/// The stable MCP kind of the typed refusal a host credential gets where no
/// host acts as a person (FIX 2222); its code is -32020, as every refusal's.
pub(super) const MCP_HOST_ACTION_REFUSED: &str = "host_action_requires_support_grant";

/// The stable MCP kind of the typed refusal an owner act gets without the
/// owner binding it needs (FIX 11434); its code is -32020 too.
pub(super) const MCP_OWNER_BINDING_REQUIRED: &str = "owner_binding_required";

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
    // FIX 2222: the owner refusal a read key or a host action carries (a
    // self-hosted root that binds no live owner) is the engine's typed
    // refusal, never the generic engine error.
    if matches!(
        error,
        oneiron::Error::Claim(oneiron::error::ClaimError::ScopedReadOwnerNotLive(_))
    ) {
        return mcp_facade_error(oneiron::MemoryError::from(error));
    }
    // A refusal that names its bound is the facade's INVALID_STATE with its
    // message (FIX 4618), never the generic engine error.
    if matches!(error, oneiron::Error::Refused(_)) {
        return mcp_facade_error(oneiron::MemoryError::from(error));
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
        ErrorKind::HostActionRequiresSupportGrant => {
            McpGatewayError::new(-32020, MCP_HOST_ACTION_REFUSED, error.to_string())
        }
        ErrorKind::LegalHold => mcp_facade_error(oneiron::MemoryError::from(error)),
        _ => {
            let mut refusal =
                McpGatewayError::new(-32603, "engine_error", format!("{context}: {error}"));
            if let oneiron::Error::Record(oneiron::error::RecordError::RoomJoinHeld(hold)) = error {
                refusal.room_join_hold = Some(hold);
            }
            refusal
        }
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
    error.hook_notice = matches!(
        &stop,
        VerbHookStop::Completed {
            hook_notice: Some(true),
            ..
        } | VerbHookStop::CompletedWithError {
            hook_notice: Some(true),
            ..
        }
    )
    .then(|| oneiron::task_verb::revoke_lands::CALLER_NOTICE_SUMMARY.to_owned());
    error.hook = Some(Box::new(stop));
    error
}

/// Resolves the short refs embedded in a notice before releasing its detail.
/// Allowed detail keeps those rows in the reply's replay provenance, after an
/// act's own detail narrowing; unknown or held detail stays content-free.
pub(super) fn mcp_hook_notice(
    server: &SyncServer,
    actor: &McpCallContext,
    notice: Option<String>,
    rows: &mut Option<Vec<oneiron::EntityId>>,
) -> Option<Value> {
    let notice = notice?;
    let withheld = || json!(oneiron::task_verb::sdk::ActAnswer::<()>::details_on_device());
    let Some(named) = crate::device_local::short_refs_in_text(&server.vault, &notice) else {
        return Some(withheld());
    };
    if !crate::device_local::retained_hold(
        &server.vault,
        &actor.destination(),
        &named,
        notice.as_bytes(),
    )
    .is_ok_and(|hold| hold.is_none())
    {
        return Some(withheld());
    }
    if let Some(rows) = rows {
        rows.extend(named);
    }
    Some(Value::String(notice))
}

/// A verb hook's stop as the tool result a client reads (ARCH-0080 §3): the
/// verb gave no output, so `isError` is set, and `structuredContent.hook`
/// carries the typed stop, a pending ask's invocation and handle included.
fn mcp_hook_stop_result(
    server: &Arc<SyncServer>,
    args: &McpVerbToolArgs,
    actor: &McpCallContext,
    stop: oneiron::runtime_hooks::VerbHookStop,
    served: Option<&[oneiron::EntityId]>,
    hook_notice: Option<String>,
) -> Result<Value, McpGatewayError> {
    let mut served = served.map(<[oneiron::EntityId]>::to_vec);
    let hook_notice = mcp_hook_notice(server, actor, hook_notice, &mut served);
    let text = stop.to_string();
    let mut structured = json!({
        "tool": args.tool.name,
        "family": args.tool.family.as_str(),
        "verb": args.tool.verb,
        "hook": stop,
        "actor": mcp_actor_result(actor),
    });
    let mut content = vec![mcp_text_content(text)];
    if let Some(notice) = hook_notice {
        content.push(mcp_text_content(
            notice
                .as_str()
                .map_or_else(|| notice.to_string(), str::to_owned),
        ));
        structured["meta"] = json!({"hook_notice": notice});
    }
    let result = json!({
        "content": content,
        "structuredContent": structured,
        "isError": true,
    });
    mcp_release_listed(server, actor, served.as_deref(), false, result, false)
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
    if let Some(receipt) = error
        .row_receipt
        .and_then(|stamp| super::actions::row_receipt(&stamp))
        && let Some(object) = data.as_object_mut()
    {
        object.insert("row_receipt".to_owned(), receipt);
    }
    if let Some(stop) = error.hook
        && let Some(object) = data.as_object_mut()
    {
        object.insert("hook".to_owned(), json!(*stop));
    }
    if let Some(notice) = error.hook_notice
        && let Some(object) = data.as_object_mut()
    {
        object.insert("hook_notice".to_owned(), Value::String(notice));
    }
    if let Some(legal_hold) = error.legal_hold
        && let Some(object) = data.as_object_mut()
    {
        object.insert("legal_hold".to_owned(), json!(*legal_hold));
    }
    if let Some(room_join_hold) = error.room_join_hold
        && let Some(object) = data.as_object_mut()
    {
        object.insert("room_join_hold".to_owned(), json!(*room_join_hold));
    }
    if let Some(retry_after) = error.retry_after
        && let Some(object) = data.as_object_mut()
    {
        object.insert("retry_after".to_owned(), json!(retry_after));
    }
    if let Some(resets_at) = error.resets_at
        && let Some(object) = data.as_object_mut()
    {
        object.insert("resets_at".to_owned(), json!(*resets_at));
    }
    if !error.reason_codes.is_empty()
        && let Some(object) = data.as_object_mut()
    {
        object.insert("reason_codes".to_owned(), json!(error.reason_codes));
    }
    if let Some(steps) = error.program_steps
        && let Some(object) = data.as_object_mut()
    {
        super::type_feedback_release::stamp_error_feedback(*steps, object);
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

/// The code-mode run one call is made in (`execute_code`): the host origin
/// its writes are made under, and the run itself, the creating run of the
/// live lens cards the call renders (OF-181, FIX 2612 (a)).
pub(crate) struct McpCodeRun {
    pub(crate) origin: oneiron::memory::HostWriteOrigin,
    pub(crate) run_id: oneiron::EntityId,
}

/// What one MCP row's credential surface is built from beside its call
/// context: where its TASKs are born, the invocation its hooks cross under,
/// a code-mode call's run, and the task-work turn the row holds.
struct McpRowSurface {
    position: oneiron::federation::record_scope::BirthPosition,
    invocation: oneiron::runtime_hooks::InvocationId,
    run: Option<McpCodeRun>,
    /// The turn the dispatch awaited for a task-work row (Rule 5): every
    /// surface built for the row runs on it and waits for no other.
    task_work_turn: Option<Arc<oneiron::work_line::TaskWorkTurn>>,
}

impl McpRowSurface {
    /// Who owns the live lens card `verb` renders for `request` on this
    /// row: a code-mode call's run, for that request's own subscription.
    /// A direct tool call, or a hook's resumed one, carries no run, so its
    /// card is held unowned (FIX 2612 (c)).
    fn lens_owner(&self, verb: &str, request: &Value) -> Option<crate::lens_frames::CardOwner> {
        self.run
            .as_ref()
            .map(|run| crate::lens_frames::CardOwner::run_request(run.run_id, verb, request))
    }

    /// The caller's surface for one row: its credential at its locality,
    /// born at this position, under this invocation and host origin, in the
    /// off-record session `mcp_credential_memory` binds for its principal
    /// (a slip naming none binds none, as its call receipt keeps none), its
    /// reads listed in `producers`. The door its call is rebuilt by is
    /// bound on it, so a call its budget window paces holds in its caller's
    /// line (FIX 19034).
    fn memory<'a>(
        &self,
        server: &'a SyncServer,
        actor: &McpCallContext,
        producers: &'a oneiron::memory::ProducerRows,
    ) -> oneiron::Memory<'a> {
        let memory = crate::api::mcp_credential_memory(
            &server.vault,
            actor.auth.as_ref(),
            actor.actor_ref,
            actor.actor_class,
        )
        .at(actor.locality())
        .with_birth_position(self.position)
        .listing_producers(producers)
        .with_invocation(self.invocation)
        .with_credential_door(verb_hooks::mcp_verb_ask_door(actor, Some(self.invocation)));
        let memory = match &actor.signing_request_transport {
            Some(transport) => memory.with_signing_request_transport(transport.clone()),
            None => memory,
        };
        // The hook pause the request resumes beside the invocation it named
        // (L13 PR-D): with no invocation named, it resumes nothing.
        let memory = match actor.hook_ask.filter(|_| actor.invocation.is_some()) {
            Some(ask) => memory.with_hook_ask(ask),
            None => memory,
        };
        let memory = match &self.run {
            Some(run) => memory.with_host_origin(run.origin.clone()),
            None => memory,
        };
        match &self.task_work_turn {
            Some(turn) => memory.with_task_work_turn(Arc::clone(turn)),
            None => memory,
        }
    }
}

/// The drain's permit when `actor` is the drain's run of its own invocation:
/// a held call's turn, or a resumed ask (FIX 19034).
fn mcp_drain_permit(actor: &McpCallContext) -> Option<&VerbAskDrainPermit> {
    actor
        .drain
        .as_ref()
        .filter(|drain| Some(drain.invocation()) == actor.invocation)
}

/// `call` with the drain's permit entered in each of its polls, when it is
/// the drain's run of its own invocation (FIX 19034): a paced turn's row
/// then runs as that turn, and its retry lookup lets it through. No scope
/// is held across an await, so a task the runtime moves to another thread
/// never carries it there. Any other call runs as it is.
pub(super) async fn mcp_drain_polls<F: std::future::Future>(
    actor: &McpCallContext,
    call: F,
) -> F::Output {
    let Some(permit) = mcp_drain_permit(actor) else {
        return call.await;
    };
    let mut call = std::pin::pin!(call);
    std::future::poll_fn(|cx| {
        let _drain = permit.enter();
        call.as_mut().poll(cx)
    })
    .await
}

/// The paced context a paced host door takes for a tool-first MCP call on
/// `memory`, the row's surface (FIX 22259): its invocation, the MCP door it
/// came in by and, on the drain's run of it, the drain's permit. `None`
/// when the surface names no invocation.
pub(super) fn mcp_paced_call(
    actor: &McpCallContext,
    memory: &oneiron::Memory<'_>,
) -> Option<crate::api::facade::FacadePacedCall> {
    let invocation = memory.invocation()?;
    Some(crate::api::facade::FacadePacedCall::mcp(
        invocation,
        verb_hooks::mcp_verb_ask_door(actor, Some(invocation)),
        mcp_drain_permit(actor).cloned(),
    ))
}

/// The caller's surface a retry of `invocation` is looked up on before an
/// admission intent starts again (FIX 19034): its credential at its
/// locality, under that invocation, with the door a paced call of it holds
/// by, as the row's own surface binds them.
pub(super) fn mcp_paced_lookup_memory<'a>(
    server: &'a SyncServer,
    actor: &McpCallContext,
    invocation: oneiron::runtime_hooks::InvocationId,
) -> oneiron::Memory<'a> {
    crate::api::mcp_credential_memory(
        &server.vault,
        actor.auth.as_ref(),
        actor.actor_ref,
        actor.actor_class,
    )
    .at(actor.locality())
    .with_invocation(invocation)
    .with_credential_door(verb_hooks::mcp_verb_ask_door(actor, Some(invocation)))
}

/// Runs task row `tool` by `row` on a blocking thread, on the caller's
/// surface built there with the host's task decisions bound (OF-533): a
/// post's take question and a report's done and ask-up questions go through
/// the host's ladder, whose model rung may block on the server's runtime.
/// The row's hooks stay with its caller. The rows its reads listed come back
/// beside its result, a refusal's too. A ladder the host cannot build
/// refuses the row: it never runs unbound.
async fn mcp_task_row<T: Send + 'static>(
    server: &Arc<SyncServer>,
    tool: &str,
    actor: &McpCallContext,
    surface: McpRowSurface,
    row: impl FnOnce(&oneiron::Memory<'_>) -> oneiron::memory::MemoryResult<T> + Send + 'static,
) -> Result<(oneiron::memory::MemoryResult<T>, Vec<oneiron::EntityId>), McpGatewayError> {
    let (server, actor) = (Arc::clone(server), actor.clone());
    // A code-mode call writes for the leased run its origin seals, on this
    // thread too (FIX 10748).
    let run_writes = surface
        .run
        .as_ref()
        .and_then(|run| oneiron::skill_attribution::run_write_token_of_origin(&run.origin));
    tokio::task::spawn_blocking(move || {
        // The drain's run of this invocation runs as its turn on this
        // thread too (FIX 19034).
        let _drain = mcp_drain_permit(&actor).map(VerbAskDrainPermit::enter);
        let producers = oneiron::memory::ProducerRows::default();
        let output = oneiron::skill_attribution::with_run_write_token(run_writes.as_ref(), || {
            server
                .decision_host()
                .task_decisions()
                .map_err(oneiron::memory::MemoryError::from)
                .and_then(|decisions| {
                    row(&surface
                        .memory(&server, &actor, &producers)
                        .with_task_decisions(decisions))
                })
        });
        (output, producers.take())
    })
    .await
    .map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            format!("{tool} worker ended without a result"),
        )
    })
}

/// Runs blocking row `tool` by `row` on a blocking thread, on the caller's
/// surface rebuilt there (FIX 9609): an organ call may wait out its whole
/// deadline, and a provider read over blocking HTTP panics on a debug
/// runtime worker (fix list row 20520); neither may hold one. The row's hooks
/// stay with its caller. The rows its reads listed come back beside its
/// result, a refusal's too. The rebuilt surface keeps the row's credential
/// and write context. Rows needing direct authorship must not take this
/// hop: the listing's bind is not
/// re-applied inside (today only `vault.workspace.work_companion.set` and
/// `tasks.answer`, neither a blocking row).
async fn mcp_off_runtime_row<T: Send + 'static>(
    server: &Arc<SyncServer>,
    tool: &str,
    actor: &McpCallContext,
    surface: McpRowSurface,
    row: impl FnOnce(&oneiron::Memory<'_>) -> oneiron::memory::MemoryResult<T> + Send + 'static,
) -> Result<(oneiron::memory::MemoryResult<T>, Vec<oneiron::EntityId>), McpGatewayError> {
    let (server, actor) = (Arc::clone(server), actor.clone());
    // A code-mode call writes for the leased run its origin seals, on this
    // thread too (FIX 10748).
    let run_writes = surface
        .run
        .as_ref()
        .and_then(|run| oneiron::skill_attribution::run_write_token_of_origin(&run.origin));
    tokio::task::spawn_blocking(move || {
        // The drain's run of this invocation runs as its turn on this
        // thread too (FIX 19034).
        let _drain = mcp_drain_permit(&actor).map(VerbAskDrainPermit::enter);
        let producers = oneiron::memory::ProducerRows::default();
        let output = oneiron::skill_attribution::with_run_write_token(run_writes.as_ref(), || {
            let memory = surface.memory(&server, &actor, &producers);
            row(&memory)
        });
        (output, producers.take())
    })
    .await
    .map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            format!("{tool} worker ended without a result"),
        )
    })
}

/// The proof a direct MCP caller's own request binds for `tool`, as the
/// HTTP facade binds it outside a room turn: the work-companion setting
/// takes the person's own proof (OF-417), an attendee ask's answer the
/// owner's own authorship (OF-365), and the owner's own `vault.delete` his
/// authorship and this host's slip issuer, so deleting a Connect guest's
/// PERSON withdraws its grants first (FIX 3875, 5317). Every other row binds
/// none here, and a code-mode call's host origin suppresses either in the
/// engine.
fn mcp_direct_authorship<'a>(
    server: &'a SyncServer,
    tool: &str,
    actor: &McpCallContext,
    memory: oneiron::Memory<'a>,
) -> Result<oneiron::Memory<'a>, McpGatewayError> {
    if !matches!(
        tool,
        "vault.workspace.work_companion.set" | "tasks.answer" | "vault.delete"
    ) {
        return Ok(memory);
    }
    let Some(auth) = actor.auth.as_ref() else {
        return Ok(memory);
    };
    let Some(owner) =
        crate::api::facade::direct_authorship(auth, server, tool).map_err(mcp_api_error)?
    else {
        return Ok(memory);
    };
    let memory = memory.with_owner_authorship(&owner);
    // With no host key the delete runs as before (FIX 3875).
    Ok(
        match server.host_issuer().filter(|_| tool == "vault.delete") {
            Some(issuer) => memory.with_host_slip_issuer(issuer),
            None => memory,
        },
    )
}

use super::{board_setup, memory_response, skill_execution, verb_hooks};
mod agent_verb_dispatch {
    include!(concat!(env!("OUT_DIR"), "/agent_verb_dispatch.rs"));
}
pub(super) mod native_read;
use agent_verb_dispatch::execute_mcp_agent_verb;
pub(crate) use agent_verb_dispatch::{
    execute_agent_verb_input, mcp_agent_verb_arguments, mcp_agent_verb_input,
};

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

    /// A reap pause's MCP refusal names its capacity bound and the
    /// self-host route in `error.data`, in the shape the managed HTTP body
    /// carries, and keeps its kind (L9-61).
    #[test]
    fn a_reap_pause_mcp_refusal_names_its_capacity_bound_and_the_self_host_route() {
        let refusal = super::super::mcp_facade_error(oneiron::MemoryError::new(
            crate::managed::WRITES_FROZEN_TAG,
            crate::managed::ManagedError::WritesFrozen.to_string(),
            &[],
        ));
        let response = mcp_error_response(json!(7), refusal);
        let error = &response["error"];
        assert_eq!(error["code"], -32020);
        let data = &error["data"];
        assert_eq!(data["kind"], "writes_frozen");
        assert_eq!(
            data["bound"],
            json!({
                "kind": "capacity",
                "resource": "vault_lifecycle_allocation",
                "phase": "reap_prepare",
            })
        );
        assert_eq!(
            data["self_hosted"],
            json!({"supported": true, "condition": "no_service_reap_limit"})
        );
        let message = data["human_message"].as_str().expect("human_message");
        assert!(message.contains("a capacity bound"), "{message}");
    }

    /// Any other MCP refusal's `error.data` carries no bound.
    #[test]
    fn another_mcp_refusal_carries_no_bound() {
        let refusal = super::super::mcp_facade_error(oneiron::MemoryError::new(
            oneiron::MEMORY_CODE_FORBIDDEN,
            "refused",
            &[],
        ));
        let response = mcp_error_response(json!(8), refusal);
        let data = &response["error"]["data"];
        assert!(data.get("bound").is_none(), "{data}");
        assert!(data.get("self_hosted").is_none(), "{data}");
    }
}
