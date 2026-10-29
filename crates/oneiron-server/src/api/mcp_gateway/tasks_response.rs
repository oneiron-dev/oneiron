//! Tasks verb and response shaping.

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
use serde_json::Value;
use serde_json::json;
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
    // It tracks whether a producer's path listed none (FIX 5988).
    let mut served = McpServed::default();
    // The hook blocks a fresh board read's answer shows; a continuation
    // restates a retained answer and spends nothing again.
    let mut hooks = None;
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
                let produced =
                    execute_mcp_agent_verb(server, &args, actor, &mut served, &mut hooks).await;
                let produced = match produced {
                    // A verb hook's stop is a result the client reads, not a
                    // refusal (ARCH-0080 §3).
                    Err(McpGatewayError {
                        hook: Some(stop), ..
                    }) => return mcp_hook_stop_result(server, &args, actor, *stop, served.rows()),
                    produced => produced,
                };
                // A refusal is released by the rows its verb served first.
                let (output, source, carrier, epoch) = produced.map_err(|error| {
                    super::device_release::mcp_release_error(server, actor, served.rows(), error)
                })?;
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
    let result = mcp_release_listed(server, actor, rows, continued, result).map(|result| {
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
        _ => McpGatewayError::new(-32603, "engine_error", format!("{context}: {error}")),
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
    served: Option<&[oneiron::EntityId]>,
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
    mcp_release_listed(server, actor, served, false, result)
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
    if let Some(retry_after) = error.retry_after
        && let Some(object) = data.as_object_mut()
    {
        object.insert("retry_after".to_owned(), json!(retry_after));
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
    /// reads listed in `producers`.
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
        .with_invocation(self.invocation);
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
    tokio::task::spawn_blocking(move || {
        let producers = oneiron::memory::ProducerRows::default();
        let output = server
            .decision_host()
            .task_decisions()
            .map_err(oneiron::memory::MemoryError::from)
            .and_then(|decisions| {
                row(&surface
                    .memory(&server, &actor, &producers)
                    .with_task_decisions(decisions))
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
/// owner's own authorship (OF-365). Every other row binds none here, and a
/// code-mode call's host origin suppresses either in the engine.
fn mcp_direct_authorship<'a>(
    server: &SyncServer,
    tool: &str,
    actor: &McpCallContext,
    memory: oneiron::Memory<'a>,
) -> Result<oneiron::Memory<'a>, McpGatewayError> {
    if !matches!(tool, "vault.workspace.work_companion.set" | "tasks.answer") {
        return Ok(memory);
    }
    let Some(auth) = actor.auth.as_ref() else {
        return Ok(memory);
    };
    Ok(
        match crate::api::facade::direct_authorship(auth, server, tool).map_err(mcp_api_error)? {
            Some(owner) => memory.with_owner_authorship(&owner),
            None => memory,
        },
    )
}

use super::{board_setup, skill_execution, verb_hooks};
#[path = "generated/agent_verb_dispatch.rs"]
mod agent_verb_dispatch;
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
}
