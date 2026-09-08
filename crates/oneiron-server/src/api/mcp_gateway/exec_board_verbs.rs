//! Execute-code and board-verb executors.

use super::{
    McpBoardOmissions, McpBoardState, McpCallContext, McpCarrierPolicy, McpGatewayError,
    mcp_actor_result, mcp_board_frame_error, mcp_board_verb_error, mcp_current_board,
    mcp_endpoint_result, mcp_page_cursor_error,
};
use crate::mcp::McpPageBudget;
use crate::mcp::McpResolvedActor;
use crate::mcp::McpRetrievalHealth;
use crate::server::SyncServer;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;

/// `execute_code`: ONE durable REPL run, through the INJECTED host.
///
/// UNREACHABLE FROM THE WIRE in this release (ONE-1704 B1/B2). `execute_code`
/// is registered on neither endpoint and a direct call is refused at
/// [`mcp_execute_code_unavailable`] before this body could be entered, so no run
/// is created and the `resume` handle below never reaches a caller. The body is
/// kept as the private adapter over the injected host seam — the same shape M1
/// left the retired plain-verb adapters in — and NOT as a second catalog.
///
/// The gateway evaluates nothing and owns no dispatch loop. The bound host
/// constructs `HostSelfDispatcher`/`GatedActorWrite` and enters the existing
/// sandbox/REPL provider through `EngineNativeExecutor`, which owns every step,
/// replay row, and terminal marker. With no host bound this fails CLOSED.
pub(crate) async fn execute_mcp_execute_code(
    server: &Arc<SyncServer>,
    args: crate::mcp::McpExecuteCodeToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    if args.page.as_ref().is_some_and(|page| page.cursor.is_some()) {
        return Err(mcp_page_cursor_error(
            crate::mcp::McpPageCursorError::Unsupported,
        ));
    }

    let host = crate::mcp::mcp_code_execution_host()
        .ok_or_else(|| mcp_code_execution_error(&crate::mcp::McpCodeExecutionError::HostUnbound))?;
    let run_id = crate::mcp::mcp_code_run_id(&args.run_ref, actor);
    let outcome = host
        .execute(crate::mcp::McpCodeExecutionRequest {
            vault: Arc::clone(&server.vault),
            actor,
            run_ref: &args.run_ref,
            task: &args.task,
            run_id,
        })
        .await
        .map_err(|error| mcp_code_execution_error(&error))?;

    let steps = outcome
        .replay_record
        .bridge_calls
        .iter()
        .map(|call| {
            json!({
                "seq": call.seq,
                "effect": call.effect.as_str(),
                "outcome": mcp_bridge_outcome_value(&call.outcome),
            })
        })
        .collect::<Vec<_>>();
    let terminal = matches!(
        outcome.status,
        oneiron::engine_executor::EngineExecutorStatus::Complete
    );
    // Non-continuable: the step log is a run's own, not a re-enumerable
    // producer set, so a non-terminal page here states
    // `continuation_unavailable` instead of minting a handle nothing consumes.
    let page = McpPageBudget::resolve(
        args.page.as_ref(),
        crate::mcp::McpPageSource::truncated(steps.len(), 0, terminal),
    );
    let steps = page.cap(steps);
    let structured = json!({
        "tool": crate::mcp::MCP_EXECUTE_CODE_TOOL,
        "schema_version": crate::mcp::MCP_CODE_RUN_SCHEMA_VERSION,
        "run_ref": args.run_ref,
        // The persisted run handle: the durable replay record this run id
        // addresses is the resume door, and re-entering it is one call.
        "run_id": run_id.to_hex(),
        "resume": {
            "tool": crate::mcp::MCP_EXECUTE_CODE_TOOL,
            "run_ref": args.run_ref,
            "run_id": run_id.to_hex(),
            "terminal": terminal,
        },
        "steps_run": outcome.steps_run,
        "bridge_calls": outcome.replay_record.bridge_calls.len(),
        "steps": steps,
        "result": mcp_executor_status_value(&outcome.status),
        "actor": mcp_actor_result(actor),
        "meta": actor.metadata(
            mcp_code_run_health(&outcome.status),
            page,
            mcp_code_run_help(&outcome.status),
            args.cache,
        ),
    });
    Ok(mcp_endpoint_result(
        server,
        actor,
        "execute_code run recorded",
        structured,
        McpCarrierPolicy::Drain,
    )
    .await)
}

fn mcp_code_execution_error(error: &crate::mcp::McpCodeExecutionError) -> McpGatewayError {
    let code = match error {
        crate::mcp::McpCodeExecutionError::HostUnbound => -32020,
        crate::mcp::McpCodeExecutionError::RunBinding(_)
        | crate::mcp::McpCodeExecutionError::Run(_) => -32603,
    };
    McpGatewayError::new(code, error.error_code(), error.to_string())
}

/// The health a run's own terminal state forces. A parked or yielded run has
/// not finished, and says so.
fn mcp_code_run_health(
    status: &oneiron::engine_executor::EngineExecutorStatus,
) -> McpRetrievalHealth {
    match status {
        oneiron::engine_executor::EngineExecutorStatus::Complete => McpRetrievalHealth::Healthy,
        oneiron::engine_executor::EngineExecutorStatus::Waiting(_)
        | oneiron::engine_executor::EngineExecutorStatus::Yielded { .. } => {
            McpRetrievalHealth::Partial
        }
        oneiron::engine_executor::EngineExecutorStatus::HardStepLimitReached => {
            McpRetrievalHealth::Degraded
        }
    }
}

/// What a caller can actually DO next. Every line here is true of the durable
/// run this result describes.
fn mcp_code_run_help(status: &oneiron::engine_executor::EngineExecutorStatus) -> Vec<String> {
    match status {
        oneiron::engine_executor::EngineExecutorStatus::Complete => {
            vec!["this durable run is complete; a new run_ref starts a new run".to_owned()]
        }
        oneiron::engine_executor::EngineExecutorStatus::Waiting(_) => vec![
            "this run is parked on a durable wait and persisted under run_id".to_owned(),
            "call execute_code again with the same run_ref to re-enter the persisted run"
                .to_owned(),
        ],
        oneiron::engine_executor::EngineExecutorStatus::Yielded { .. } => vec![
            "this run yielded at its soft step limit; the same run_ref continues it".to_owned(),
        ],
        oneiron::engine_executor::EngineExecutorStatus::HardStepLimitReached => {
            vec!["this run reached its hard step limit and will not continue".to_owned()]
        }
    }
}

fn mcp_durable_wait_value(wait: &oneiron::code_run::SelfDurableWait) -> Value {
    json!({
        "kind": "durable_wait",
        "wait_id": wait.wait_id.to_hex(),
        "effect": wait.effect.as_str(),
        "reason": mcp_durable_wait_reason(wait.reason),
        "prompt": wait.prompt,
    })
}

fn mcp_durable_wait_reason(reason: oneiron::code_run::SelfDurableWaitReason) -> &'static str {
    match reason {
        oneiron::code_run::SelfDurableWaitReason::HumanInput => "human_input",
        oneiron::code_run::SelfDurableWaitReason::DestructiveEffect => "destructive_effect",
        oneiron::code_run::SelfDurableWaitReason::OutboundEffect => "outbound_effect",
        oneiron::code_run::SelfDurableWaitReason::PeerResult => "peer_result",
    }
}

/// The executor status as typed wire data. `Waiting` stays `Waiting`.
fn mcp_executor_status_value(status: &oneiron::engine_executor::EngineExecutorStatus) -> Value {
    match status {
        oneiron::engine_executor::EngineExecutorStatus::Complete => {
            json!({ "status": "complete" })
        }
        oneiron::engine_executor::EngineExecutorStatus::Waiting(wait) => json!({
            "status": "waiting",
            "wait": mcp_durable_wait_value(wait),
        }),
        oneiron::engine_executor::EngineExecutorStatus::Yielded { next_step_seq } => json!({
            "status": "yielded",
            "next_step_seq": next_step_seq,
        }),
        oneiron::engine_executor::EngineExecutorStatus::HardStepLimitReached => {
            json!({ "status": "hard_step_limit_reached" })
        }
    }
}

/// One recorded bridge-call outcome as JSON, entry for entry.
///
/// `CodeRunBridgeCall.outcome` is the MessagePack value the engine's replay
/// record stores, so it cannot enter `json!` directly. Every arm states the
/// value it was handed: no entry is dropped, replaced by a placeholder, or
/// rendered as debug text. `Binary` is the recorder's entity-id form — it
/// stores `EntityId::as_bytes` — so it becomes the same lowercase hex
/// `EntityId::to_hex` puts on this wire everywhere else, which is what keeps a
/// step's `wait_id` equal to the `wait_id` under `result.wait`.
fn mcp_bridge_outcome_value(outcome: &rmpv::Value) -> Value {
    match outcome {
        rmpv::Value::Nil => Value::Null,
        rmpv::Value::Boolean(flag) => Value::Bool(*flag),
        rmpv::Value::Integer(number) => number
            .as_i64()
            .map(Value::from)
            .or_else(|| number.as_u64().map(Value::from))
            .unwrap_or(Value::Null),
        rmpv::Value::F32(number) => Value::from(f64::from(*number)),
        rmpv::Value::F64(number) => Value::from(*number),
        // A non-UTF-8 MessagePack string is bytes, so it is stated as hex like
        // any other byte string instead of collapsing to null.
        rmpv::Value::String(text) => text.as_str().map_or_else(
            || Value::String(super::hex_bytes(text.as_bytes())),
            |text| Value::String(text.to_owned()),
        ),
        rmpv::Value::Binary(bytes) => Value::String(super::hex_bytes(bytes)),
        rmpv::Value::Array(values) => {
            Value::Array(values.iter().map(mcp_bridge_outcome_value).collect())
        }
        rmpv::Value::Map(entries) => Value::Object(
            entries
                .iter()
                .map(|(key, value)| {
                    // The recorder writes string keys only; anything else keeps
                    // its JSON text so no entry can be erased.
                    let key = match mcp_bridge_outcome_value(key) {
                        Value::String(key) => key,
                        key => key.to_string(),
                    };
                    (key, mcp_bridge_outcome_value(value))
                })
                .collect(),
        ),
        // The recorder emits no ext values; the tag is kept beside its bytes so
        // this arm cannot silently drop one either.
        rmpv::Value::Ext(tag, bytes) => Value::Array(vec![
            Value::from(*tag),
            Value::String(super::hex_bytes(bytes)),
        ]),
    }
}

/// The live board one board verb reads, assembled from the same sections the
/// primary keyframe renders. The engine's `dispatch_board_verb` owns every
/// board semantic; this only supplies the current view.
struct McpLiveBoard {
    /// The world this view was BUILT for, taken from the registered credential
    /// scope. `read_current` refuses any other, so the scope argument is
    /// enforced rather than ignored.
    world: oneiron::EntityId,
    view: oneiron::board_verb::LiveBoardView,
}

impl oneiron::board_verb::LiveBoardSource for McpLiveBoard {
    fn read_current(
        &self,
        scope: &oneiron::board_verb::BoardWorldScope,
    ) -> Result<oneiron::board_verb::LiveBoardView, oneiron::board_verb::BoardVerbError> {
        if scope.world() != self.world {
            return Err(oneiron::board_verb::BoardVerbError::Source(format!(
                "board world scope {requested} is not the scope this view was built for",
                requested = scope.world().to_hex(),
            )));
        }
        Ok(self.view.clone())
    }
}

/// The world one connector's board is read under.
///
/// Taken from the REGISTERED scope; a vault-wide credential reads its own
/// actor's board. Nothing a caller sends reaches this.
fn mcp_board_world(actor: &McpResolvedActor) -> oneiron::EntityId {
    actor.scope.world_ref.unwrap_or(actor.actor_ref)
}

fn mcp_live_board(
    actor: &McpResolvedActor,
    board: &McpBoardState,
) -> Result<McpLiveBoard, McpGatewayError> {
    let header = oneiron::context_board::BoardBlockHeader {
        epoch: board.epoch,
        scope: board.scope_label.clone(),
    };
    let render = oneiron::board_verb::render_current_keyframe(
        &header,
        &board.sections,
        oneiron::context_board::BoardBudgetRequest {
            harness_default_tok: crate::mcp::MCP_BOARD_BUDGET_TOK,
            caller_limit_tok: None,
            explicit_override_tok: None,
        },
    )
    .map_err(mcp_board_frame_error)?;

    let mut rows = std::collections::BTreeMap::new();
    let mut expansions = std::collections::BTreeMap::new();
    for section in &board.sections {
        let lines = section
            .pinned_rows()
            .iter()
            .chain(section.detail_rows())
            .cloned()
            .collect::<Vec<_>>();
        for (index, line) in lines.iter().enumerate() {
            rows.insert(format!("{}:{index}", section.name()), line.clone());
        }
        expansions.insert(section.name().to_owned(), lines);
    }
    Ok(McpLiveBoard {
        world: mcp_board_world(actor),
        view: oneiron::board_verb::LiveBoardView {
            snapshot: oneiron::context_board::BoardSnapshot {
                epoch: board.epoch,
                keyframe: render.text,
                rows,
            },
            expansions,
        },
    })
}

fn mcp_board_verb_call(
    args: &crate::mcp::McpVerbToolArgs,
) -> Result<oneiron::board_verb::BoardVerbCall, McpGatewayError> {
    let arguments = &args.payload.arguments;
    let scopes = || {
        arguments
            .scopes
            .iter()
            .flatten()
            .map(|scope| scope.engine())
            .collect::<std::collections::BTreeSet<_>>()
    };
    match args.tool.binding {
        crate::mcp::McpVerbBinding::BoardExpand => Ok(oneiron::board_verb::BoardVerbCall::Expand {
            key: arguments.key.clone().unwrap_or_default(),
            frame_epoch: arguments.frame_epoch,
        }),
        crate::mcp::McpVerbBinding::BoardRefresh => {
            Ok(oneiron::board_verb::BoardVerbCall::Refresh {
                frame_epoch: arguments.frame_epoch,
            })
        }
        crate::mcp::McpVerbBinding::BoardSubscribe => {
            Ok(oneiron::board_verb::BoardVerbCall::Subscribe { scopes: scopes() })
        }
        crate::mcp::McpVerbBinding::BoardUnsubscribe => {
            Ok(oneiron::board_verb::BoardVerbCall::Unsubscribe { scopes: scopes() })
        }
        _ => Err(mcp_verb_family_error(args)),
    }
}

pub(super) fn mcp_verb_family_error(args: &crate::mcp::McpVerbToolArgs) -> McpGatewayError {
    McpGatewayError::new(
        -32603,
        "verb_dispatch_failed",
        format!(
            "{name} is not dispatched by the {family} verb executor",
            name = args.tool.name,
            family = args.tool.family.as_str(),
        ),
    )
}

fn mcp_board_verb_output_value(output: &oneiron::board_verb::BoardVerbOutput) -> Value {
    match output {
        oneiron::board_verb::BoardVerbOutput::Expanded { key, lines } => json!({
            "kind": "expanded",
            "key": key,
            "lines": lines,
        }),
        oneiron::board_verb::BoardVerbOutput::Frame(frame) => json!({
            "kind": "frame",
            "frame": frame,
        }),
        oneiron::board_verb::BoardVerbOutput::Subscription(receipt) => json!({
            "kind": "subscription",
            "connection": receipt.connection,
            "active": receipt.active,
        }),
    }
}

/// `board.*`: dispatched by the engine's own verb dispatcher, over this
/// connector's process-local STREAM state and the STATE-fenced board snapshot.
pub(super) async fn execute_mcp_board_verb(
    server: &Arc<SyncServer>,
    args: &crate::mcp::McpVerbToolArgs,
    actor: &McpCallContext,
) -> Result<(Value, crate::mcp::McpPageSource, McpCarrierPolicy, u64), McpGatewayError> {
    let board = mcp_current_board(server, actor).await?;
    let omissions = board.omissions();
    let source = mcp_live_board(actor, &board)?;
    let scope = oneiron::board_verb::BoardWorldScope::single(mcp_board_world(actor));
    let call = mcp_board_verb_call(args)?;
    let mints_keyframe = matches!(args.tool.binding, crate::mcp::McpVerbBinding::BoardRefresh);

    let output = {
        let mut registry = server.mcp_registry.lock().await;
        let mut context = oneiron::board_verb::BoardVerbContext {
            connection: &actor.stream_connection,
            scope: &scope,
            source: &source,
            streams: registry.streams_mut(),
            budget: oneiron::context_board::BoardBudgetRequest {
                harness_default_tok: crate::mcp::MCP_BOARD_BUDGET_TOK,
                caller_limit_tok: None,
                explicit_override_tok: None,
            },
        };
        oneiron::board_verb::dispatch_board_verb(&mut context, call)
    }
    .map_err(mcp_board_verb_error)?;

    let value = mcp_board_verb_output_value(&output);
    let page_source = mcp_board_verb_page_source(args.tool.binding, &value, omissions);
    // A verb that just minted a fresh keyframe returns it as the RESULT; the
    // central chokepoint supersedes and drains the queue behind it, so it is
    // never also attached as a carrier beside itself and nothing is stranded.
    let carrier = if mints_keyframe {
        McpCarrierPolicy::FreshKeyframe(None)
    } else {
        McpCarrierPolicy::Drain
    };
    Ok((value, page_source, carrier, board.epoch))
}

/// What this board verb actually produced, what the REQUESTED SCOPE removed,
/// and what the board's own render window truncated.
///
/// ONE-1704 repair: the two are reported on separate axes, and only the section
/// the omissions are OF carries them. A `board.expand` of `VERBS` is not partial
/// because a TASKS row was outside the credential's ceiling, and rows the render
/// row cap dropped are a window fact rather than a scope one.
pub(crate) fn mcp_board_verb_page_source(
    binding: crate::mcp::McpVerbBinding,
    output: &Value,
    omissions: McpBoardOmissions,
) -> crate::mcp::McpPageSource {
    match binding {
        crate::mcp::McpVerbBinding::BoardExpand => {
            let produced = output
                .get("lines")
                .and_then(Value::as_array)
                .map_or(0, Vec::len);
            if output.get("key").and_then(Value::as_str) == Some(MCP_BOARD_TASKS_SECTION) {
                crate::mcp::McpPageSource::scoped_window(
                    produced,
                    omissions.scope_omitted,
                    omissions.window_truncated,
                    omissions.source_exhausted,
                )
            } else {
                crate::mcp::McpPageSource::complete(produced)
            }
        }
        // A refresh renders the WHOLE board, so both axes apply to it.
        crate::mcp::McpVerbBinding::BoardRefresh => crate::mcp::McpPageSource::scoped_window(
            1,
            omissions.scope_omitted,
            omissions.window_truncated,
            omissions.source_exhausted,
        ),
        // A subscription receipt is one row and states itself completely.
        _ => crate::mcp::McpPageSource::complete(1),
    }
}

/// The board section the TASKS producer's omissions belong to.
pub(crate) const MCP_BOARD_TASKS_SECTION: &str = "TASKS";
