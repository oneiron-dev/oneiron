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

/// Named results an `execute_code` answer lists, newest first.
const MCP_RUN_RESULT_CARDS: usize = 64;

/// One durable REPL run under the authenticated connector actor. This door
/// becomes wire-reachable only after the host verifies its QuickJS component.
/// The engine owns all bridge calls, replay checkpoints and terminal markers.
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

    let host = server
        .code_execution_host()
        .ok_or_else(|| mcp_code_execution_error(&crate::mcp::McpCodeExecutionError::HostUnbound))?;
    let run_id = crate::mcp::mcp_code_run_id(&args.run_ref, actor);
    let verbs = Arc::new(super::code_mode_verbs::McpCodeModeVerbs::new(
        server, actor, run_id,
    ));
    let outcome = host
        .execute(crate::mcp::McpCodeExecutionRequest {
            vault: Arc::clone(&server.vault),
            actor,
            run_ref: &args.run_ref,
            task: &args.task,
            run_id,
            verbs: Arc::clone(&verbs) as Arc<dyn oneiron::code_run::AgentVerbDoor>,
        })
        .await;
    // Revocation takes effect at once: a credential that died while its run
    // ran gets its own refusal, never the run's results or failure. The run's
    // durable record stays for a re-entry its credential admits. A failure is
    // released as a result is, by the rows the run served before it failed.
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            super::actor_dispatch::mcp_execute_code_gate(server, actor)?;
            let rows = match server.vault.get_code_run_replay_record(&run_id) {
                Ok(Some(record)) => record.agent_verb_rows(),
                Ok(None) => Some(Vec::new()),
                Err(_) => None,
            }
            .map(|mut rows| {
                rows.extend(verbs.served());
                rows
            });
            return Err(super::device_release::mcp_release_error(
                server,
                actor,
                rows.as_deref(),
                mcp_code_execution_error(&error),
            ));
        }
    };

    let steps = outcome
        .replay_record
        .bridge_calls
        .iter()
        .map(|call| {
            json!({
                "seq": call.seq,
                "effect": call.effect.as_str(),
                "outcome": mcp_step_outcome_value(call),
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
    let mut structured = json!({
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
        "session_manifests": verbs.manifests(),
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
    // The run's named results, so a stored value or a stored answer can be
    // found and read with `read_result`. They are released below with the
    // rest of the answer, under its checks.
    let (results, results_count) = server
        .vault
        .code_run_result_cards(&outcome.replay_record, MCP_RUN_RESULT_CARDS)
        .map_err(|error| super::mcp_engine_error("execute_code result cards failed", error))?;
    structured["results"] = json!(results);
    structured["resultsCount"] = json!(results_count);
    if let Some(receipt) = &outcome.seat_receipt {
        structured["model_choice"] = json!(receipt);
    }
    if let Some(report) = &outcome.compaction {
        structured["compaction"] = mcp_compaction_value(report);
    }
    // Judged by the rows its verb answers listed, as its record keeps them
    // beside each answer, fresh or replayed, and as this call's verb calls
    // listed them, recorded or not.
    let named = super::device_release::mcp_run_named_rows(&server.vault, &structured)
        .zip(outcome.replay_record.agent_verb_rows())
        .map(|(mut named, recorded)| {
            named.extend(recorded);
            named.extend(verbs.served());
            named
        });
    let result = mcp_endpoint_result(
        server,
        actor,
        "execute_code run recorded",
        structured,
        McpCarrierPolicy::Drain,
    )
    .await;
    // Checked after the result's last wait, so no wait parks the run's
    // results past their credential's death.
    super::actor_dispatch::mcp_execute_code_gate(server, actor)?;
    #[cfg(test)]
    super::device_release::release_hook::run(server);
    super::device_release::mcp_release_run_result(server, actor, named.as_deref(), result)
}

/// One read of a result of the durable run `run_ref` names under this
/// credential: its card, or a slice, search, query or chunks page of it. No
/// model is called and no run is entered. The run id is the credential's own
/// derivation, never an id or digest a caller sends, and only that run's
/// results resolve. The read is checked against the rows the run's answers
/// were served from and the result's taint, as inside the run, and the
/// answer is released as `execute_code`'s is, under its live credential.
pub(crate) async fn execute_mcp_read_result(
    server: &Arc<SyncServer>,
    args: crate::mcp::McpReadResultToolArgs,
    actor: &McpCallContext,
) -> Result<Value, McpGatewayError> {
    let run_id = crate::mcp::mcp_code_run_id(&args.run_ref, actor);
    let facet = args.facet.and_then(crate::mcp::McpResultFacet::facet);
    let locality = actor.locality();
    let vault = Arc::clone(&server.vault);
    let reference = args.reference.clone();
    let input = Value::Object(args.input.clone().unwrap_or_default());
    // A search or a table query scans up to its bound from disk, so it runs
    // off the gateway's reactor.
    let (reply, served) = tokio::task::spawn_blocking(move || {
        let mut served = None;
        let reply = vault.read_code_run_result(run_id, &reference, facet, input, |rows| {
            served = Some(rows.map(<[oneiron::EntityId]>::to_vec));
            if locality == oneiron::claim::CallerLocality::OnDevice {
                return Ok(false);
            }
            rows.map_or(Ok(true), |rows| {
                crate::device_local::withholds_retained(&vault, locality, rows, &[])
            })
        });
        reply.map(|reply| (reply, served))
    })
    .await
    .map_err(|_| {
        McpGatewayError::new(
            -32603,
            "engine_error",
            "read_result worker ended without a result",
        )
    })?
    .map_err(|error| super::mcp_engine_error("read_result failed", error))?;
    let health = if reply.get("denied").is_some() {
        McpRetrievalHealth::Degraded
    } else if reply["output"]["done"] == json!(false) {
        McpRetrievalHealth::Partial
    } else {
        McpRetrievalHealth::Healthy
    };
    let help = vec![
        "pass a reply's next back as input.cursor (search, query, chunks) or as the selection (slice) to read on".to_owned(),
        "a chunk's ref is a range ref read_result takes as ref".to_owned(),
    ];
    let structured = json!({
        "tool": crate::mcp::MCP_READ_RESULT_TOOL,
        "schema_version": crate::mcp::MCP_CODE_RUN_SCHEMA_VERSION,
        "run_ref": args.run_ref,
        "run_id": run_id.to_hex(),
        "ref": args.reference,
        "facet": facet.map_or("describe", oneiron::code_run::ResultFacet::as_str),
        "result": reply,
        "actor": mcp_actor_result(actor),
        "meta": actor.metadata(
            health,
            McpPageBudget::resolve(None, crate::mcp::McpPageSource::complete(1)),
            help,
            None,
        ),
    });
    let result = mcp_endpoint_result(
        server,
        actor,
        "read_result answered",
        structured,
        McpCarrierPolicy::Drain,
    )
    .await;
    super::actor_dispatch::mcp_execute_code_gate(server, actor)?;
    // An unknown ref resolved nothing, so no rows were read.
    let rows = served.unwrap_or_else(|| Some(Vec::new()));
    super::device_release::mcp_release_run_result(server, actor, rows.as_deref(), result)
}

fn mcp_code_execution_error(error: &crate::mcp::McpCodeExecutionError) -> McpGatewayError {
    let code = match error {
        crate::mcp::McpCodeExecutionError::HostUnbound
        | crate::mcp::McpCodeExecutionError::RunBusy
        | crate::mcp::McpCodeExecutionError::RunWaitedOut => -32020,
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
        | oneiron::engine_executor::EngineExecutorStatus::Yielded { .. }
        | oneiron::engine_executor::EngineExecutorStatus::WindowFull { .. } => {
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
        oneiron::engine_executor::EngineExecutorStatus::WindowFull { .. } => vec![
            "this run's context window is full and no compacted summary has landed yet".to_owned(),
            "the same run_ref continues it once compaction lands".to_owned(),
        ],
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
        oneiron::engine_executor::EngineExecutorStatus::WindowFull {
            next_step_seq,
            reason,
        } => json!({
            "status": "window_full",
            "next_step_seq": next_step_seq,
            "reason": mcp_window_full_reason(*reason),
        }),
    }
}

/// One step's outcome as its caller reads it: the recorded outcome, less the
/// rows a verb's answer keeps for its release (DEC-0005), which are the host
/// door's, not the verb's output.
fn mcp_step_outcome_value(call: &oneiron::code_run::CodeRunBridgeCall) -> Value {
    let mut outcome = mcp_bridge_outcome_value(&call.outcome);
    if call.effect == oneiron::code_run::SelfEffect::AgentVerb
        && let Some(entries) = outcome.as_object_mut()
    {
        entries.remove("rows");
    }
    outcome
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
pub(super) struct McpLiveBoard {
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

/// A keyed `describe` and `self.focus.*`: dispatched by the engine's own verb
/// dispatcher, over this connector's process-local STREAM state and the
/// STATE-fenced board snapshot.
pub(super) async fn execute_mcp_board_verb(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    served: &mut Vec<oneiron::EntityId>,
    call: impl FnOnce(
        &mut oneiron::board_verb::BoardVerbContext<'_, McpLiveBoard>,
    ) -> Result<
        oneiron::board_verb::BoardVerbOutput,
        oneiron::board_verb::BoardVerbError,
    >,
) -> Result<
    (
        Value,
        crate::mcp::McpPageSource,
        McpCarrierPolicy,
        Option<u64>,
    ),
    McpGatewayError,
> {
    let board = mcp_current_board(server, actor).await?;
    served.extend_from_slice(&board.rows);
    let omissions = board.omissions();
    let source = mcp_live_board(actor, &board)?;
    let scope = oneiron::board_verb::BoardWorldScope::single(mcp_board_world(actor));
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
        call(&mut context)
    }
    .map_err(mcp_board_verb_error)?;

    let output = match output {
        oneiron::board_verb::BoardVerbOutput::Frame(frame) => {
            let frame = board
                .changes
                .ride(Some(frame))
                .expect("rider preserves an existing frame");
            let keyframe = matches!(frame.kind, oneiron::context_board::FrameKind::Keyframe(_));
            super::board_observations::delivered(
                server,
                actor,
                &board.changes,
                keyframe,
                frame.epoch,
            )
            .await;
            oneiron::board_verb::BoardVerbOutput::Frame(frame)
        }
        other => other,
    };
    // The present board producer serves TASKS, presence and loaded metadata.
    // None are new CLAIM/SKILL/AGENT_DEF body observations. An expansion has no
    // typed entity mapping, so its renderer strings are never parsed for ids.
    let value = mcp_board_verb_output_value(&output);
    let page_source = mcp_board_verb_page_source(&output, omissions);
    // A verb that just minted a fresh keyframe returns it as the RESULT; the
    // central chokepoint supersedes and drains the queue behind it, so it is
    // never also attached as a carrier beside itself and nothing is stranded.
    let carrier = if matches!(output, oneiron::board_verb::BoardVerbOutput::Frame(_)) {
        McpCarrierPolicy::FreshKeyframe(None)
    } else {
        McpCarrierPolicy::Drain
    };
    Ok((value, page_source, carrier, Some(board.epoch)))
}

/// What this board verb actually produced, what the REQUESTED SCOPE removed,
/// and what the board's own render window truncated.
///
/// ONE-1704 repair: the two are reported on separate axes, and only the section
/// the omissions are OF carries them. A `describe` of `VERBS` is not partial
/// because a TASKS row was outside the credential's ceiling, and rows the render
/// row cap dropped are a window fact rather than a scope one.
pub(crate) fn mcp_board_verb_page_source(
    output: &oneiron::board_verb::BoardVerbOutput,
    omissions: McpBoardOmissions,
) -> crate::mcp::McpPageSource {
    match output {
        oneiron::board_verb::BoardVerbOutput::Expanded { key, lines } => {
            let produced = lines.len();
            let source = if key == MCP_BOARD_TASKS_SECTION {
                crate::mcp::McpPageSource::scoped_window(
                    produced,
                    omissions.scope_omitted,
                    omissions.window_truncated,
                    omissions.source_exhausted,
                )
            } else {
                crate::mcp::McpPageSource::complete(produced)
            };
            source.rows_at("lines")
        }
        // A refresh renders the WHOLE board, so both axes apply to it.
        oneiron::board_verb::BoardVerbOutput::Frame(_) => crate::mcp::McpPageSource::scoped_window(
            1,
            omissions.scope_omitted,
            omissions.window_truncated,
            omissions.source_exhausted,
        ),
        // A subscription receipt is one row and states itself completely.
        oneiron::board_verb::BoardVerbOutput::Subscription(_) => {
            crate::mcp::McpPageSource::complete(1)
        }
    }
}

/// The board section the TASKS producer's omissions belong to.
pub(crate) const MCP_BOARD_TASKS_SECTION: &str = "TASKS";

/// Why a run parked at its window budget, as typed wire data.
fn mcp_window_full_reason(reason: oneiron::engine_executor::WindowFullReason) -> Value {
    match reason {
        oneiron::engine_executor::WindowFullReason::InFlight => json!({"kind": "in_flight"}),
        oneiron::engine_executor::WindowFullReason::NothingToCompact => {
            json!({"kind": "nothing_to_compact"})
        }
        oneiron::engine_executor::WindowFullReason::Suppressed(suppression) => {
            let mut value = mcp_suppression_value(suppression);
            value["kind"] = json!("suppressed");
            value
        }
    }
}

/// Why compaction did not run, typed: never a bare "did not run".
fn mcp_suppression_value(suppression: oneiron::compaction::CompactionSuppression) -> Value {
    use oneiron::compaction::CompactionSuppression;
    let mut value = json!({"suppression": suppression.as_str()});
    match suppression {
        CompactionSuppression::TurnScoped { check: Some(check) } => {
            value["check"] = json!(check.as_str());
        }
        CompactionSuppression::Sticky { why } => value["why"] = json!(why.as_str()),
        _ => {}
    }
    value
}

/// A run's compaction after this call (agent-runtime-v1 §d7): its window,
/// a pass in flight, the last swap, and why it did not run.
fn mcp_compaction_value(report: &oneiron::engine_executor::CompactionReport) -> Value {
    let mut value = json!({
        "used_tokens": report.used_tokens,
        "compact_at": report.compact_at,
        "window_tokens": report.window_tokens,
        "in_flight": report.in_flight,
    });
    if let Some((epoch, first, last)) = report.last_swap {
        value["last_swap"] = json!({"epoch": epoch, "first_step": first, "last_step": last});
    }
    if let Some(suppression) = report.suppressed {
        value["suppressed"] = mcp_suppression_value(suppression);
    }
    value
}

/// A pumped run's `self.focus.*` and keyed `describe` (OF-533): the engine's
/// own board dispatcher over the run's own board connection and its agent's
/// board, as [`execute_mcp_board_verb`] serves a connector's. Answers the
/// verb's wire value and every row the board was derived from. A refresh's
/// frame is the answer, so the queue behind it is superseded and drained.
pub(crate) async fn execute_run_board_verb(
    server: &Arc<SyncServer>,
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
    call: oneiron::board_verb::BoardVerbCall,
) -> Result<(Value, Vec<oneiron::EntityId>), oneiron::memory::MemoryError> {
    let board = super::board_setup::run_current_board(server, actor, connection)
        .await
        .map_err(run_board_error)?;
    let world = actor.entity_ref();
    let source = McpLiveBoard {
        world,
        view: live_board_view(&board).map_err(run_board_error)?,
    };
    let scope = oneiron::board_verb::BoardWorldScope::single(world);
    let output = {
        let mut registry = server.mcp_registry.lock().await;
        let mut context = oneiron::board_verb::BoardVerbContext {
            connection,
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
    .map_err(|error| run_board_error(mcp_board_verb_error(error)))?;
    let output = match output {
        oneiron::board_verb::BoardVerbOutput::Frame(frame) => {
            let frame = board
                .changes
                .ride(Some(frame))
                .expect("rider preserves an existing frame");
            let keyframe = matches!(frame.kind, oneiron::context_board::FrameKind::Keyframe(_));
            super::board_observations::run_delivered(
                server,
                actor,
                connection,
                &board.changes,
                keyframe,
                frame.epoch,
            )
            .await;
            let _superseded = server
                .mcp_registry
                .lock()
                .await
                .next_carrier_frame(connection);
            oneiron::board_verb::BoardVerbOutput::Frame(frame)
        }
        other => other,
    };
    Ok((mcp_board_verb_output_value(&output), board.rows))
}

/// Drops a pumped run's board connection, snapshot and read set.
pub(crate) async fn drop_run_board(
    server: &SyncServer,
    actor: oneiron::WriteActor,
    connection: &oneiron::context_board::StreamConnectionId,
) {
    server.mcp_registry.lock().await.drop_run_board(connection);
    server.memories_cursors.lock().await.read_sets.remove(
        &super::board_observations::run_read_set_key(actor, connection),
    );
}

/// [`mcp_live_board`]'s view of one rendered board.
fn live_board_view(
    board: &McpBoardState,
) -> Result<oneiron::board_verb::LiveBoardView, McpGatewayError> {
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
    Ok(oneiron::board_verb::LiveBoardView {
        snapshot: oneiron::context_board::BoardSnapshot {
            epoch: board.epoch,
            keyframe: render.text,
            rows,
        },
        expansions,
    })
}

/// A board refusal as the run's door states it: the verb's own refusal is
/// the caller's, anything else the host's.
fn run_board_error(error: McpGatewayError) -> oneiron::memory::MemoryError {
    if error.kind == "verb_dispatch_failed" {
        oneiron::memory::MemoryError::bad_request(error.message)
    } else {
        oneiron::memory::MemoryError::new(
            oneiron::memory::MEMORY_CODE_INTERNAL,
            error.message,
            &["Report this host-door failure."],
        )
    }
}
