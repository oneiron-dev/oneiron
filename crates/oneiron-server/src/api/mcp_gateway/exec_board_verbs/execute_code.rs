//! The execute-code executor: one durable REPL run entered under its
//! connector actor, and the answer that entry renders.

use super::super::code_run_resume::McpCodeRunEntry;
use super::*;

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

    let entry = McpCodeRunEntry::begin(server, crate::mcp::mcp_code_run_id(&args.run_ref, actor));
    let McpCodeRunEntered {
        run_id,
        verbs,
        outcome,
    } = enter_mcp_code_run(server, actor, &args.run_ref, &args.task, entry).await?;
    // Revocation takes effect at once: a credential that died while its run
    // ran gets its own refusal, never the run's results or failure. The run's
    // durable record stays for a re-entry its credential admits. A failure is
    // released as a result is, by the rows the run served before it failed,
    // with the feedback its steps kept on its own release (FIX 10389).
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
            return Err(type_feedback_release::release_run_error(
                server,
                actor,
                rows.as_deref(),
                run_id,
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
    let record = &outcome.replay_record;
    // Each program step's type feedback (FIX 8277), and the feedback its
    // bridge steps carry, leave after the answer on their own release (FIX
    // 10390), never paged with the bridge steps.
    let held =
        type_feedback_release::hold_run_feedback(&mut structured, record, outcome.program_steps);
    let named = super::device_release::mcp_run_named_rows(server, actor, &structured, record)
        .zip(record.agent_verb_rows())
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
    type_feedback_release::release_run_answer(server, actor, named, held, result)
}

/// One entry of a durable run: its id, the verb door it ran behind and
/// what the host answered.
pub(in crate::api::mcp_gateway) struct McpCodeRunEntered {
    pub(in crate::api::mcp_gateway) run_id: oneiron::EntityId,
    pub(in crate::api::mcp_gateway) verbs: Arc<super::code_mode_verbs::McpCodeModeVerbs>,
    pub(in crate::api::mcp_gateway) outcome:
        Result<oneiron::engine_executor::EngineExecutorOutcome, crate::mcp::McpCodeExecutionError>,
}

/// The admitted entry of the durable run `entry` holds, which `run_ref`
/// names under `actor`: the host's single flight, run admission, model seat
/// and spend line, as every entry of the run takes them. This is the
/// caller's own call, which renders its answer. The outcome settles
/// `entry`: a run parked on a wait registers it, and any other end removes
/// the registration.
pub(in crate::api::mcp_gateway) async fn enter_mcp_code_run(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    task: &str,
    entry: McpCodeRunEntry,
) -> Result<McpCodeRunEntered, McpGatewayError> {
    let host = server
        .code_execution_host()
        .ok_or_else(|| mcp_code_execution_error(&crate::mcp::McpCodeExecutionError::HostUnbound))?;
    let run_id = entry.run_id();
    let verbs = Arc::new(super::code_mode_verbs::McpCodeModeVerbs::new(
        server, actor, run_id,
    ));
    let outcome = host
        .execute(mcp_code_run_request(
            server, actor, run_ref, task, run_id, &verbs,
        ))
        .await;
    Ok(mcp_code_run_ended(
        server, actor, run_ref, task, entry, verbs, outcome,
    ))
}

/// The automatic re-entry of a parked run whose reply was delivered (FIX
/// 4606), through the same admitted entry as the caller's own call. It
/// renders no answer. `condition` is the wait and the generation the
/// re-entry was readied for, and the host checks it under the run's single
/// flight. `None`: the run had left them, as when a caller's own call took
/// it first, so no batch ran and the entry ends as one that started
/// nothing. Any other outcome settles `entry` as a caller's call does.
pub(in crate::api::mcp_gateway) async fn resume_mcp_code_run(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    task: &str,
    entry: McpCodeRunEntry,
    condition: crate::mcp::McpCodeRunResumeCondition,
) -> Result<Option<McpCodeRunEntered>, McpGatewayError> {
    let host = server
        .code_execution_host()
        .ok_or_else(|| mcp_code_execution_error(&crate::mcp::McpCodeExecutionError::HostUnbound))?;
    let run_id = entry.run_id();
    let verbs = Arc::new(super::code_mode_verbs::McpCodeModeVerbs::new(
        server, actor, run_id,
    ));
    let request = mcp_code_run_request(server, actor, run_ref, task, run_id, &verbs);
    let outcome = match host.execute_resumed(request, condition).await {
        Ok(crate::mcp::McpCodeRunResumed::Superseded) => {
            entry.supersede();
            return Ok(None);
        }
        Ok(crate::mcp::McpCodeRunResumed::Entered(outcome)) => Ok(*outcome),
        Err(error) => Err(error),
    };
    Ok(Some(mcp_code_run_ended(
        server, actor, run_ref, task, entry, verbs, outcome,
    )))
}

/// The host request for one entry of `run_id`, the run `run_ref` names
/// under `actor`, behind the verb door `verbs`, with the run's self brief
/// when `actor`'s connection has one.
fn mcp_code_run_request<'a>(
    server: &Arc<SyncServer>,
    actor: &'a McpCallContext,
    run_ref: &'a str,
    task: &'a str,
    run_id: oneiron::EntityId,
    verbs: &Arc<super::code_mode_verbs::McpCodeModeVerbs>,
) -> crate::mcp::McpCodeExecutionRequest<'a> {
    // FIX 17594 D5: the durable run's self brief, keyed by its trusted run
    // id, for a connection that has one; the host installs it under the
    // run's single flight and closes it when the run completes. A parked
    // run's automatic re-entry (FIX 4606) takes it the same way.
    let brief = crate::api::connection_has_brief(actor).then(|| {
        Arc::new(super::code_mode_self_brief::CodeModeSelfBrief::new(
            server, actor, run_id,
        )) as Arc<dyn crate::mcp::McpCodeRunSelfBrief>
    });
    crate::mcp::McpCodeExecutionRequest {
        vault: Arc::clone(&server.vault),
        actor,
        off_record_session: actor.off_record_session.clone(),
        run_ref,
        task,
        run_id,
        verbs: Arc::clone(verbs) as Arc<dyn oneiron::code_run::AgentVerbDoor>,
        brief,
    }
}

/// Ends one entry of `entry`'s run with what its host answered. A run that
/// ended ends its desktop and closes the live lens cards it created, named
/// by its run id's hex (OF-181, FIX 2612); any other entry leaves them
/// parked for the run's next entry (CUA-001). The outcome then settles
/// `entry`.
fn mcp_code_run_ended(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    task: &str,
    entry: McpCodeRunEntry,
    verbs: Arc<super::code_mode_verbs::McpCodeModeVerbs>,
    outcome: Result<
        oneiron::engine_executor::EngineExecutorOutcome,
        crate::mcp::McpCodeExecutionError,
    >,
) -> McpCodeRunEntered {
    let run_id = entry.run_id();
    if outcome.as_ref().is_ok_and(|outcome| {
        matches!(
            outcome.status,
            oneiron::engine_executor::EngineExecutorStatus::Complete
        )
    }) {
        server.desktop_seats.end_run(run_id);
        server.browser_seats.end_run(run_id);
        server.lens_frames.close_run(&run_id.to_hex());
        if let Err(error) = server.vault.seal_code_run_scratchpads(run_id) {
            tracing::warn!(%error, run_id = %run_id.to_hex(), "code-run scratchpad seal failed");
        }
    }
    entry.settle(actor, run_ref, task, &outcome);
    McpCodeRunEntered {
        run_id,
        verbs,
        outcome,
    }
}

fn mcp_code_execution_error(error: &crate::mcp::McpCodeExecutionError) -> McpGatewayError {
    let code = match error {
        crate::mcp::McpCodeExecutionError::HostUnbound
        | crate::mcp::McpCodeExecutionError::RunWaitedOut => -32020,
        crate::mcp::McpCodeExecutionError::RunBinding(_)
        | crate::mcp::McpCodeExecutionError::Run(_)
        | crate::mcp::McpCodeExecutionError::ProviderUnavailable { .. } => -32603,
    };
    let retry_after = match error {
        crate::mcp::McpCodeExecutionError::ProviderUnavailable { retry_after } => {
            Some(*retry_after)
        }
        _ => None,
    };
    McpGatewayError {
        retry_after,
        ..McpGatewayError::new(code, error.error_code(), error.to_string())
    }
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
    // FIX 4465: who wrote the last self-written pass and what ran it, as the
    // host recorded it; unknown counters stay null, never zero.
    if let Some(execution) = &report.last_self_pass {
        value["self_writer"] = serde_json::to_value(execution).unwrap_or(Value::Null);
    }
    if let Some(why) = report.self_unavailable {
        value["self_unavailable"] = json!(why.as_str());
    }
    // FIX 4465 B: the durable receipt of each self-written summary the run
    // landed, as its rows keep it; the last pass above may not have landed.
    if !report.landed_self.is_empty() {
        value["self_landed"] = serde_json::to_value(&report.landed_self).unwrap_or(Value::Null);
    }
    value
}
