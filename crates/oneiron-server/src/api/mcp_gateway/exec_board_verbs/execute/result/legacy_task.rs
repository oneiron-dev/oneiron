//! The old task result projection used by the retained task-path tests.

use super::*;

const MCP_RUN_RESULT_CARDS: usize = 64;

pub(in crate::api::mcp_gateway::exec_board_verbs::execute) async fn render_task_for_test(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    entered: McpCodeRunEntered,
) -> Result<Value, McpGatewayError> {
    let McpCodeRunEntered {
        run_id,
        verbs,
        outcome,
    } = entered;
    // Revocation takes effect at once: a credential that died while its run
    // ran gets its own refusal, never the run's results or failure. The run's
    // durable record stays for a re-entry its credential admits. A failure is
    // released as a result is, by the rows the run served before it failed,
    // with the feedback its steps kept on its own release (FIX 10389).
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            actor_dispatch::mcp_execute_code_gate(server, actor)?;
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
                if matches!(error, McpCodeExecutionError::RunRefReused) {
                    mcp_code_execution_error(&McpCodeExecutionError::RunBinding(
                        "engine executor config changed for existing run".to_owned(),
                    ))
                } else {
                    mcp_code_execution_error(&error)
                },
            ));
        }
    };

    let steps = recorded_steps(&outcome.replay_record);
    // Each step's released caller notice, as its denial or answer kept it
    // (FIX 12517): content-free summaries beside the steps, never in them.
    let hook_notices = steps
        .iter()
        .filter_map(|step| step.pointer("/outcome/hook_notice").and_then(Value::as_str))
        .filter_map(|notice| serde_json::from_str::<Value>(notice).ok())
        .collect::<Vec<_>>();
    let terminal = matches!(
        outcome.status,
        oneiron::engine_executor::EngineExecutorStatus::Complete
    );
    // Non-continuable: the step log is a run's own, not a re-enumerable
    // producer set, so a non-terminal page here states
    // `continuation_unavailable` instead of minting a handle nothing consumes.
    let page = McpPageBudget::resolve(
        None,
        crate::mcp::McpPageSource::truncated(steps.len(), 0, terminal),
    );
    let steps = page.cap(steps);
    let mut structured = json!({
        "tool": "execute_code",
        "schema_version": crate::mcp::MCP_CODE_RUN_SCHEMA_VERSION,
        "run_ref": run_ref,
        // The persisted run handle: the durable replay record this run id
        // addresses is the resume door, and re-entering it is one call.
        "run_id": run_id.to_hex(),
        "resume": {
            "tool": "execute_code",
            "run_ref": run_ref,
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
            None,
        ),
    });
    if !hook_notices.is_empty() {
        structured["meta"]["hook_notices"] = json!(hook_notices);
    }
    // The run's named results, so a stored value or a stored answer can be
    // found and read with `read_result`. They are released below with the
    // rest of the answer, under its checks.
    let (results, results_count) = server
        .vault
        .code_run_result_cards(&outcome.replay_record, MCP_RUN_RESULT_CARDS)
        .map_err(|error| mcp_engine_error("execute_code result cards failed", error))?;
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
    let named = device_release::mcp_run_named_rows(server, actor, &structured, record)
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
    actor_dispatch::mcp_execute_code_gate(server, actor)?;
    device_release::release_hook::run(server);
    device_release::with_run_hydrate_scan(actor, record, result, |result| {
        type_feedback_release::release_run_answer(server, actor, named, held, result)
    })
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
        | oneiron::engine_executor::EngineExecutorStatus::WindowFull { .. }
        | oneiron::engine_executor::EngineExecutorStatus::Paused { .. } => {
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
        oneiron::engine_executor::EngineExecutorStatus::Paused { .. } => vec![
            "this run's branch was paused at a step boundary and holds no lease".to_owned(),
            "it goes on once its branch is resumed (vault.runs.resume)".to_owned(),
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
        oneiron::engine_executor::EngineExecutorStatus::Paused { next_step_seq } => json!({
            "status": "paused",
            "next_step_seq": next_step_seq,
        }),
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
