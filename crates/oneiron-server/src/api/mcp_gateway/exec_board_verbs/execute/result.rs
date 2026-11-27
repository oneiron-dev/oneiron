//! The execute/resume result and its release against the run's recorded rows.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use oneiron::code_run::{CodeRunBridgeCall, CodeRunReplayRecord, SelfDurableWaitReason};
use oneiron::engine_executor::{EngineExecutorStatus, read_caller_run_output};
use oneiron::task_verb::sdk::{AgentVerb, RunVerb};

use super::*;

#[cfg(test)]
mod legacy_task;
#[cfg(test)]
pub(super) use legacy_task::render_task_for_test;

const INLINE_CALLS: usize = 50;
const NO_RETURN: &str = "(the code returned nothing; `return` a value to see it)";

pub(super) async fn render(
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
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(McpCodeExecutionError::RunRefReused) => {
            return refusal(
                server,
                actor,
                run_ref,
                mcp_code_execution_error(&McpCodeExecutionError::RunRefReused),
            )
            .await;
        }
        Err(error) => {
            super::actor_dispatch::mcp_execute_code_gate(server, actor)?;
            let record = server.vault.get_code_run_replay_record(&run_id);
            let rows = match &record {
                Ok(Some(record)) => record.agent_verb_rows(),
                Ok(None) => Some(Vec::new()),
                Err(_) => None,
            }
            .map(|mut rows| {
                rows.extend(verbs.served());
                rows
            });
            let error = type_feedback_release::release_run_error(
                server,
                actor,
                rows.as_deref(),
                run_id,
                mcp_code_execution_error(&error),
            );
            let mut shape = error_shape(run_ref, &error);
            if error.kind == "code_run_failed"
                && let Ok(Some(record)) = &record
            {
                let calls = recorded_calls(server, actor, record);
                if let Some(call) = calls.iter().rev().find(|call| {
                    call["code"]
                        .as_str()
                        .is_some_and(|code| error.message.contains(code))
                }) {
                    shape["error"]["code"] = call["code"].clone();
                    shape["error"]["verb"] = call["verb"].clone();
                    if let Some(reasons) = call.get("reason_codes") {
                        shape["error"]["reason_codes"] = reasons.clone();
                        if let Some(grant) = reasons
                            .as_array()
                            .into_iter()
                            .flatten()
                            .find_map(|reason| reason.as_str()?.strip_prefix("grant_required."))
                        {
                            shape["error"]["message"] = json!(format!(
                                "this operation needs an owner credential or a Grant naming {grant}"
                            ));
                        }
                    }
                } else {
                    set_syntax_or_thrown(&mut shape, &error.message);
                }
                shape["calls"] = json!(compress_calls(&calls));
            } else if error.kind == "code_run_failed" {
                // No record (a syntax error before any bridge call): still name
                // SYNTAX/THROWN with its authored line.
                set_syntax_or_thrown(&mut shape, &error.message);
            }
            let mut feedback = serde_json::Map::new();
            if let Some(steps) = error.program_steps {
                type_feedback_release::stamp_error_feedback(*steps, &mut feedback);
            }
            let answer = endpoint_result(server, actor, shape, None, true).await?;
            let pre = answer.clone();
            let released = super::super::super::claimed_release::without_recording(|| {
                super::super::super::device_release::mcp_release_run_result(
                    server,
                    actor,
                    rows.as_deref(),
                    answer,
                )
            });
            match released {
                Ok(mut reply) => {
                    if let Some(meta) = reply["_meta"].as_object_mut() {
                        meta.extend(feedback);
                    }
                    wire_shape(&mut reply);
                    super::super::super::claimed_release::record(&reply, rows.as_deref());
                    return Ok(reply);
                }
                Err(error) => {
                    let mut base = pre;
                    wire_shape(&mut base);
                    super::super::super::claimed_release::record(&base, rows.as_deref());
                    return Err(error);
                }
            }
        }
    };

    let record = &outcome.replay_record;
    let complete = matches!(outcome.status, EngineExecutorStatus::Complete);
    let output = read_caller_run_output(&server.vault, record, complete)
        .map_err(|error| mcp_engine_error("execute could not read the stored result", error))?;
    let calls = recorded_calls(server, actor, record);
    let mut structured = json!({
        "status": if complete { "complete" } else { "paused" },
        "run_ref": run_ref,
        "result": output.result,
        "calls": compress_calls(&calls),
        "tree_reads": 0,
        "console": output.console,
    });
    if let Some(wait) = waiting_on(server, &outcome.status)? {
        structured["waiting_on"] = wait;
    }
    // Keep the unprojected step list for the existing producer and feedback
    // checks. It is not part of the execute/resume wire result.
    structured["steps"] = json!(recorded_steps(record));
    if output.result.as_ref().is_some_and(Value::is_null) {
        structured["_returned_null"] = Value::Bool(true);
    }
    let held =
        type_feedback_release::hold_run_feedback(&mut structured, record, outcome.program_steps);
    let named =
        super::super::super::device_release::mcp_run_named_rows(server, actor, &structured, record)
            .zip(record.agent_verb_rows())
            .map(|(mut named, recorded)| {
                named.extend(recorded);
                named.extend(verbs.served());
                named
            });
    let answer = endpoint_result(
        server,
        actor,
        structured,
        output.truncated_ref.as_deref(),
        false,
    )
    .await?;
    #[cfg(test)]
    super::super::super::device_release::release_hook::run(server);
    // The release scans a copy whose hydrate steps' miss echoes are cleared
    // (#10571), so an off-device miss of a device-local row reads as a miss
    // of a never-used id. The release runs unrecorded (P1-2): the only kept
    // value is the wire shape recorded below, never the full answer with its
    // internal steps. Waiters must never receive those steps, even when this
    // destination withheld the result but theirs admits it.
    let pre = answer.clone();
    let released = super::super::super::claimed_release::without_recording(|| {
        super::super::super::device_release::with_run_hydrate_scan(
            actor,
            record,
            answer,
            |answer| {
                type_feedback_release::release_run_answer(
                    server,
                    actor,
                    named.clone(),
                    held,
                    answer,
                )
            },
        )
    });
    match released {
        Ok(mut reply) => {
            wire_shape(&mut reply);
            super::super::super::claimed_release::record(&reply, named.as_deref());
            Ok(reply)
        }
        Err(error) => {
            // Withheld: the safe pre-release base in its wire shape, with its
            // rows, omitting separate feedback that was never admitted.
            let mut base = pre;
            wire_shape(&mut base);
            super::super::super::claimed_release::record(&base, named.as_deref());
            Err(error)
        }
    }
}

/// An answer in its wire shape: no internal `steps`, `_returned_null` or
/// `structuredContent.program_steps`; released program feedback in
/// `_meta.program_steps` (P1-2). Applied to the recorded copy and to the reply.
fn wire_shape(answer: &mut Value) {
    let moved = if let Some(fields) = answer["structuredContent"].as_object_mut() {
        fields.remove("steps");
        fields.remove("_returned_null");
        fields
            .remove("program_steps")
            .filter(|steps| steps.as_array().is_some_and(|steps| !steps.is_empty()))
    } else {
        None
    };
    if let Some(steps) = moved {
        answer["_meta"]["program_steps"] = steps;
    }
    type_feedback_release::sync_content(answer);
}

/// The authored line and column in `message`'s position suffix, when it carries
/// one: `"; at line {line}, column {column} of the TypeScript source"` or
/// `" of the JavaScript source"` at its end (P1-8).
fn authored_position(message: &str) -> Option<(u32, u32)> {
    let (_, position) = message.rsplit_once("; at line ")?;
    let position = position
        .strip_suffix(" of the TypeScript source")
        .or_else(|| position.strip_suffix(" of the JavaScript source"))?;
    let (line, column) = position.split_once(", column ")?;
    Some((line.parse().ok()?, column.parse().ok()?))
}

/// A `SYNTAX` or `THROWN` refusal in `shape`, with its authored line (and
/// column for `SYNTAX`) when the message names one (P1-8).
fn set_syntax_or_thrown(shape: &mut Value, message: &str) {
    let syntax = message.contains("SyntaxError");
    shape["error"]["code"] = json!(if syntax { "SYNTAX" } else { "THROWN" });
    if let Some((line, column)) = authored_position(message) {
        shape["error"]["line"] = json!(line);
        if syntax {
            shape["error"]["column"] = json!(column);
        }
    }
}

pub(super) async fn refusal(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    error: McpGatewayError,
) -> Result<Value, McpGatewayError> {
    refusal_for_verb(server, actor, run_ref, error, Some(&[]), None).await
}

pub(super) async fn refusal_for_verb(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    run_ref: &str,
    error: McpGatewayError,
    rows: Option<&[oneiron::EntityId]>,
    verb: Option<&str>,
) -> Result<Value, McpGatewayError> {
    let error = super::super::super::device_release::mcp_release_error(server, actor, rows, error);
    let mut structured = error_shape(run_ref, &error);
    if let Some(verb) = verb {
        structured["error"]["verb"] = json!(verb);
    }
    endpoint_result(server, actor, structured, None, true).await
}

fn error_shape(run_ref: &str, error: &McpGatewayError) -> Value {
    let mut refusal = json!({"code": error.kind, "message": error.message});
    if !error.reason_codes.is_empty() {
        refusal["reason_codes"] = json!(error.reason_codes);
    }
    json!({
        "status": "error", "run_ref": run_ref, "result": null,
        "calls": [], "tree_reads": 0, "console": [], "error": refusal,
    })
}

async fn endpoint_result(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    structured: Value,
    truncated: Option<&str>,
    is_error: bool,
) -> Result<Value, McpGatewayError> {
    let text = render_text(&structured, truncated);
    let mut result =
        mcp_endpoint_result(server, actor, text, structured, McpCarrierPolicy::Drain).await;
    // A credential revoked while the caller waited sees only its gate refusal.
    super::actor_dispatch::mcp_execute_code_gate(server, actor)?;
    result["isError"] = Value::Bool(is_error);
    result["_meta"] = json!({"policy_ref": crate::mcp::MCP_CODE_RUN_CONSENT_POLICY_REF});
    if let Some(reference) = truncated {
        result["_meta"]["result_ref"] = json!(reference);
    }
    Ok(result)
}

fn render_text(structured: &Value, truncated: Option<&str>) -> String {
    let status = structured["status"].as_str().unwrap_or("error");
    let run_ref = structured["run_ref"]
        .as_str()
        .unwrap_or_default()
        .replace(['\r', '\n'], " ");
    let calls = structured["calls"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let count = |call: &Value| call["count"].as_u64();
    let grouped = calls.iter().any(|call| count(call).is_some());
    let total = if grouped {
        calls.iter().filter_map(count).sum()
    } else {
        calls.len() as u64
    };
    let entries = calls
        .iter()
        .map(|call| {
            let verb = call["verb"].as_str().unwrap_or_default();
            let outcome = call["outcome"].as_str().unwrap_or_default();
            let mut line = format!("{verb} {outcome}");
            if let Some(count) = count(call) {
                let _ = write!(line, " ×{count}");
            }
            if let Some(reference) = call["ref"].as_str() {
                let _ = write!(line, " {reference}");
            }
            if let Some(code) = call["code"].as_str() {
                let _ = write!(line, " {code}");
            }
            line
        })
        .collect::<Vec<_>>()
        .join("; ");
    let mut text = format!("{status} · {run_ref} · {total} verb calls");
    if !entries.is_empty() {
        let _ = write!(text, ": {entries}");
    }
    text.push_str("\nresult:\n");
    if let Some(error) = structured.get("error") {
        let code = error["code"].as_str().unwrap_or_default();
        let message = error["message"].as_str().unwrap_or_default();
        let _ = write!(text, "{code}: {message}");
    } else if let Some(wait) = structured.get("waiting_on") {
        text.push_str(wait["detail"].as_str().unwrap_or_default());
    } else {
        match &structured["result"] {
            Value::String(value) => text.push_str(value),
            Value::Null if structured.get("_returned_null").is_none() => text.push_str(NO_RETURN),
            value => text.push_str(&value.to_string()),
        }
    }
    if let Some(reference) = truncated {
        // The call names this run and this result as JSON string literals, so
        // the caller can paste it into its code as written.
        let _ = write!(
            text,
            "\nreturn less (map or filter in the code); the whole value, 20,000 bytes at a time: await vault.runs.read_result({{ run_ref: {run_ref}, result_ref: {reference}, offset: 0 }})",
            run_ref = json!(structured["run_ref"].as_str().unwrap_or_default()),
            reference = json!(reference),
        );
    }
    text
}

fn waiting_on(
    server: &SyncServer,
    status: &EngineExecutorStatus,
) -> Result<Option<Value>, McpGatewayError> {
    Ok(Some(match status {
        EngineExecutorStatus::Complete => return Ok(None),
        EngineExecutorStatus::Waiting(wait) => {
            let ask = super::resume::pending_ask(server, wait)?;
            let kind = if ask.is_some() || wait.reason == SelfDurableWaitReason::HumanInput {
                "answer"
            } else if matches!(
                wait.reason,
                SelfDurableWaitReason::DestructiveEffect | SelfDurableWaitReason::OutboundEffect
            ) {
                "approval"
            } else {
                "time"
            };
            let mut value = json!({
                "kind": kind,
                "verb": wait.effect.as_str(),
                "detail": wait.prompt.as_deref().unwrap_or("the run is waiting; call resume with the same run_ref"),
            });
            if let Some((_, Some(cutoff))) = ask {
                value["expires_at"] = json!(cutoff);
            }
            value
        }
        EngineExecutorStatus::Yielded { .. } => {
            json!({"kind": "time", "detail": "the run reached its time slice; call resume"})
        }
        EngineExecutorStatus::WindowFull { .. } => {
            json!({"kind": "time", "detail": "the run's context is full; resume after compaction"})
        }
        EngineExecutorStatus::Paused { .. } => {
            json!({"kind": "time", "detail": "the branch is paused; resume once its pause is cleared"})
        }
    }))
}

fn recorded_calls(
    server: &SyncServer,
    actor: &McpCallContext,
    record: &CodeRunReplayRecord,
) -> Vec<Value> {
    let read = super::super::super::tasks_response::mcp_scoped_read(&server.vault, actor).ok();
    record
        .bridge_calls
        .iter()
        .map(|call| {
            let verb = recorded_verb_name(call);
            let outcome = mcp_step_outcome_value(call);
            let output = outcome["output"]
                .as_str()
                .and_then(|body| serde_json::from_str::<Value>(body).ok());
            let body = output.as_ref().unwrap_or(&outcome);
            let code = match outcome["kind"].as_str() {
                Some("denied") => outcome["outcome"].as_str(),
                Some("failed") => Some(outcome["code"].as_str().unwrap_or("code_run_failed")),
                _ => body["denied"].as_str(),
            };
            let writes = AgentVerb::from_name(verb).is_some_and(AgentVerb::writes)
                || RunVerb::from_name(verb).is_some_and(RunVerb::writes);
            let parked = outcome["kind"].as_str() == Some("durable_wait");
            let held = writes
                && (matches!(
                    body["approval"]
                        .as_str()
                        .or_else(|| body["status"].as_str()),
                    Some("proposed" | "held" | "pending" | "stored_awaiting_approval")
                ) || outcome["kind"].as_str() == Some("task_ask")
                    && !outcome["hold"].is_null()
                    || parked && body["reason"].as_str() == Some("outbound_effect"));
            let kind = if code.is_some() {
                "refused"
            } else if held {
                "held"
            } else if writes && !parked {
                "landed"
            } else {
                "read"
            };
            let mut value = json!({"verb": verb, "outcome": kind});
            if let Some(code) = code {
                value["code"] = json!(code);
            }
            if matches!(kind, "landed" | "held") {
                if let Some(reference) = [
                    "claim_short_id",
                    "short_id",
                    "ref",
                    "id",
                    "group",
                    "task_ref",
                    "proposal_ref",
                ]
                .into_iter()
                .find_map(|key| body[key].as_str())
                {
                    value["ref"] = json!(reference);
                }
                if let Some(prior) = body["superseded_short_id"].as_str() {
                    value["superseded_short_id"] = json!(prior);
                }
            }
            let reasons = [
                &outcome["row_reason_codes"],
                &outcome["reason_codes"],
                &body["reason_codes"],
                &body["reasonCodes"],
            ]
            .into_iter()
            .find(|codes| codes.as_array().is_some_and(|codes| !codes.is_empty()));
            if let Some(reasons) = reasons {
                value["reason_codes"] = reasons.clone();
            } else if held
                && let (Some(read), Some(receipt)) = (&read, body["receipt_ref"].as_str())
                && let Ok(Some(explanation)) = server.vault.explain_gate_receipt(read, receipt)
                && !explanation.reason_codes.is_empty()
            {
                value["reason_codes"] = json!(explanation.reason_codes);
            }
            value
        })
        .collect()
}

fn recorded_verb_name(call: &CodeRunBridgeCall) -> &str {
    use oneiron::code_run::SelfEffect;
    if let Some(verb) = call.request.as_map().and_then(|fields| {
        fields.iter().find_map(|(key, value)| {
            (key.as_str() == Some("verb"))
                .then(|| value.as_str())
                .flatten()
        })
    }) {
        return verb;
    }
    match call.effect {
        SelfEffect::TasksAsk => AgentVerb::Ask.as_str(),
        SelfEffect::TasksWait => AgentVerb::Wait.as_str(),
        effect => effect.as_str(),
    }
}

fn compress_calls(calls: &[Value]) -> Vec<Value> {
    if calls.len() <= INLINE_CALLS {
        return calls.to_vec();
    }
    let mut counts = BTreeMap::new();
    for call in calls {
        if let (Some(verb), Some(outcome)) = (call["verb"].as_str(), call["outcome"].as_str()) {
            *counts.entry((verb, outcome)).or_insert(0u64) += 1;
        }
    }
    counts
        .into_iter()
        .map(|((verb, outcome), count)| json!({"verb": verb, "outcome": outcome, "count": count}))
        .chain(
            calls
                .iter()
                .filter(|call| matches!(call["outcome"].as_str(), Some("held" | "refused")))
                .cloned(),
        )
        .collect()
}

fn recorded_steps(record: &CodeRunReplayRecord) -> Vec<Value> {
    record
        .bridge_calls
        .iter()
        .map(|call| {
            json!({
                "seq": call.seq,
                "effect": call.effect.as_str(),
                "outcome": mcp_step_outcome_value(call),
            })
        })
        .collect()
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
            || Value::String(hex_bytes(text.as_bytes())),
            |text| Value::String(text.to_owned()),
        ),
        rmpv::Value::Binary(bytes) => Value::String(hex_bytes(bytes)),
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
        rmpv::Value::Ext(tag, bytes) => {
            Value::Array(vec![Value::from(*tag), Value::String(hex_bytes(bytes))])
        }
    }
}
