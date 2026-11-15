//! The MCP Tasks extension of the 2026-07-28 revision (ARCH-0028 `#mcp-tasks`;
//! owner ruling ONEIRON-MCP-TASKS = AB; L1-03): an optional adapter over the
//! records the engine already keeps.
//!
//! A task is a transport handle, never a TASK entity and never a second
//! scheduler. A `tools/call` whose own request declares the extension, to a
//! verb that starts a record, answers a task over that record; the handle row
//! is stored before the answer leaves. Every `tasks/*` call runs the record's
//! own public verb as its caller, through the same admission, scope and
//! release a tool call meets, so each poll re-checks the caller with no copy
//! of those rules. A handle the caller may not see, one past its time to live,
//! and an unknown id all answer alike as missing. The record's end gives the
//! task's end: a failed run ends `completed` with `isError`, as a tool result
//! with `isError` does.
//!
//! Not built here: `subscriptions/listen` (change notices are optional, and
//! this endpoint answers one request per POST with no server stream), and the
//! form questions of `input_required` (L1-03 PR 3).
//! Not this module: `tasks_response.rs`, which serves the TASKS board section.

use std::sync::Arc;

use axum::http::{Extensions, HeaderMap};
use oneiron::mcp_task::{McpTaskId, McpTaskRecord, McpTaskSubject};
use serde_json::{Map, Value, json};

use super::{
    McpCallContext, McpGatewayError, McpToolCallParams, ensure_mcp_actor_matches, execute_mcp_tool,
    mcp_admit_scoped_call, mcp_validated_call_args,
};
use crate::server::SyncServer;

/// How often a client may poll a task: no faster than this (canon :263).
const MCP_TASK_POLL_INTERVAL_MS: u64 = 2000;

/// The one answer for an unknown id, another actor's handle and an expired
/// one, so no answer tells that a hidden task exists.
const MCP_TASK_MISSING: &str = "Failed to retrieve task: Task not found";

/// The consent a task method's inner verb call states: the caller's own
/// task method, never a new purpose.
const MCP_TASK_POLICY_REF: &str = "policy:mcp-task";

/// A record kind a task can wrap: the verb that starts it, and the record's
/// own read and cancel verbs.
struct TaskRecordVerbs {
    start: &'static str,
    read: &'static str,
    cancel: &'static str,
}

/// A saved-workflow run, by its root attempt.
const WORKFLOW_RUN: TaskRecordVerbs = TaskRecordVerbs {
    start: "vault.workflows.dispatch",
    read: "vault.workflows.status",
    cancel: "vault.workflows.cancel",
};

/// The `-32021` refusal of a `tasks/*` request that does not declare the
/// extension itself: an earlier request's declaration does not count.
pub(super) fn tasks_not_declared() -> McpGatewayError {
    McpGatewayError::missing_capabilities(
        "this method needs the request to declare the io.modelcontextprotocol/tasks extension \
         in its own _meta client capabilities",
        json!({
            "extensions": { (super::client_surface::MCP_TASKS_EXTENSION): {} },
        }),
    )
}

fn task_missing() -> McpGatewayError {
    McpGatewayError::new(-32602, "task_not_found", MCP_TASK_MISSING).with_field("taskId")
}

/// A declared `tools/call`'s answer: a task over the record `answered` names
/// when `tool` starts one and the call did not fail, else `answered` as it is.
/// The handle is stored before this returns.
pub(super) fn task_for_call(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    tool: &str,
    answered: Value,
) -> Result<Value, McpGatewayError> {
    if tool != WORKFLOW_RUN.start || answered.get("isError") == Some(&Value::Bool(true)) {
        return Ok(answered);
    }
    let output = verb_output(&answered);
    let Some(root) = output
        .and_then(|view| view.get("root_attempt_ref"))
        .and_then(Value::as_str)
        .and_then(|hex| oneiron::EntityId::from_hex(hex).ok())
    else {
        return Ok(answered);
    };
    let status = output.map_or(TaskStatus::Working, TaskStatus::of_run);
    let vault = server.vault();
    let now_ms = vault.now_recorded_ms();
    let ttl_ms = server.config.mcp_task_ttl_ms;
    let id = vault
        .mint_mcp_task(
            actor.actor_ref,
            McpTaskSubject::WorkflowRun {
                root_attempt_ref: root,
            },
            ttl_ms,
            now_ms,
        )
        .map_err(|error| McpGatewayError::new(-32603, "engine_error", error.to_string()))?;
    let row = McpTaskRecord {
        actor_ref: actor.actor_ref,
        subject: McpTaskSubject::WorkflowRun {
            root_attempt_ref: root,
        },
        created_at_ms: now_ms,
        ttl_ms,
        cancel_requested_at_ms: None,
        input_round: 0,
    };
    let mut reply = task_fields(&id, &row, status, output);
    reply.insert("resultType".to_owned(), json!("task"));
    reply.insert("_meta".to_owned(), private_meta(answered.get("_meta")));
    Ok(Value::Object(reply))
}

/// One `tasks/get`, `tasks/update` or `tasks/cancel` from the resolved caller
/// `actor`, whose request declared the extension.
pub(super) async fn tasks_method(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    headers: &HeaderMap,
    connection: &Extensions,
    method: &str,
    params: Option<Value>,
) -> Result<Value, McpGatewayError> {
    let id = params
        .as_ref()
        .and_then(|params| params.get("taskId"))
        .and_then(Value::as_str)
        .and_then(McpTaskId::from_hex)
        .ok_or_else(task_missing)?;
    let vault = server.vault();
    let now_ms = vault.now_recorded_ms();
    let engine =
        |error: oneiron::Error| McpGatewayError::new(-32603, "engine_error", error.to_string());
    match method {
        "tasks/cancel" => {
            let row = vault
                .request_mcp_task_cancel(actor.actor_ref, &id, now_ms)
                .map_err(engine)?
                .ok_or_else(task_missing)?;
            // The record's own cancel verb, as a tool call of the caller's:
            // judged, run, released and receipted. It asks the work to stop
            // and never undoes committed work.
            let McpTaskSubject::WorkflowRun { root_attempt_ref } = row.subject else {
                return Err(task_missing());
            };
            let params = verb_call(
                WORKFLOW_RUN.cancel,
                json!({ "root_attempt_ref": root_attempt_ref.to_hex() }),
            );
            super::envelope::call_tool_as(
                server,
                actor.mode,
                headers,
                connection,
                actor,
                Some(params),
                None,
                None,
            )
            .await
            .map_err(|_| task_missing())?;
            Ok(json!({ "resultType": "complete", "_meta": private_meta(None) }))
        }
        "tasks/update" => {
            // No subject asks for input yet (form questions: L1-03 PR 3), so
            // responses are ignored, as the spec ignores responses under a
            // key the task did not ask.
            vault
                .mcp_task(actor.actor_ref, &id, now_ms)
                .map_err(engine)?
                .ok_or_else(task_missing)?;
            Ok(json!({ "resultType": "complete", "_meta": private_meta(None) }))
        }
        _ => {
            let row = vault
                .mcp_task(actor.actor_ref, &id, now_ms)
                .map_err(engine)?
                .ok_or_else(task_missing)?;
            let McpTaskSubject::WorkflowRun { root_attempt_ref } = &row.subject else {
                return Err(task_missing());
            };
            // The record's own read verb, as the caller: a refusal answers
            // as missing, never in the verb's own words.
            let read = read_record(
                server,
                actor,
                headers,
                connection,
                WORKFLOW_RUN.read,
                json!({ "root_attempt_ref": root_attempt_ref.to_hex() }),
            )
            .await
            .map_err(|_| task_missing())?;
            let output = verb_output(&read);
            let status = output.map_or(TaskStatus::Working, TaskStatus::of_run);
            let mut reply = task_fields(&id, &row, status, output);
            reply.insert("resultType".to_owned(), json!("complete"));
            if matches!(
                status,
                TaskStatus::Completed | TaskStatus::CompletedWithError
            ) {
                let mut result = read;
                if status == TaskStatus::CompletedWithError
                    && let Some(object) = result.as_object_mut()
                {
                    object.insert("isError".to_owned(), Value::Bool(true));
                }
                reply.insert("result".to_owned(), result);
            }
            reply.insert("_meta".to_owned(), private_meta(None));
            Ok(Value::Object(reply))
        }
    }
}

/// Runs the record's read verb `verb` with `input` as the caller `actor`, on
/// the caller's own endpoint, through the tool call's admission and release.
/// A read: no call receipt is written for it, and it is not counted as a
/// wire tool call.
async fn read_record(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    headers: &HeaderMap,
    connection: &Extensions,
    verb: &str,
    input: Value,
) -> Result<Value, McpGatewayError> {
    let params: McpToolCallParams = serde_json::from_value(verb_call(verb, input))
        .map_err(|error| McpGatewayError::new(-32603, "engine_error", error.to_string()))?;
    let args = mcp_validated_call_args(server, actor.mode, params, None, actor)?;
    ensure_mcp_actor_matches(&args, actor)?;
    mcp_admit_scoped_call(server, &args, actor)?;
    Box::pin(execute_mcp_tool(server, args, actor, headers, connection)).await
}

/// The `tools/call` params of the generated verb `verb` over `input`.
fn verb_call(verb: &str, input: Value) -> Value {
    json!({
        "name": verb,
        "arguments": {
            "schema_version": crate::mcp::MCP_TOOL_ARGS_SCHEMA_VERSION,
            "consent": {
                "policy_ref": MCP_TASK_POLICY_REF,
                "purpose": "the record an MCP task wraps, under the caller's own task method",
            },
            "arguments": { "spec": input },
        },
    })
}

/// A generated verb's typed output inside its tool result.
fn verb_output(answered: &Value) -> Option<&Value> {
    answered
        .get("structuredContent")
        .and_then(|content| content.get("output"))
        .and_then(|output| output.get("value"))
}

/// A task's status, from its record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TaskStatus {
    Working,
    Completed,
    /// The record ended in failure: the task ends `completed`, its result
    /// marked `isError` (canon: a tool result with `isError` still ends
    /// `completed`; `failed` is the JSON-RPC error's).
    CompletedWithError,
    Cancelled,
}

impl TaskStatus {
    /// From a `vault.workflows.status` view's `state`.
    fn of_run(view: &Value) -> Self {
        match view.get("state").and_then(Value::as_str) {
            Some("completed") => Self::Completed,
            Some("failed") => Self::CompletedWithError,
            Some("cancelled") => Self::Cancelled,
            _ => Self::Working,
        }
    }

    fn wire(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Completed | Self::CompletedWithError => "completed",
            Self::Cancelled => "cancelled",
        }
    }
}

/// The fields every task answer carries: its id, status, a status line that
/// names only the step ordinal and count, its times, retention and poll
/// interval. `ttlMs` is the handle's retention and keeps its own value.
fn task_fields(
    id: &McpTaskId,
    row: &McpTaskRecord,
    status: TaskStatus,
    output: Option<&Value>,
) -> Map<String, Value> {
    let updated_ms = row.cancel_requested_at_ms.unwrap_or(row.created_at_ms);
    let mut fields = Map::new();
    fields.insert("taskId".to_owned(), json!(id.to_hex()));
    fields.insert("status".to_owned(), json!(status.wire()));
    if let Some(message) = output.and_then(|view| step_message(view, status)) {
        fields.insert("statusMessage".to_owned(), json!(message));
    }
    fields.insert(
        "createdAt".to_owned(),
        json!(crate::owner::stamp::rfc3339(row.created_at_ms)),
    );
    fields.insert(
        "lastUpdatedAt".to_owned(),
        json!(crate::owner::stamp::rfc3339(updated_ms)),
    );
    fields.insert("ttlMs".to_owned(), json!(row.ttl_ms));
    fields.insert(
        "pollIntervalMs".to_owned(),
        json!(MCP_TASK_POLL_INTERVAL_MS),
    );
    fields
}

/// "step 2 of 3" while a run works: never a world name or agent text.
fn step_message(view: &Value, status: TaskStatus) -> Option<String> {
    if status != TaskStatus::Working {
        return None;
    }
    let steps = view.get("steps").and_then(Value::as_array)?.len();
    let done = view.get("results").and_then(Value::as_array)?.len();
    Some(format!("step {} of {steps}", (done + 1).min(steps)))
}

/// A task answer's `_meta`: actor-bound, so private and never cached. The
/// starting call's own metadata rides along when there is one.
fn private_meta(base: Option<&Value>) -> Value {
    let mut meta = base.and_then(Value::as_object).cloned().unwrap_or_default();
    meta.insert("ttlMs".to_owned(), json!(0));
    meta.insert(
        "cacheScope".to_owned(),
        json!(crate::mcp::MCP_RESULT_CACHE_SCOPE),
    );
    Value::Object(meta)
}
