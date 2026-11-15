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
//! and an unknown id all answer alike as missing, and so does a record verb
//! that did not run for the caller: a refusal, or a hook's stop answered as a
//! result. A cancel is kept on the handle only once the record's cancel verb
//! ran. A caller verified in an anonymous off-record session keeps no record
//! of a task method, as of its tool call (OF-063). The record's end gives the
//! task's end: a failed run ends `completed` with `isError`, as a tool result
//! with `isError` does.
//!
//! Form questions (L1-03 PR 3): while a run works and its agents' asks to
//! the poller stand open, a poll that declares form elicitation answers
//! `input_required` with one form of those questions, each a choice among
//! its options and never free text; any other poll answers `working` with
//! the count. `tasks/update` reads only the current form's responses: an
//! accepted answer is the poller's word through `tasks.answer`, evidence and
//! never an approval; a decline voids the poller's seats through
//! `tasks.decline`, and the asks go on without that word; a cancel stops the
//! run as `tasks/cancel` does. A verb hook's ask, a consent ask or any other
//! approval is never a question: a run parked on one answers `working`,
//! waiting on an approval.
//!
//! Not built here: `subscriptions/listen` (change notices are optional, and
//! this endpoint answers one request per POST with no server stream).
//! Not this module: `tasks_response.rs`, which serves the TASKS board section.

use std::sync::Arc;

use axum::http::{Extensions, HeaderMap};
use oneiron::EntityId;
use oneiron::mcp_task::{McpTaskId, McpTaskRecord, McpTaskSubject};
use oneiron::task_verb::{WorkflowRunAsks, WorkflowRunQuestion};
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

/// The status line of a run parked on an approval, which no form carries.
const MCP_TASK_APPROVAL_WAIT: &str = "waiting on an approval";

/// The verb an accepted form answer runs as the poller: the word is
/// evidence, never approval.
const MCP_TASK_ANSWER_VERB: &str = "tasks.answer";

/// The verb a declined form runs as the poller, for each of its questions.
const MCP_TASK_DECLINE_VERB: &str = "tasks.decline";

/// The start of a form's key in `inputRequests`.
const MCP_TASK_FORM_KEY_PREFIX: &str = "form-";

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

fn engine_error(error: oneiron::Error) -> McpGatewayError {
    McpGatewayError::new(-32603, "engine_error", error.to_string())
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
    let Some(output) = verb_output(&answered) else {
        return Ok(answered);
    };
    let Some(root) = output
        .get("root_attempt_ref")
        .and_then(Value::as_str)
        .and_then(|hex| oneiron::EntityId::from_hex(hex).ok())
    else {
        return Ok(answered);
    };
    let status = TaskStatus::of_run(output);
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
        .map_err(engine_error)?;
    let row = McpTaskRecord {
        actor_ref: actor.actor_ref,
        subject: McpTaskSubject::WorkflowRun {
            root_attempt_ref: root,
        },
        created_at_ms: now_ms,
        ttl_ms,
        cancel_requested_at_ms: None,
    };
    let mut reply = task_fields(&id, &row, status, step_message(output, status));
    reply.insert("resultType".to_owned(), json!("task"));
    let mut meta = private_meta(answered.get("_meta"));
    // The starting call's own receipt (OF-538), which its tool result states
    // in `structuredContent.meta`.
    if let (Some(fields), Some(stated)) = (
        meta.as_object_mut(),
        answered
            .pointer("/structuredContent/meta")
            .and_then(Value::as_object),
    ) {
        for key in ["receipt_ref", "no_record"] {
            if let Some(value) = stated.get(key) {
                fields.insert(key.to_owned(), value.clone());
            }
        }
    }
    reply.insert("_meta".to_owned(), meta);
    let reply = Value::Object(reply);
    // A claimed call's waiters get this answer, released again by the rows
    // its tool result was judged by (FIX 7914).
    super::claimed_release::answered_as(&reply);
    Ok(reply)
}

/// A task method's answer to a caller verified in an anonymous off-record
/// session (OF-063): it keeps no record and says so, as that caller's tool
/// call does, in its `_meta` or in its error.
pub(super) fn off_record(
    answered: Result<Value, McpGatewayError>,
) -> Result<Value, McpGatewayError> {
    let stamp = crate::api::call_receipt::CallStamp::NoRecord;
    match answered {
        Ok(mut reply) => {
            if let Some(meta) = reply.get_mut("_meta").and_then(Value::as_object_mut) {
                stamp.stamp_json(meta);
            }
            Ok(reply)
        }
        Err(mut error) => {
            error.call_receipt = Some(Box::new(stamp));
            Err(error)
        }
    }
}

/// Whether `reply`, the answer of `method`, is a task method's answer that
/// keeps no record ([`off_record`]), so its connection records none either.
pub(super) fn kept_off_record(method: &str, reply: &Value) -> bool {
    method.starts_with("tasks/") && reply.pointer("/_meta/no_record") == Some(&Value::Bool(true))
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
    let row = vault
        .mcp_task(actor.actor_ref, &id, now_ms)
        .map_err(engine_error)?
        .ok_or_else(task_missing)?;
    let McpTaskSubject::WorkflowRun { root_attempt_ref } = &row.subject else {
        return Err(task_missing());
    };
    let root = *root_attempt_ref;
    let call = RecordCall {
        server,
        actor,
        headers,
        connection,
    };
    let spec = json!({ "root_attempt_ref": root.to_hex() });
    match method {
        "tasks/cancel" => {
            call.cancel(&id, spec, now_ms).await?;
            Ok(json!({ "resultType": "complete", "_meta": private_meta(None) }))
        }
        "tasks/update" => {
            // The record reads for the caller first, as on a poll, or the
            // task is missing. Only the responses under the current form's
            // key are read: one under any other key (never asked, answered
            // or superseded) is ignored, as the spec ignores it.
            let read = call.read(WORKFLOW_RUN.read, spec.clone()).await?;
            if TaskStatus::of_run(ran_output(&read)?) == TaskStatus::Working {
                let asks = call.open_asks(root)?;
                if let Some(form) = Form::of(&asks.questions)
                    && let Some(response) = params
                        .as_ref()
                        .and_then(|params| params.get("inputResponses"))
                        .and_then(|responses| responses.get(&form.key))
                {
                    call.respond(&form, response, &id, spec, now_ms).await?;
                }
            }
            Ok(json!({ "resultType": "complete", "_meta": private_meta(None) }))
        }
        _ => {
            let read = call.read(WORKFLOW_RUN.read, spec).await?;
            let output = ran_output(&read)?;
            let mut status = TaskStatus::of_run(output);
            let mut message = step_message(output, status);
            let mut input_requests = None;
            if status == TaskStatus::Working {
                let asks = call.open_asks(root)?;
                if let Some(form) = Form::of(&asks.questions) {
                    message = Some(form.message());
                    // Only a request that declares form elicitation is
                    // shown the questions; any other polls `working`.
                    if super::client_surface::declares_form_elicitation(
                        params.as_ref().and_then(|params| params.get("_meta")),
                    ) {
                        status = TaskStatus::InputRequired;
                        input_requests = Some(form.input_requests());
                    }
                } else if asks.waits_on_approval {
                    message = Some(MCP_TASK_APPROVAL_WAIT.to_owned());
                }
            }
            let mut reply = task_fields(&id, &row, status, message);
            reply.insert("resultType".to_owned(), json!("complete"));
            if let Some(requests) = input_requests {
                reply.insert("inputRequests".to_owned(), requests);
            }
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

/// A task method's caller and the request it came in, for the calls the
/// method makes of the record's own verbs as that caller.
struct RecordCall<'a> {
    server: &'a Arc<SyncServer>,
    actor: &'a McpCallContext,
    headers: &'a HeaderMap,
    connection: &'a Extensions,
}

impl RecordCall<'_> {
    /// Runs the record's read verb `verb` with `input` as the caller, on the
    /// caller's own endpoint, through the tool call's admission and release,
    /// and answers its tool result when the verb ran. A refusal, a hook's
    /// stop and a result with no output answer as missing, never in the
    /// verb's own words. A read: no call receipt is written for it, and it
    /// is not counted as a wire tool call.
    async fn read(&self, verb: &str, input: Value) -> Result<Value, McpGatewayError> {
        let params: McpToolCallParams = serde_json::from_value(verb_call(verb, input))
            .map_err(|error| McpGatewayError::new(-32603, "engine_error", error.to_string()))?;
        let read = async {
            let args =
                mcp_validated_call_args(self.server, self.actor.mode, params, None, self.actor)?;
            ensure_mcp_actor_matches(&args, self.actor)?;
            mcp_admit_scoped_call(self.server, &args, self.actor)?;
            Box::pin(execute_mcp_tool(
                self.server,
                args,
                self.actor,
                self.headers,
                self.connection,
            ))
            .await
        }
        .await
        .map_err(|_| task_missing())?;
        ran_output(&read)?;
        Ok(read)
    }

    /// Calls the generated verb `verb` with `input` as a tool call of the
    /// caller's: judged, run, released and receipted, as the wire's own call
    /// is. Answers its tool result when the verb ran; a refusal or a hook's
    /// stop answers as missing.
    async fn write(&self, verb: &str, input: Value) -> Result<Value, McpGatewayError> {
        let answered = super::envelope::call_tool_as(
            self.server,
            self.actor.mode,
            self.headers,
            self.connection,
            self.actor,
            Some(verb_call(verb, input)),
            None,
            None,
        )
        .await
        .map_err(|_| task_missing())?;
        ran_output(&answered)?;
        Ok(answered)
    }

    /// The record's own cancel verb, as a tool call of the caller's. It asks
    /// the work to stop and never undoes committed work. Only a cancel the
    /// verb ran is acknowledged and kept on the handle; a refusal or a
    /// hook's stop answers as missing and leaves the handle as it was.
    async fn cancel(
        &self,
        id: &McpTaskId,
        spec: Value,
        now_ms: u64,
    ) -> Result<(), McpGatewayError> {
        self.write(WORKFLOW_RUN.cancel, spec).await?;
        self.server
            .vault()
            .request_mcp_task_cancel(self.actor.actor_ref, id, now_ms)
            .map_err(engine_error)?;
        Ok(())
    }

    /// The open questions the run `root` asked the caller, and whether it is
    /// parked on an approval: read as the caller's own person, so only its
    /// own seats are listed.
    fn open_asks(&self, root: EntityId) -> Result<WorkflowRunAsks, McpGatewayError> {
        self.server
            .vault()
            .memory(self.actor.actor_ref, self.actor.actor_class)
            .open_asks_for_run(root)
            .map_err(|error| McpGatewayError::new(-32603, "engine_error", error.message))
    }

    /// One form response, the caller's own words: `accept` answers each
    /// question whose property names one of its options through
    /// `tasks.answer` (evidence, never approval) and leaves the rest
    /// unanswered; `decline` declines each question of the form through
    /// `tasks.decline`, so each ask goes on without the caller's word;
    /// `cancel` asks the run to stop, as `tasks/cancel` does. The server
    /// never fills an answer. A question whose verb does not run for the
    /// caller stays open and is asked again on the next poll.
    async fn respond(
        &self,
        form: &Form<'_>,
        response: &Value,
        id: &McpTaskId,
        spec: Value,
        now_ms: u64,
    ) -> Result<(), McpGatewayError> {
        match response.get("action").and_then(Value::as_str) {
            Some("accept") => {
                let content = response.get("content").and_then(Value::as_object);
                for question in form.questions {
                    let Some(option) = content
                        .and_then(|content| content.get(&Form::property(question)))
                        .and_then(Value::as_str)
                        .filter(|picked| {
                            question
                                .options
                                .iter()
                                .any(|(offered, _)| offered.as_str() == *picked)
                        })
                    else {
                        continue;
                    };
                    let input = json!({
                        "handle": { "group_ref": question.handle.group_ref.to_hex() },
                        "word": {
                            "result_ref": question.subject_ref.to_hex(),
                            "option": option,
                        },
                    });
                    // A word the verb refused leaves its question open.
                    let _ = self.write(MCP_TASK_ANSWER_VERB, input).await;
                }
            }
            Some("decline") => {
                for question in form.questions {
                    let input = json!({
                        "handle": { "group_ref": question.handle.group_ref.to_hex() },
                    });
                    // A decline the verb refused leaves its question open.
                    let _ = self.write(MCP_TASK_DECLINE_VERB, input).await;
                }
            }
            Some("cancel") => self.cancel(id, spec, now_ms).await?,
            _ => {}
        }
        Ok(())
    }
}

/// The open questions of one round as one form: every question the run
/// asked the poller and that stands open, under one key. The key is the
/// digest of the questions' (ask, revision) pairs, so a changed question set
/// is a new form under a new key, and an answer to an earlier form is never
/// read as this one's.
struct Form<'a> {
    key: String,
    questions: &'a [WorkflowRunQuestion],
}

impl<'a> Form<'a> {
    /// The form of `questions`; `None` when no question stands open.
    fn of(questions: &'a [WorkflowRunQuestion]) -> Option<Self> {
        if questions.is_empty() {
            return None;
        }
        let mut digest = blake3::Hasher::new();
        for question in questions {
            digest.update(question.handle.group_ref.as_bytes());
            digest.update(&question.revision.to_le_bytes());
        }
        let key = format!(
            "{MCP_TASK_FORM_KEY_PREFIX}{}",
            &digest.finalize().to_hex()[..16]
        );
        Some(Self { key, questions })
    }

    /// A question's property: its ask and revision, so a word binds to the
    /// question it was shown.
    fn property(question: &WorkflowRunQuestion) -> String {
        format!(
            "{}-r{}",
            question.handle.group_ref.to_hex(),
            question.revision
        )
    }

    /// "2 questions": the count only, never a question's words.
    fn count(&self) -> String {
        match self.questions.len() {
            1 => "1 question".to_owned(),
            count => format!("{count} questions"),
        }
    }

    /// The task's status line while the form is open: "waiting on 2
    /// questions".
    fn message(&self) -> String {
        format!("waiting on {}", self.count())
    }

    /// `inputRequests`: this form's one `elicitation/create` request in form
    /// mode. Every property is one question, a string whose every value is
    /// one of its options, so a form holds no free text and asks for no
    /// secret: an ask already refuses an option named as a credential.
    fn input_requests(&self) -> Value {
        let mut properties = Map::new();
        for (ordinal, question) in self.questions.iter().enumerate() {
            let title = question
                .label
                .clone()
                .unwrap_or_else(|| format!("Question {}", ordinal + 1));
            let options = question
                .options
                .iter()
                .map(|(id, label)| json!({ "const": id.as_str(), "title": label }))
                .collect::<Vec<_>>();
            properties.insert(
                Self::property(question),
                json!({ "type": "string", "title": title, "oneOf": options }),
            );
        }
        json!({
            (self.key.clone()): {
                "method": "elicitation/create",
                "params": {
                    "mode": "form",
                    "message": format!("Answer the {} this workflow run asked you.", self.count()),
                    "requestedSchema": { "type": "object", "properties": properties },
                },
            },
        })
    }
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

/// A record verb's typed output when the verb ran for the caller: a tool
/// result marked `isError` (a hook's stop or skip among them) or one with no
/// output answers as missing.
fn ran_output(answered: &Value) -> Result<&Value, McpGatewayError> {
    if answered.get("isError") == Some(&Value::Bool(true)) {
        return Err(task_missing());
    }
    verb_output(answered).ok_or_else(task_missing)
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
    /// The run works and asks the poller questions, shown as a form.
    InputRequired,
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
            Self::InputRequired => "input_required",
        }
    }
}

/// The fields every task answer carries: its id, status, its status line
/// `message` (a step ordinal and count, a question count or an approval
/// wait, never a world name or agent text), its times, retention and poll
/// interval. `ttlMs` is the handle's retention and keeps its own value.
fn task_fields(
    id: &McpTaskId,
    row: &McpTaskRecord,
    status: TaskStatus,
    message: Option<String>,
) -> Map<String, Value> {
    let updated_ms = row.cancel_requested_at_ms.unwrap_or(row.created_at_ms);
    let mut fields = Map::new();
    fields.insert("taskId".to_owned(), json!(id.to_hex()));
    fields.insert("status".to_owned(), json!(status.wire()));
    if let Some(message) = message {
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
