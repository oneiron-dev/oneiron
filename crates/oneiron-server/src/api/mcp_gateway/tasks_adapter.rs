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
//! Form questions (L1-03 PR 3): while a run works and its agents' plain
//! questions to the poller stand open, a poll that declares form elicitation
//! answers `input_required` with one form of those questions, each a choice
//! among its options and never free text; any other poll answers `working`
//! with the count. The questions are the record's own read verb's answer,
//! `vault.workflows.asks`, run as the poller as every record read is, so its
//! admission, destination and release judge them; a refused read shows no
//! question and says nothing of one. `tasks/update` reads only the current
//! form's responses: an accepted answer is the poller's word through
//! `tasks.answer`, evidence and never an approval; a decline voids the
//! poller's seats through `tasks.decline`, and the asks go on without that
//! word; a cancel stops the run as `tasks/cancel` does. An ask the engine
//! raises itself (a verb hook's, a consent, a comm widen or a holder's ask)
//! is never a question: a run parked on a hook's ask says it waits on an
//! approval.
//!
//! The other two records (L1-03 PR 4): a Timer `host.wake` answers a task
//! over its night step's root, read through `vault.sieve.settlements.get`;
//! the step ends once its outcome no longer runs, and a partial outcome ends
//! `completed`, naming itself. An `ai.video` call answers a task over its
//! job's ticket, read through `ai.video.poll` and stopped through
//! `ai.video.cancel`. A night step has no stop door: its cancel is
//! acknowledged and the step ends with its record. A task's end is final:
//! the handle keeps the first end a read saw, though a night step's
//! remainder works again a policy interval later. A later read that no
//! longer finds the record at that end is not the task's result: the task
//! answers its end and says the record has worked on since, and the handle
//! keeps no copy of the record. A task that ended is never cancelled, and a
//! video task's cancel stops only a job that still runs (`if_running`), so
//! a cancel never deletes a finished clip, even one that finished after the
//! task's last read: that cancel answers the task's end instead.
//! A start sent again without `_meta["oneiron/invocation"]` (for
//! `ai.video`, nor its `idempotency_key`) is a new call, as the verb's own
//! rules make it: it starts new work and answers a new task.
//!
//! Not built here: `subscriptions/listen` (change notices are optional, and
//! this endpoint answers one request per POST with no server stream).
//! Not this module: `tasks_response.rs`, which serves the TASKS board section.

use std::sync::Arc;

use axum::http::{Extensions, HeaderMap};
use oneiron::mcp_task::{McpTaskEnd, McpTaskEnded, McpTaskId, McpTaskRecord, McpTaskSubject};
use oneiron::task_verb::{WorkflowRunAsks, WorkflowRunQuestion};
use serde_json::{Map, Value, json};

use super::{
    McpCallContext, McpGatewayError, McpToolCallParams, ensure_mcp_actor_matches, execute_mcp_tool,
    mcp_admit_scoped_call, mcp_validated_call_args,
};
use crate::mcp::McpValidatedToolArgs;
use crate::server::SyncServer;

/// How often a client may poll a task: no faster than this (canon :263).
const MCP_TASK_POLL_INTERVAL_MS: u64 = 2000;

/// The one answer for an unknown id, another actor's handle and an expired
/// one, so no answer tells that a hidden task exists.
const MCP_TASK_MISSING: &str = "Failed to retrieve task: Task not found";

/// The consent a task method's inner verb call states: the caller's own
/// task method, never a new purpose.
const MCP_TASK_POLICY_REF: &str = "policy:mcp-task";

/// What the status line names of a run parked on an approval, which no form
/// carries.
const MCP_TASK_APPROVAL_WAIT: &str = "an approval";

/// The verb an accepted form answer runs as the poller: the word is
/// evidence, never approval.
const MCP_TASK_ANSWER_VERB: &str = "tasks.answer";

/// The verb a declined form runs as the poller, for each of its questions.
const MCP_TASK_DECLINE_VERB: &str = "tasks.decline";

/// The start of a form's key in `inputRequests`.
const MCP_TASK_FORM_KEY_PREFIX: &str = "form-";

/// The status line of a task whose record has worked on past the end the
/// task keeps (a night step's remainder).
const MCP_TASK_RECORD_MOVED: &str = "ended; its record has worked on since";

/// A record kind a task can wrap: the verb that starts it, and the record's
/// own read and cancel verbs.
struct TaskRecordVerbs {
    start: &'static str,
    read: &'static str,
    /// `None` when the record has no stop door: a cancel is acknowledged and
    /// nothing stops.
    cancel: Option<&'static str>,
    /// The read of the questions the record's work asked its reader; `None`
    /// when its work asks none.
    asks: Option<&'static str>,
    /// Whether the cancel verb stops the work and drops the record at once
    /// (a video job, its kept row and clips), so the task ends `cancelled`
    /// as soon as that verb ran, with no record left to read.
    cancel_drops_record: bool,
    /// The cancel verb's input flag that stops only work still running and
    /// keeps a record that already ended (a finished clip), set on every
    /// cancel: a record that ended after the task's last read then refuses
    /// the stop and keeps its result. `None` when the cancel verb never
    /// undoes an end.
    cancel_keeps_ended: Option<&'static str>,
}

/// A saved-workflow run, by its root attempt.
const WORKFLOW_RUN: TaskRecordVerbs = TaskRecordVerbs {
    start: "vault.workflows.dispatch",
    read: "vault.workflows.status",
    cancel: Some("vault.workflows.cancel"),
    asks: Some("vault.workflows.asks"),
    cancel_drops_record: false,
    cancel_keeps_ended: None,
};

/// A Dreamer night step (a Timer `host.wake`), by its root attempt and its
/// settlement (ARCH-0026). It has no stop door.
const NIGHT_STEP: TaskRecordVerbs = TaskRecordVerbs {
    start: "host.wake",
    read: "vault.sieve.settlements.get",
    cancel: None,
    asks: None,
    cancel_drops_record: false,
    cancel_keeps_ended: None,
};

/// A provider job (an `ai.video` render), by its ticket.
const PROVIDER_JOB: TaskRecordVerbs = TaskRecordVerbs {
    start: "ai.video",
    read: "ai.video.poll",
    cancel: Some("ai.video.cancel"),
    asks: None,
    cancel_drops_record: true,
    cancel_keeps_ended: Some("if_running"),
};

/// The verbs of the record `subject` names.
fn record_verbs(subject: &McpTaskSubject) -> &'static TaskRecordVerbs {
    match subject {
        McpTaskSubject::WorkflowRun { .. } => &WORKFLOW_RUN,
        McpTaskSubject::NightStep { .. } => &NIGHT_STEP,
        McpTaskSubject::ProviderJob { .. } => &PROVIDER_JOB,
    }
}

/// The input every verb of the record `subject` names takes: the record's
/// own key.
fn record_spec(subject: &McpTaskSubject) -> Value {
    match subject {
        McpTaskSubject::WorkflowRun { root_attempt_ref } => {
            json!({ "root_attempt_ref": root_attempt_ref.to_hex() })
        }
        McpTaskSubject::NightStep { wake_root_ref } => json!({ "wake": wake_root_ref.to_hex() }),
        McpTaskSubject::ProviderJob { job } => json!({ "job": job }),
    }
}

/// The record a call of `tool` started, from the typed `output` its verb
/// answered: a saved-workflow run's root, a Timer wake's root (any other
/// wake starts no record a task wraps), a video job's ticket.
fn started_subject(tool: &str, output: &Value) -> Option<McpTaskSubject> {
    let entity = |field: &str| {
        output
            .get(field)
            .and_then(Value::as_str)
            .and_then(|hex| oneiron::EntityId::from_hex(hex).ok())
    };
    if tool == WORKFLOW_RUN.start {
        return entity("root_attempt_ref")
            .map(|root_attempt_ref| McpTaskSubject::WorkflowRun { root_attempt_ref });
    }
    if tool == NIGHT_STEP.start {
        if output.get("wake_kind").and_then(Value::as_str) != Some("timer") {
            return None;
        }
        return entity("attempt").map(|wake_root_ref| McpTaskSubject::NightStep { wake_root_ref });
    }
    if tool == PROVIDER_JOB.start {
        return output
            .get("job")
            .and_then(Value::as_str)
            .filter(|job| !job.is_empty())
            .map(|job| McpTaskSubject::ProviderJob {
                job: job.to_owned(),
            });
    }
    None
}

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

/// The `-32602` refusal of a cancel of a task that already ended (the
/// spec: a task in a terminal status is never cancelled). The caller reads
/// its own task, so the refusal names the end.
fn task_ended(end: McpTaskEnd) -> McpGatewayError {
    let status = TaskStatus::of_end(end).wire();
    McpGatewayError::new(
        -32602,
        "task_ended",
        format!("Cannot cancel task: it is already {status}"),
    )
    .with_field("taskId")
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
    if answered.get("isError") == Some(&Value::Bool(true)) {
        return Ok(answered);
    }
    let Some(output) = verb_output(&answered) else {
        return Ok(answered);
    };
    let Some(subject) = started_subject(tool, output) else {
        return Ok(answered);
    };
    // A dispatch answers the run's view; a wake or a ticket answers no
    // state yet, and the record has just started.
    let (status, message) = match &subject {
        McpTaskSubject::WorkflowRun { .. } => {
            let status = TaskStatus::of_run(output);
            (status, step_message(output, status))
        }
        McpTaskSubject::NightStep { .. } | McpTaskSubject::ProviderJob { .. } => {
            (TaskStatus::Working, None)
        }
    };
    let vault = server.vault();
    let now_ms = vault.now_recorded_ms();
    let ttl_ms = server.config.mcp_task_ttl_ms;
    let id = vault
        .mint_mcp_task(actor.actor_ref, subject.clone(), ttl_ms, now_ms)
        .map_err(engine_error)?;
    let row = McpTaskRecord {
        actor_ref: actor.actor_ref,
        subject,
        created_at_ms: now_ms,
        ttl_ms,
        cancel_requested_at_ms: None,
        ended: None,
    };
    let mut reply = task_fields(&id, &row, status, message);
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
    let verbs = record_verbs(&row.subject);
    let spec = record_spec(&row.subject);
    let call = RecordCall {
        server,
        actor,
        headers,
        connection,
    };
    // Every method reads the record for the caller first, through the
    // record's own read verb, or the task is missing. A record its cancel
    // dropped (a video job) has nothing left to read: its handle answers the
    // end it kept once the caller passes every check a call of that read
    // meets before it runs, and nothing of the record.
    let read = if verbs.cancel_drops_record
        && row
            .ended
            .is_some_and(|ended| ended.end == McpTaskEnd::Cancelled)
    {
        call.preflight(verbs.read, spec.clone())?;
        None
    } else {
        Some(call.read(verbs.read, spec.clone()).await?)
    };
    let TaskReading {
        mut status,
        row,
        read_is_result,
    } = match &read {
        Some(read) => call.status(&id, row, ran_output(read)?)?,
        None => TaskReading {
            status: TaskStatus::Cancelled,
            row,
            read_is_result: false,
        },
    };
    match method {
        "tasks/cancel" => {
            // A task's end is final: a cancel never reaches a record whose
            // end the task already answers, so it never undoes a finished
            // job (a video job's cancel deletes its clip).
            if let Some(end) = status.end() {
                return Err(task_ended(end));
            }
            call.cancel(&id, &row, verbs, spec).await?;
            Ok(json!({ "resultType": "complete", "_meta": private_meta(None) }))
        }
        "tasks/update" => {
            // Only the responses under the current form's key are read: one
            // under any other key (never asked, answered or superseded) is
            // ignored, as the spec ignores it.
            if status == TaskStatus::Working
                && let Some(asks_verb) = verbs.asks
            {
                let asks = call.open_asks(asks_verb, spec.clone()).await;
                if let Some(form) = Form::of(&asks.questions)
                    && let Some(response) = params
                        .as_ref()
                        .and_then(|params| params.get("inputResponses"))
                        .and_then(|responses| responses.get(&form.key))
                {
                    call.respond(&form, response, &id, &row, verbs, spec)
                        .await?;
                }
            }
            Ok(json!({ "resultType": "complete", "_meta": private_meta(None) }))
        }
        _ => {
            let mut message = match &read {
                Some(read) if read_is_result => {
                    record_message(&row.subject, ran_output(read)?, status)
                }
                Some(_) => Some(MCP_TASK_RECORD_MOVED.to_owned()),
                None => None,
            };
            let mut input_requests = None;
            if status == TaskStatus::Working
                && let Some(asks_verb) = verbs.asks
            {
                let asks = call.open_asks(asks_verb, spec).await;
                let form = Form::of(&asks.questions);
                // Only a request that declares form elicitation is shown the
                // questions; any other polls `working`.
                if let Some(form) = &form
                    && super::client_surface::declares_form_elicitation(
                        params.as_ref().and_then(|params| params.get("_meta")),
                    )
                {
                    status = TaskStatus::InputRequired;
                    input_requests = Some(form.input_requests());
                }
                message = wait_message(form.as_ref(), asks.waits_on_approval).or(message);
            }
            let mut reply = task_fields(&id, &row, status, message);
            reply.insert("resultType".to_owned(), json!("complete"));
            if let Some(requests) = input_requests {
                reply.insert("inputRequests".to_owned(), requests);
            }
            if matches!(
                status,
                TaskStatus::Completed | TaskStatus::CompletedWithError
            ) && let Some(read) = read
            {
                // A read past the task's end is the record as it stands
                // now, not the task's result; the handle keeps no copy of
                // the end's own read.
                let mut result = if read_is_result {
                    read
                } else {
                    moved_result(verbs.read)
                };
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
        let args = self.admit(verb, input)?;
        let read = Box::pin(execute_mcp_tool(
            self.server,
            args,
            self.actor,
            self.headers,
            self.connection,
        ))
        .await
        .map_err(|_| task_missing())?;
        ran_output(&read)?;
        Ok(read)
    }

    /// The admission a call of the record's verb `verb` with `input` meets
    /// as the caller, on the caller's own endpoint: its arguments, its actor
    /// and its scope. A refusal answers as missing.
    fn admit(&self, verb: &str, input: Value) -> Result<McpValidatedToolArgs, McpGatewayError> {
        let params: McpToolCallParams = serde_json::from_value(verb_call(verb, input))
            .map_err(|error| McpGatewayError::new(-32603, "engine_error", error.to_string()))?;
        mcp_validated_call_args(self.server, self.actor.mode, params, None, self.actor)
            .and_then(|args| {
                ensure_mcp_actor_matches(&args, self.actor)?;
                mcp_admit_scoped_call(self.server, &args, self.actor)?;
                Ok(args)
            })
            .map_err(|_| task_missing())
    }

    /// Every check a call of the record's verb `verb` with `input` meets as
    /// the caller before it runs: [`Self::admit`], then the verb's
    /// credential gate (a live credential, its record bounds and the verb's
    /// scope) and its door's own proof (an owner-grade one for a video
    /// job's), as the tool call's dispatch runs them. Nothing runs. A
    /// refusal answers as missing.
    fn preflight(&self, verb: &str, input: Value) -> Result<(), McpGatewayError> {
        let McpValidatedToolArgs::Verb(call) = self.admit(verb, input)? else {
            return Err(task_missing());
        };
        let shared = super::actor_dispatch::mcp_share_view_context(self.actor, call.tool.name);
        let actor = shared.as_ref().unwrap_or(self.actor);
        super::actor_dispatch::mcp_verb_gate(
            self.server,
            call.tool,
            &call.payload.arguments,
            actor,
        )
        .map_err(|_| task_missing())?;
        if let Some(auth) = actor.auth.as_ref() {
            crate::api::facade::row_door_admits(self.server, auth, call.tool.name)
                .map_err(|_| task_missing())?;
        }
        Ok(())
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

    /// The task's status from `output`, the caller's read of its record:
    /// the end the handle keeps, else the record's own state, kept on the
    /// handle once it is an end, so a task's end never changes. A record
    /// that can work on past its end (a night step) keeps a digest of its
    /// outcome with it, so a read at the same end with another outcome is
    /// not the task's result. The end is kept at the time of its write, so
    /// a handle whose time ran out during the read keeps nothing. A read
    /// that names no record answers as missing.
    fn status(
        &self,
        id: &McpTaskId,
        row: McpTaskRecord,
        output: &Value,
    ) -> Result<TaskReading, McpGatewayError> {
        let status = TaskStatus::of_record(&row.subject, output).ok_or_else(task_missing)?;
        let seen = record_end(&row.subject, output, status);
        let outcome_digest = record_outcome_digest(&row.subject, output);
        if let Some(ended) = row.ended {
            return Ok(TaskReading {
                status: TaskStatus::of_end(ended.end),
                read_is_result: seen.is_some_and(|end| same_end(ended, end, outcome_digest)),
                row,
            });
        }
        let Some(end) = seen else {
            return Ok(TaskReading {
                status,
                row,
                read_is_result: true,
            });
        };
        let vault = self.server.vault();
        let ended = McpTaskEnded {
            end,
            at_ms: vault.now_recorded_ms(),
            outcome_digest,
        };
        let kept = vault
            .end_mcp_task(self.actor.actor_ref, id, ended)
            .map_err(engine_error)?
            .ok_or_else(task_missing)?;
        let kept_ended = kept.ended.unwrap_or(ended);
        Ok(TaskReading {
            status: TaskStatus::of_end(kept_ended.end),
            read_is_result: same_end(kept_ended, end, outcome_digest),
            row: kept,
        })
    }

    /// The record's own cancel verb, as a tool call of the caller's. It asks
    /// the work to stop and never undoes committed work: a record whose
    /// cancel could delete an end (a video job's clip) is asked to stop only
    /// work still running. Only a cancel the verb ran is acknowledged and
    /// kept on the handle. A refusal or a hook's stop leaves the handle as
    /// it was: when a fresh read then finds the record ended since the
    /// task's last read, the cancel is refused as a cancel of that ended
    /// task, else it answers as missing. A record with no stop door (a night
    /// step) is acknowledged with nothing stopped: the spec's cancel is
    /// cooperative, and the task ends with its record. A cancel that drops
    /// its record (a video job) ends the task `cancelled` at once.
    async fn cancel(
        &self,
        id: &McpTaskId,
        row: &McpTaskRecord,
        verbs: &TaskRecordVerbs,
        spec: Value,
    ) -> Result<(), McpGatewayError> {
        if let Some(cancel) = verbs.cancel {
            let mut input = spec.clone();
            if let (Some(flag), Some(fields)) = (verbs.cancel_keeps_ended, input.as_object_mut()) {
                fields.insert(flag.to_owned(), Value::Bool(true));
            }
            if let Err(refused) = self.write(cancel, input).await {
                return Err(self
                    .ended_since(id, row.clone(), verbs.read, spec)
                    .await
                    .unwrap_or(refused));
            }
        }
        let vault = self.server.vault();
        let now_ms = vault.now_recorded_ms();
        vault
            .request_mcp_task_cancel(self.actor.actor_ref, id, now_ms)
            .map_err(engine_error)?;
        if verbs.cancel_drops_record {
            let ended = McpTaskEnded {
                end: McpTaskEnd::Cancelled,
                at_ms: now_ms,
                outcome_digest: None,
            };
            vault
                .end_mcp_task(self.actor.actor_ref, id, ended)
                .map_err(engine_error)?;
        }
        Ok(())
    }

    /// After a cancel the record's verb refused: the refusal of a cancel of
    /// an ended task, when a fresh read of the record, run as the caller,
    /// finds it ended since the task's last read; the handle keeps that end.
    /// `None` while the record works, or when the read did not run for the
    /// caller.
    async fn ended_since(
        &self,
        id: &McpTaskId,
        row: McpTaskRecord,
        read_verb: &str,
        spec: Value,
    ) -> Option<McpGatewayError> {
        let read = self.read(read_verb, spec).await.ok()?;
        let reading = self.status(id, row, ran_output(&read).ok()?).ok()?;
        reading.status.end().map(task_ended)
    }

    /// The open questions the run `spec` names asked the caller, and whether
    /// it is parked on an approval: the record's own asks verb, run as the
    /// caller through the read's admission and release, so only its own
    /// seats are listed, and only what may go where the answer goes. A read
    /// that did not run for the caller shows no question and no approval
    /// wait, so it says nothing of an ask it may not show.
    async fn open_asks(&self, asks_verb: &str, spec: Value) -> WorkflowRunAsks {
        let Ok(read) = self.read(asks_verb, spec).await else {
            return WorkflowRunAsks::default();
        };
        ran_output(&read)
            .ok()
            .and_then(|output| serde_json::from_value(output.clone()).ok())
            .unwrap_or_default()
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
        row: &McpTaskRecord,
        verbs: &TaskRecordVerbs,
        spec: Value,
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
                                .any(|offered| offered.id.as_str() == *picked)
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
            Some("cancel") => self.cancel(id, row, verbs, spec).await?,
            _ => {}
        }
        Ok(())
    }
}

/// The open questions of one round as one form: every question the run
/// asked the poller and that stands open, under one key. The key is the
/// digest of the questions' (ask, revision) pairs, so a changed question set
/// is a new form under a new key, and an answer to an earlier form is never
/// read as this one's. It is a digest of the set, not a token of one fetch:
/// should the same set stand open again, its key is the same.
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
    /// one of its options, so a form holds no free text: no answer can carry
    /// a typed key, password, token or card number. The labels are the
    /// asker's own words, as the ask shows them on every other surface.
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
                .map(|option| json!({ "const": option.id.as_str(), "title": option.label }))
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

/// A task after a read of its record: its status, its handle, and whether
/// the read is the task's own answer.
struct TaskReading {
    status: TaskStatus,
    row: McpTaskRecord,
    /// `false` once the record has worked on past the end the task keeps (a
    /// night step's remainder, also once it ended again; a failed attempt's
    /// successor): the read is then the record as it stands now, not the
    /// task's result.
    read_is_result: bool,
}

/// Whether the end `kept` on a handle is the end `end` a read shows, with
/// the outcome `outcome_digest` names.
fn same_end(kept: McpTaskEnded, end: McpTaskEnd, outcome_digest: Option<[u8; 16]>) -> bool {
    kept.end == end && kept.outcome_digest == outcome_digest
}

/// A digest of the outcome a read of the record `subject` names, for a
/// record that can work on past its end: a night step, whose deferred
/// remainder runs under the same root and can end again with other jobs
/// and results. `None` for any other record, whose end never moves.
fn record_outcome_digest(subject: &McpTaskSubject, output: &Value) -> Option<[u8; 16]> {
    if !matches!(subject, McpTaskSubject::NightStep { .. }) {
        return None;
    }
    let outcome = serde_json::to_vec(output.get("outcome")?).ok()?;
    blake3::hash(&outcome).as_bytes()[..16].try_into().ok()
}

/// The end a read of the record `subject` names shows at `status`, as the
/// handle keeps it: a night step's partial outcome is its own end. `None`
/// while the record works.
fn record_end(subject: &McpTaskSubject, output: &Value, status: TaskStatus) -> Option<McpTaskEnd> {
    let end = status.end()?;
    let partial = matches!(subject, McpTaskSubject::NightStep { .. })
        && output.pointer("/outcome/state").and_then(Value::as_str) == Some("partial");
    Some(if partial {
        McpTaskEnd::CompletedPartial
    } else {
        end
    })
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

    /// From a `vault.sieve.settlements.get` view's outcome: the step works
    /// while its outcome runs or waits on its host, and ends once it no
    /// longer runs (ARCH-0026: the caller polls "until the outcome is no
    /// longer running"). A partial outcome ends `completed` and names itself
    /// in the result, because settled is not success; a failed one ends
    /// `completed` marked an error. `None` when the root is gone.
    fn of_night_step(view: &Value) -> Option<Self> {
        match view.pointer("/outcome/state").and_then(Value::as_str)? {
            "succeeded" | "partial" => Some(Self::Completed),
            "failed" => Some(Self::CompletedWithError),
            _ => Some(Self::Working),
        }
    }

    /// From an `ai.video.poll` answer's `state`: a done render ends
    /// `completed` with its clip, a failed one `completed` marked an error.
    fn of_video_job(job: &Value) -> Option<Self> {
        match job.get("state").and_then(Value::as_str)? {
            "done" => Some(Self::Completed),
            "failed" => Some(Self::CompletedWithError),
            _ => Some(Self::Working),
        }
    }

    /// From a read of the record `subject` names: `None` when the read names
    /// no record.
    fn of_record(subject: &McpTaskSubject, output: &Value) -> Option<Self> {
        match subject {
            McpTaskSubject::WorkflowRun { .. } => Some(Self::of_run(output)),
            McpTaskSubject::NightStep { .. } => Self::of_night_step(output),
            McpTaskSubject::ProviderJob { .. } => Self::of_video_job(output),
        }
    }

    /// The end this status is, kept on the handle once a read saw it.
    fn end(self) -> Option<McpTaskEnd> {
        match self {
            Self::Working | Self::InputRequired => None,
            Self::Completed => Some(McpTaskEnd::Completed),
            Self::CompletedWithError => Some(McpTaskEnd::CompletedWithError),
            Self::Cancelled => Some(McpTaskEnd::Cancelled),
        }
    }

    fn of_end(end: McpTaskEnd) -> Self {
        match end {
            McpTaskEnd::Completed | McpTaskEnd::CompletedPartial => Self::Completed,
            McpTaskEnd::CompletedWithError => Self::CompletedWithError,
            McpTaskEnd::Cancelled => Self::Cancelled,
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
    let updated_ms = row.last_updated_at_ms();
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

/// The status line of a run that waits on its poller: "waiting on 2
/// questions", "waiting on an approval", or both ("waiting on 1 question and
/// an approval"); `None` while it waits on neither.
fn wait_message(form: Option<&Form<'_>>, waits_on_approval: bool) -> Option<String> {
    match (form, waits_on_approval) {
        (Some(form), true) => Some(format!(
            "waiting on {} and {MCP_TASK_APPROVAL_WAIT}",
            form.count()
        )),
        (Some(form), false) => Some(form.message()),
        (None, true) => Some(format!("waiting on {MCP_TASK_APPROVAL_WAIT}")),
        (None, false) => None,
    }
}

/// The status line a read of the record `subject` names gives at `status`:
/// counts, states and outcome classes only, never a world name, a job's
/// words or agent text.
fn record_message(subject: &McpTaskSubject, output: &Value, status: TaskStatus) -> Option<String> {
    match subject {
        McpTaskSubject::WorkflowRun { .. } => step_message(output, status),
        McpTaskSubject::NightStep { .. } => night_step_message(output, status),
        McpTaskSubject::ProviderJob { .. } => video_job_message(output, status),
    }
}

/// A night step's line: "waiting on 2 of 5 jobs" or "waiting on the host"
/// while it works; "outcome partial" once it ended (the outcome class, which
/// the result names too).
fn night_step_message(view: &Value, status: TaskStatus) -> Option<String> {
    let outcome = view.get("outcome")?;
    let state = outcome.get("state").and_then(Value::as_str)?;
    match status {
        TaskStatus::Working => {
            if state == "awaiting_host" {
                return Some("waiting on the host".to_owned());
            }
            let waiting = outcome.get("waiting_on").and_then(Value::as_array)?.len();
            let jobs = view.get("jobs").and_then(Value::as_array)?.len();
            Some(format!("waiting on {waiting} of {jobs} jobs"))
        }
        TaskStatus::Completed | TaskStatus::CompletedWithError
            if matches!(state, "succeeded" | "partial" | "failed") =>
        {
            Some(format!("outcome {state}"))
        }
        _ => None,
    }
}

/// A video job's line while it works: "queued", "rendering" or
/// "rendering, 40%".
fn video_job_message(job: &Value, status: TaskStatus) -> Option<String> {
    if status != TaskStatus::Working {
        return None;
    }
    match job.get("state").and_then(Value::as_str)? {
        "queued" => Some("queued".to_owned()),
        "running" => Some(
            match job
                .get("progress")
                .and_then(Value::as_u64)
                .filter(|progress| *progress <= 100)
            {
                Some(progress) => format!("rendering, {progress}%"),
                None => "rendering".to_owned(),
            },
        ),
        _ => None,
    }
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

/// The result of a task whose record has worked on past its end: the handle
/// keeps no copy of the record, so the result says so and names the read
/// that answers the record as it stands now. It carries nothing of the
/// record.
fn moved_result(read_verb: &str) -> Value {
    json!({
        "content": [{
            "type": "text",
            "text": format!(
                "This task ended, and its record has worked on since. No copy of the record \
                 is kept; call {read_verb} for the record as it stands now."
            ),
        }],
    })
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
