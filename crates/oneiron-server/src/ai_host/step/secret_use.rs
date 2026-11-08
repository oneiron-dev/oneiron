//! `self.use` on a saved-workflow text step (FIX 2315). A step whose
//! context holds a masked secret's handle (`sc<n>`) may hand it to one of
//! the engine's table operations and read the operation's answer, never the
//! value. Each call goes through the use door
//! ([`sdk::use_secret_as_caller`]) as the step's own agent while the step
//! still holds its lease, under an invocation derived from the step's run,
//! the same on every replay of the try, with its leased try bound as the
//! use's task host: a secret its run found is the step's to use (FIX 8334).
//! It crosses the row's verb-hook boundary ([`verb_hook_boundary::row`]) as
//! a pumped run's `self.use` does, so the owner's verb hooks fire once
//! around it: Pending durably parks this same leaf; a skip goes back to the model
//! as the tool's error result,
//! its reason with it, never as the step's failure. Every round the model is asked
//! again is admitted and metered on the step's one funded run, so the
//! step's budget bounds the rounds; nothing else does.
//!
//! Nothing here expands a handle. The tool result is the door's typed
//! answer, or its refusal as the door words it (revoked, unbound and
//! unknown-operation refusals included); neither holds the value, and
//! neither is logged. Every table operation is offered. On a served vault
//! the call goes, past the same boundary, to the server's own `self.use`
//! door ([`crate::api::self_use_as`]), which sends `connector.call` under
//! the agent's own grant and gate (FIX 7016); with no server bound the
//! embedded door answers, and it refuses `connector.call`.
//!
//! The tool rides only a route every rung of which takes tool calls and
//! their results: a rung without them refuses a request that carries tools,
//! and a step that ran before must still run.

use oneiron::actor_claims::craft_message_entries;
use oneiron::agent_dispatch::{WorkflowToolCursor, WorkflowToolWait};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE, MemoryError};
use oneiron::runtime_hooks::{InvocationId, VerbHookStop};
use oneiron::secret_custody::SECRET_USE_OPERATIONS;
use oneiron::task_verb::sdk::{self, AgentVerb, SecretUseRequest};
use oneiron::task_verb::{HostBinding, verb_hook_boundary};
use oneiron::{
    ContentPart, LlmCapability, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmToolSpec,
    Vault, WriteActor,
};
use serde_json::{Value, json};

use super::super::CHAT_ROLE;
use super::StepHost;
use super::live_lease::LiveLease;
use crate::models::{ModelCallBinding, OfferLadder};

/// The `self.use` verb as the step's tool: providers take letters, digits,
/// `_` and `-` in a tool's name, so the dot becomes `_`.
const SELF_USE_TOOL: &str = "self_use";

/// Finalizes a workflow step's staged capture, when one was staged, with
/// the binding its call returned. A workflow's step call is admitted on the
/// chat role (FIX 6359), so its replays are admitted on that role too.
pub(super) fn finalize_capture(
    staged: Option<oneiron::code_run::WorkflowCaptureHandle>,
    vault: &Vault,
    binding: &ModelCallBinding,
) {
    if let Some(staged) = staged {
        staged.finalize(
            vault,
            binding.rung.clone(),
            CHAT_ROLE,
            binding.route.clone(),
        );
    }
}

/// Puts `self.use` on `request` when every rung of `ladder` takes tool
/// calls and their results; whether it did.
pub(super) fn offer(ladder: &OfferLadder, request: &mut LlmRequest) -> bool {
    let takes = [LlmCapability::ToolCalling, LlmCapability::ToolResults]
        .iter()
        .all(|capability| ladder.supports(&request.model, capability));
    if takes {
        request.tools.push(tool_spec());
    }
    takes
}

/// The tool: the use door's input, its operations the engine's table.
fn tool_spec() -> LlmToolSpec {
    let operations: Vec<&str> = SECRET_USE_OPERATIONS.iter().map(|op| op.name).collect();
    let described = SECRET_USE_OPERATIONS
        .iter()
        .map(|op| format!("{} ({})", op.name, op.what))
        .collect::<Vec<_>>()
        .join("; ");
    LlmToolSpec {
        name: SELF_USE_TOOL.to_owned(),
        description: format!(
            "self.use: hand a masked secret to one trusted operation by its handle, such as \
             sc12, and read the operation's answer, never the secret's value. The operations \
             are: {described}."
        ),
        input_schema: json!({
            "type": "object",
            "properties": {
                "handle": {
                    "type": "string",
                    "description": "The secret's handle, such as sc12, as the text holds it."
                },
                "operation": {
                    "type": "string",
                    "enum": operations,
                    "description": "The operation to hand the secret to."
                },
                "arguments": {
                    "type": "object",
                    "description": "The operation's arguments; {} for one that takes none."
                }
            },
            "required": ["handle", "operation"],
            "additionalProperties": false
        }),
    }
}

/// A pending pre-hook is control flow, never an error result for the model.
pub(super) enum StepToolOutcome {
    Answered(Value, bool),
    HookPending(WorkflowToolWait),
}

pub(super) enum StepConversation {
    Answered {
        response: LlmResponse,
        binding: ModelCallBinding,
        tool_rounds: bool,
        request: LlmRequest,
    },
    HookPending(WorkflowToolWait),
}

pub(super) enum StepConversationFault {
    Model(oneiron::llm::LlmError),
    Checkpoint(oneiron::Error),
}

impl From<oneiron::llm::LlmError> for StepConversationFault {
    fn from(error: oneiron::llm::LlmError) -> Self {
        Self::Model(error)
    }
}

impl From<oneiron::Error> for StepConversationFault {
    fn from(error: oneiron::Error) -> Self {
        Self::Checkpoint(error)
    }
}

/// One step's `self.use`: its vault, the leased try it runs as, its agent,
/// the run its invocations derive from, and the server it sends through
/// once one is bound.
pub(super) struct StepSecretUse<'a> {
    vault: &'a Vault,
    attempt: &'a AttemptRecord,
    actor: WriteActor,
    run: Vec<u8>,
    host: &'a StepHost,
}

impl<'a> StepSecretUse<'a> {
    pub(super) fn new(
        vault: &'a Vault,
        attempt: &'a AttemptRecord,
        actor: WriteActor,
        run_id: &str,
        host: &'a StepHost,
    ) -> Self {
        Self {
            vault,
            attempt,
            actor,
            run: format!("{run_id}/self.use").into_bytes(),
            host,
        }
    }

    /// Asks `ladder` on `run` until an answer calls no tool, answering each
    /// tool call in between; that answer, the binding of the rung that gave
    /// the final answer (FIX 12743) and whether any tool round ran. Each
    /// round is the step's model call again: its
    /// permit, its gate, its meter bounded by `lease`'s live room, and the
    /// same errors end it. The returned request is the final round's: craft
    /// refreshed and tool calls and results appended, the bytes the last
    /// answer goes with.
    pub(super) fn converse(
        &self,
        runtime: &tokio::runtime::Runtime,
        ladder: &OfferLadder,
        run: &RunAdmission,
        lease: &LiveLease<'_>,
        mut request: LlmRequest,
        capture: impl FnOnce(&LlmRequest) -> Option<oneiron::code_run::WorkflowCaptureHandle>,
        continuation: Option<(WorkflowToolCursor, Option<WorkflowToolWait>)>,
        mut save: impl FnMut(
            &LlmRequest,
            &WorkflowToolCursor,
            Option<WorkflowToolWait>,
            Option<(&LlmResponse, &ModelCallBinding)>,
            &[oneiron::EntityId],
        ) -> oneiron::Result<()>,
    ) -> Result<StepConversation, StepConversationFault> {
        let reasoning = ladder.supports(&request.model, &LlmCapability::Reasoning);
        let may_send = || {
            lease.book_and_revise();
            true
        };
        let mut retained = continuation.is_some();
        let (mut cursor, mut waiting) = continuation.unwrap_or((
            WorkflowToolCursor {
                assistant_message: 0,
                tool_index: 0,
                use_ordinal: 0,
                round: 0,
                capture_completed: false,
            },
            None,
        ));
        let mut rounds = retained;
        let mut capture = Some(capture);
        let mut refreshed_sources = Vec::new();
        loop {
            if !retained {
                for source in self.refresh_requester_craft(
                    &mut request,
                    rounds.then_some(&mut cursor.assistant_message),
                ) {
                    if !refreshed_sources.contains(&source) {
                        refreshed_sources.push(source);
                    }
                }
                let staged = if cursor.capture_completed {
                    None
                } else {
                    capture.take().and_then(|capture| capture(&request))
                };
                let generated = runtime.block_on(ladder.generate_recorded_while(
                    run,
                    request.clone(),
                    None,
                    &may_send,
                ));
                let (response, binding) = match generated {
                    Ok(answer) => answer,
                    Err(error) => {
                        if rounds {
                            save(&request, &cursor, None, None, &refreshed_sources)?;
                        }
                        return Err(error.into());
                    }
                };
                if !cursor.capture_completed {
                    finalize_capture(staged, self.vault, &binding);
                    cursor.capture_completed = true;
                }
                if !response
                    .message
                    .content
                    .iter()
                    .any(|part| matches!(part, ContentPart::ToolCall { .. }))
                {
                    if rounds {
                        save(
                            &request,
                            &cursor,
                            None,
                            Some((&response, &binding)),
                            &refreshed_sources,
                        )?;
                    }
                    return Ok(StepConversation::Answered {
                        response,
                        binding,
                        tool_rounds: rounds,
                        request,
                    });
                }
                rounds = true;
                lease.book_and_revise();
                let content = response
                    .message
                    .content
                    .into_iter()
                    .filter(|part| reasoning || !matches!(part, ContentPart::Reasoning { .. }))
                    .collect();
                cursor.assistant_message = request.messages.len();
                cursor.tool_index = 0;
                cursor.round = cursor
                    .round
                    .checked_add(1)
                    .ok_or(oneiron::Error::ArithmeticOverflow("workflow tool round"))?;
                request.messages.push(LlmMessage {
                    role: LlmMessageRole::Assistant,
                    content,
                });
                // Keep the paid assistant tail before the first tool can run.
                save(&request, &cursor, None, None, &refreshed_sources)?;
            }
            let assistant = request
                .messages
                .get(cursor.assistant_message)
                .filter(|message| message.role == LlmMessageRole::Assistant)
                .ok_or_else(|| {
                    oneiron::Error::InvalidConfig("workflow tool message is missing".to_owned())
                })?;
            let calls: Vec<(String, String, Value)> = assistant
                .content
                .iter()
                .filter_map(|part| match part {
                    ContentPart::ToolCall {
                        call_id,
                        name,
                        input,
                        ..
                    } => Some((call_id.clone(), name.clone(), input.clone())),
                    _ => None,
                })
                .collect();
            if cursor.tool_index > calls.len() {
                return Err(oneiron::Error::InvalidConfig(
                    "workflow tool cursor is past its calls".to_owned(),
                )
                .into());
            }
            for (index, (call_id, name, input)) in
                calls.into_iter().enumerate().skip(cursor.tool_index)
            {
                let prior_wait = waiting.take();
                let outcome = if name == SELF_USE_TOOL {
                    let invocation = if let Some(wait) = prior_wait {
                        Some(wait.invocation)
                    } else {
                        cursor.use_ordinal = cursor
                            .use_ordinal
                            .checked_add(1)
                            .ok_or(oneiron::Error::ArithmeticOverflow("workflow tool ordinal"))?;
                        None
                    };
                    self.use_once(input, cursor.use_ordinal, invocation)
                } else {
                    let (output, is_error) = refusal(&MemoryError::bad_request_with(
                        format!("{name} is not a tool of this step"),
                        &["Call self_use, the one tool this step has."],
                    ));
                    StepToolOutcome::Answered(output, is_error)
                };
                match outcome {
                    StepToolOutcome::HookPending(wait) => {
                        save(
                            &request,
                            &cursor,
                            Some(wait.clone()),
                            None,
                            &refreshed_sources,
                        )?;
                        return Ok(StepConversation::HookPending(wait));
                    }
                    StepToolOutcome::Answered(output, is_error) => {
                        request.messages.push(LlmMessage {
                            role: LlmMessageRole::Tool,
                            content: vec![ContentPart::ToolResult {
                                call_id,
                                output,
                                is_error,
                            }],
                        });
                        cursor.tool_index = index + 1;
                        // Cursor==calls is a durable point before the next model call.
                        save(&request, &cursor, None, None, &refreshed_sources)?;
                    }
                }
            }
            retained = false;
        }
    }

    /// Re-reads the step's requester craft for the round going out (FIX
    /// 11395): the fresh message takes the old requester craft's slot, a
    /// round that now has craft the start did not gains it after the
    /// instructions, and one that now has none loses it. The planner craft
    /// is the start's, untouched.
    fn refresh_requester_craft(
        &self,
        request: &mut LlmRequest,
        assistant: Option<&mut usize>,
    ) -> Vec<oneiron::EntityId> {
        let at = super::super::unix_now();
        let fresh = super::super::resident_craft::queue_craft(
            self.vault,
            self.attempt.id,
            &self.actor.entity_ref(),
            at,
        );
        let slot = request.messages.iter().position(|message| {
            message.role == LlmMessageRole::System
                && craft_message_entries(&super::super::resident_craft::message_text(message), at)
                    .is_some()
        });
        match (fresh, slot) {
            (Some((craft, rows)), Some(slot)) => {
                request.messages[slot] = craft;
                rows
            }
            (Some((craft, rows)), None) => {
                let at = request
                    .messages
                    .iter()
                    .take_while(|message| message.role == LlmMessageRole::System)
                    .count();
                super::super::resident_craft::join_craft(&mut request.messages, craft);
                if let Some(assistant) = assistant
                    && at <= *assistant
                {
                    *assistant += 1;
                }
                rows
            }
            (None, Some(slot)) => {
                request.messages.remove(slot);
                if let Some(assistant) = assistant
                    && slot < *assistant
                {
                    *assistant -= 1;
                }
                Vec::new()
            }
            (None, None) => Vec::new(),
        }
    }

    /// One `self.use` call's answer or refusal, or a typed pre-hook wait.
    /// A Pending is never sent to the model as a tool error. `ordinal` numbers the
    /// step's uses, so its invocation is the same on every replay of the try.
    fn use_once(&self, input: Value, ordinal: u64, retained: Option<[u8; 16]>) -> StepToolOutcome {
        let answered_refusal = |error: &MemoryError| {
            let (output, is_error) = refusal(error);
            StepToolOutcome::Answered(output, is_error)
        };
        if <SecretUseRequest as serde::Deserialize>::deserialize(&input).is_err() {
            return answered_refusal(&MemoryError::bad_request_with(
                "self_use takes a handle, an operation and the operation's arguments",
                &[
                    "Name the handle as the text holds it, such as sc12, one of the listed \
                     operations, and its arguments object.",
                ],
            ));
        };
        if !self.lease_live() {
            return answered_refusal(&MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "this step no longer holds its lease, so nothing was used",
                &["The step's next try may use the secret again."],
            ));
        }
        let invocation = InvocationId::of_run_step(&self.run, ordinal);
        if retained.is_some_and(|saved| saved != invocation.0) {
            return answered_refusal(&MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "workflow hook invocation changed",
                &["Read this workflow leaf's retained invocation."],
            ));
        }
        let memory = self
            .vault
            .memory(self.actor.entity_ref(), self.actor.actor_class())
            .with_invocation(invocation);
        // The step's leased try is the use's task host, so a secret its run
        // found is the step's to use (FIX 8334). The invocation stays: a
        // held connector call is found again by it.
        let memory = match HostBinding::from_leased(self.attempt, None) {
            Ok(binding) => memory.with_task_host(binding),
            Err(error) if retained.is_some() => return answered_refusal(&error),
            Err(_) => memory,
        };
        // The row's one verb-hook boundary, as a pumped run's `self.use`
        // crosses it: the pre chain may rewrite the args, which pass the
        // row's own input check again, and the post chain reads the answer.
        let verb = AgentVerb::SelfUse.as_str();
        let run = |args| {
            sdk::validate_input(verb, &args)?;
            let request = serde_json::from_value::<SecretUseRequest>(args).map_err(|_| {
                MemoryError::bad_request("self_use's arguments did not read after its hooks")
            })?;
            // A served vault's own door, as a pumped run's `self.use` calls
            // it (FIX 7016); with no server bound, the embedded one. The
            // step's thread is its blocking worker, outside any runtime.
            let answer = match self.host.get().and_then(std::sync::Weak::upgrade) {
                Some(server) => crate::api::self_use_as(&server, &memory, request)?,
                None => sdk::use_secret_as_caller(&memory, request)?,
            };
            serde_json::to_value(&answer).map_err(|_| {
                MemoryError::new(
                    MEMORY_CODE_INTERNAL,
                    "the use's answer could not be read",
                    &["Its receipt is on the vault's Gate record."],
                )
            })
        };
        let answered = if retained.is_some() {
            verb_hook_boundary::row_retained(&memory, verb, input, run)
        } else {
            verb_hook_boundary::row(&memory, verb, input, run)
        };
        match answered {
            Ok(output) => StepToolOutcome::Answered(output, false),
            Err(error) => {
                if let Some(VerbHookStop::Pending {
                    invocation: saved,
                    ask,
                }) = error.hook.as_deref()
                    && saved == &invocation.to_hex()
                    && let Ok(ask) = oneiron::EntityId::from_hex(ask)
                {
                    return StepToolOutcome::HookPending(WorkflowToolWait {
                        invocation: invocation.0,
                        ask,
                    });
                }
                answered_refusal(&error)
            }
        }
    }

    /// Whether the try this step runs as still holds the lease it was
    /// claimed under.
    fn lease_live(&self) -> bool {
        matches!(
            AttemptQueue::new(self.vault).get(self.attempt.id),
            Ok(Some(row)) if row.state == AttemptState::Leased
                && row.lease_owner == self.attempt.lease_owner
                && row.attempt_count == self.attempt.attempt_count
        )
    }
}

/// A refusal as a tool result: the door's typed error, marked as one.
fn refusal(error: &MemoryError) -> (Value, bool) {
    let output = serde_json::to_value(error).unwrap_or_else(|_| {
        json!({
            "code": error.code,
            "message": error.message,
        })
    });
    (output, true)
}
