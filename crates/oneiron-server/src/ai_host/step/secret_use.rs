//! `self.use` on a saved-workflow text step (FIX 2315). A step whose
//! context holds a masked secret's handle (`sc<n>`) may hand it to one of
//! the engine's table operations and read the operation's answer, never the
//! value. Each call goes through the use door
//! ([`sdk::use_secret_as_caller`]) as the step's own agent while the step
//! still holds its lease, under an invocation derived from the step's run,
//! the same on every replay of the try. It crosses the row's verb-hook
//! boundary ([`verb_hook_boundary::row`]) as a pumped run's `self.use`
//! does, so the owner's verb hooks fire once around it: a pre-hook's skip
//! (or any other stop) goes back to the model as the tool's error result,
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

use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, AttemptState};
use oneiron::llm::run_admission::RunAdmission;
use oneiron::memory::{MEMORY_CODE_INTERNAL, MEMORY_CODE_INVALID_STATE, MemoryError};
use oneiron::runtime_hooks::InvocationId;
use oneiron::secret_custody::SECRET_USE_OPERATIONS;
use oneiron::task_verb::sdk::{self, AgentVerb, SecretUseRequest};
use oneiron::task_verb::verb_hook_boundary;
use oneiron::{
    ContentPart, LlmCapability, LlmMessage, LlmMessageRole, LlmRequest, LlmResponse, LlmResult,
    LlmToolSpec, ModelId, Vault, WriteActor,
};
use serde_json::{Value, json};

use super::StepHost;
use super::live_lease::LiveLease;
use crate::models::OfferLadder;

/// The `self.use` verb as the step's tool: providers take letters, digits,
/// `_` and `-` in a tool's name, so the dot becomes `_`.
const SELF_USE_TOOL: &str = "self_use";

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
    /// tool call in between; that answer, the rung that gave it and whether
    /// any tool round ran. Each round is the step's model call again: its
    /// permit, its gate, its meter bounded by `lease`'s live room, and the
    /// same errors end it.
    pub(super) fn converse(
        &self,
        runtime: &tokio::runtime::Runtime,
        ladder: &OfferLadder,
        run: &RunAdmission,
        lease: &LiveLease<'_>,
        mut request: LlmRequest,
    ) -> LlmResult<(LlmResponse, ModelId, bool)> {
        // A rung that cannot read reasoning back is never sent it.
        let reasoning = ladder.supports(&request.model, &LlmCapability::Reasoning);
        let may_send = || {
            lease.book_and_revise();
            true
        };
        let mut uses = 0_u64;
        let mut rounds = false;
        loop {
            let (response, served) = runtime.block_on(ladder.generate_served_while(
                run,
                request.clone(),
                None,
                &may_send,
            ))?;
            let calls: Vec<(String, String, Value)> = response
                .message
                .content
                .iter()
                .filter_map(|part| match part {
                    ContentPart::ToolCall {
                        call_id,
                        name,
                        input,
                    } => Some((call_id.clone(), name.clone(), input.clone())),
                    _ => None,
                })
                .collect();
            if calls.is_empty() {
                return Ok((response, served, rounds));
            }
            rounds = true;
            // The round's spend goes on the lease before its tools run, so
            // siblings see it meanwhile (FIX 1819).
            lease.book_and_revise();
            let content = response
                .message
                .content
                .into_iter()
                .filter(|part| reasoning || !matches!(part, ContentPart::Reasoning { .. }))
                .collect();
            request.messages.push(LlmMessage {
                role: LlmMessageRole::Assistant,
                content,
            });
            for (call_id, name, input) in calls {
                let (output, is_error) = if name == SELF_USE_TOOL {
                    uses += 1;
                    self.use_once(input, uses)
                } else {
                    refusal(&MemoryError::bad_request_with(
                        format!("{name} is not a tool of this step"),
                        &["Call self_use, the one tool this step has."],
                    ))
                };
                request.messages.push(LlmMessage {
                    role: LlmMessageRole::Tool,
                    content: vec![ContentPart::ToolResult {
                        call_id,
                        output,
                        is_error,
                    }],
                });
            }
        }
    }

    /// One `self.use` call's result: the door's answer, or a refusal marked
    /// as an error, a verb hook's stop among them. `ordinal` numbers the
    /// step's uses, so its invocation is the same on every replay of the try.
    fn use_once(&self, input: Value, ordinal: u64) -> (Value, bool) {
        if <SecretUseRequest as serde::Deserialize>::deserialize(&input).is_err() {
            return refusal(&MemoryError::bad_request_with(
                "self_use takes a handle, an operation and the operation's arguments",
                &[
                    "Name the handle as the text holds it, such as sc12, one of the listed \
                     operations, and its arguments object.",
                ],
            ));
        };
        if !self.lease_live() {
            return refusal(&MemoryError::new(
                MEMORY_CODE_INVALID_STATE,
                "this step no longer holds its lease, so nothing was used",
                &["The step's next try may use the secret again."],
            ));
        }
        let memory = self
            .vault
            .memory(self.actor.entity_ref(), self.actor.actor_class())
            .with_invocation(InvocationId::of_run_step(&self.run, ordinal));
        // The row's one verb-hook boundary, as a pumped run's `self.use`
        // crosses it: the pre chain may rewrite the args, which pass the
        // row's own input check again, and the post chain reads the answer.
        let verb = AgentVerb::SelfUse.as_str();
        let answered = verb_hook_boundary::row(&memory, verb, input, |args| {
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
        });
        match answered {
            Ok(output) => (output, false),
            Err(error) => refusal(&error),
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
