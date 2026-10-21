//! A TASK bound to a library program (CUA E4, FIX 7603; DESIGN-2 §2): its
//! try runs the program its first lease pinned, strict, on the run's own
//! door, before its seat is born. A program that meets its postcondition
//! with every one of the TASK's browser checks holding settles the try on
//! its receipt NOTE with no model call; any other end hands the run to its
//! planner with the receipt named before it. The program runs at the run's
//! first entry alone, and an end it came to is never run again: a later
//! entry reads that end, so its task says the same thing at every entry.

use oneiron::agent_dispatch::{AgentDispatcher, agent_dispatch_actor};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, AttemptResultRef, SetAttemptResult};
use oneiron::code_run::{AgentVerbDoor, HostSelfDispatcher, SelfAgentVerbCall};
use oneiron::dreamer_runner::CompleteDreamerAttempt;
use oneiron::engine_executor::{EngineExecutorError, entered_run};
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron::task_verb::{
    TaskWorkflowAttempt, TaskWorkflowCheck, TaskWorkflowHandoff, TaskWorkflowOutcome,
    TaskWorkflowReport, record_task_workflow_outcome, runner_done_question,
    runner_workflow_done_answer, task_workflow_binding,
};
use oneiron::{DreamerRunnerStore, EntityId, Vault, WriteActor};
use oneiron_browser::{ExpectInput, ExpectOutput};

use super::{Claimed, LEASE_OWNER};
use crate::api::{WorkflowPreflight, preflight_task_workflow};
use crate::decision_host::DecisionHost;
use crate::mcp::EngineRunError;

/// What a bound try's program came to before its seat is born.
pub(super) enum BeforeSeat {
    /// No program is owed now: the run goes on as an unbound one would.
    Unbound,
    /// The program and the TASK's checks held: the try settles on this
    /// receipt NOTE with no model call.
    Done(EntityId),
    /// The planner takes the run, with this put after its task.
    Handoff(String),
}

/// Runs `attempt`'s pinned program before its seat is born, through `door`,
/// the run's own, and records what it came to. A run that realizes no bound
/// TASK, or whose pin does not read, goes on as today; a pin that came to an
/// end already gives that end; a program owed at a later entry is not run.
///
/// # Errors
///
/// The door's own failure, so a provider outage parks the run as any of
/// its calls would.
pub(super) fn before_seat(
    vault: &Vault,
    door: &dyn AgentVerbDoor,
    actor: WriteActor,
    attempt: &AttemptRecord,
    run_id: EntityId,
    now: u64,
) -> Result<BeforeSeat, EngineRunError> {
    if attempt.task_ref.is_none() {
        return Ok(BeforeSeat::Unbound);
    }
    let (dispatcher, binding, pinned) = match bound_try(vault, actor, attempt) {
        Ok(Some(bound)) => bound,
        Ok(None) => return Ok(BeforeSeat::Unbound),
        Err(error) => {
            tracing::warn!(%error, attempt = ?attempt.id, "a try's library program pin did not read; it runs as an unbound try");
            return Ok(BeforeSeat::Unbound);
        }
    };
    match pinned.outcome() {
        TaskWorkflowOutcome::Done { receipt_ref } => return Ok(BeforeSeat::Done(*receipt_ref)),
        TaskWorkflowOutcome::Handoff { cause, receipt_ref } => {
            return Ok(BeforeSeat::Handoff(handoff_text(
                &pinned,
                cause,
                *receipt_ref,
            )));
        }
        TaskWorkflowOutcome::Pending => {}
    }
    // A run that entered before its end was recorded ran its first entry
    // without the program: running it now would say something new to a run
    // whose task its record holds.
    if !matches!(entered_run(vault, run_id), Ok(None)) {
        return Ok(BeforeSeat::Unbound);
    }
    let report = match pinned.active() {
        None => TaskWorkflowReport::Unavailable,
        Some((record, args)) => {
            let origin = match dispatcher.browser_origin_from_host(AgentVerb::SelfBrowserLibraryRun)
            {
                Ok(origin) => origin,
                Err(error) => {
                    tracing::warn!(%error, attempt = ?attempt.id, "a bound try's library run has no write origin; it runs as an unbound try");
                    return Ok(BeforeSeat::Unbound);
                }
            };
            match preflight_task_workflow(door, record, args, &origin, InvocationId::mint())? {
                WorkflowPreflight::Done(output) => TaskWorkflowReport::Ran {
                    output,
                    checks: read_checks(door, &dispatcher, &pinned.goal().browser_checks)?,
                },
                WorkflowPreflight::Handoff {
                    stop_cause,
                    receipt,
                } => TaskWorkflowReport::Program {
                    stop_cause,
                    output: receipt,
                },
            }
        }
    };
    // A receipt the try cannot record leaves its end unwritten: the run goes
    // on as an unbound one, and no later entry runs the program again.
    match record_task_workflow_outcome(vault, &binding, report, now) {
        Ok(TaskWorkflowOutcome::Done { receipt_ref }) => Ok(BeforeSeat::Done(receipt_ref)),
        Ok(TaskWorkflowOutcome::Handoff { cause, receipt_ref }) => Ok(BeforeSeat::Handoff(
            handoff_text(&pinned, &cause, receipt_ref),
        )),
        Ok(TaskWorkflowOutcome::Pending) => Ok(BeforeSeat::Unbound),
        Err(error) => {
            tracing::warn!(%error, attempt = ?attempt.id, "a bound try's library program receipt was not recorded; it runs as an unbound try");
            Ok(BeforeSeat::Unbound)
        }
    }
}

/// `attempt`'s dispatcher, its TASK binding and its pin, read under its
/// lease. `None` when the try realizes no TASK or pins no program.
fn bound_try<'a>(
    vault: &'a Vault,
    actor: WriteActor,
    attempt: &AttemptRecord,
) -> oneiron::Result<
    Option<(
        HostSelfDispatcher<'a>,
        oneiron::task_verb::HostBinding,
        TaskWorkflowAttempt,
    )>,
> {
    let dispatcher = HostSelfDispatcher::for_leased_agent_attempt(vault, actor, attempt)?;
    let Some(binding) = dispatcher.task_host_binding()? else {
        return Ok(None);
    };
    let Some(pinned) = task_workflow_binding(vault, &binding)? else {
        return Ok(None);
    };
    Ok(Some((dispatcher, binding, pinned)))
}

/// Reads each of the TASK's browser checks on the page the program left,
/// through the run's own door, in the pinned order. A check the door
/// refuses holds nothing: it reads as unmet, with no row.
fn read_checks(
    door: &dyn AgentVerbDoor,
    dispatcher: &HostSelfDispatcher<'_>,
    checks: &[ExpectInput],
) -> Result<Vec<TaskWorkflowCheck>, EngineRunError> {
    let mut read = Vec::with_capacity(checks.len());
    for expect in checks {
        let observed = match dispatcher.browser_origin_from_host(AgentVerb::SelfBrowserExpect) {
            Ok(origin) => {
                let call = SelfAgentVerbCall {
                    verb: AgentVerb::SelfBrowserExpect,
                    input: serde_json::to_value(expect)
                        .map_err(|error| EngineRunError::Binding(error.to_string()))?,
                };
                match door.call(&call, &origin, InvocationId::mint()) {
                    Ok(Ok(answer)) => {
                        serde_json::from_value(answer.output).unwrap_or_else(|error| {
                            tracing::warn!(%error, "a TASK browser check's answer does not read; it is unmet");
                            unmet()
                        })
                    }
                    Ok(Err(refusal)) => {
                        tracing::warn!(code = %refusal.code, "a TASK browser check was refused; it is unmet");
                        unmet()
                    }
                    Err(error) => {
                        return Err(EngineRunError::Run(EngineExecutorError::Engine(error)));
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "a TASK browser check has no write origin; it is unmet");
                unmet()
            }
        };
        read.push(TaskWorkflowCheck {
            expect: expect.clone(),
            observed,
        });
    }
    Ok(read)
}

/// A check no page answered.
fn unmet() -> ExpectOutput {
    ExpectOutput {
        met: false,
        row: None,
        partial: None,
        rebindings: Vec::new(),
    }
}

/// What the planner reads after its task when the try's program handed it
/// the run: built from the recorded end alone, so every entry says the same.
fn handoff_text(
    pinned: &TaskWorkflowAttempt,
    cause: &TaskWorkflowHandoff,
    receipt: EntityId,
) -> String {
    let typed = serde_json::to_string(cause).unwrap_or_else(|_| cause.code().to_owned());
    format!(
        "\n\nThis TASK binds library program workflow:{}. It ran strict on this run's browser before you, and handed off: {} ({typed}). Its whole receipt, with the failed step, the checks that did not hold and what the page showed, is NOTE {}: read it, then finish the TASK from the page as it stands.",
        pinned.requested().to_hex(),
        cause.code(),
        receipt.to_hex(),
    )
}

/// Settles a try whose program met its TASK's goal with no model call: its
/// receipt NOTE is its result. A goal of browser checks alone is Done with no
/// question asked (Engine C1); any other goal's judge reads the receipt, as
/// it reads a run's result today.
pub(super) fn complete(
    vault: &Vault,
    decisions: &DecisionHost,
    claimed: &Claimed,
    receipt: EntityId,
    now: u64,
) -> oneiron::Result<()> {
    let attempt = &claimed.status.attempt;
    AttemptQueue::new(vault).set_result(SetAttemptResult {
        id: attempt.id,
        lease_owner: LEASE_OWNER.to_owned(),
        attempt_count: attempt.attempt_count,
        result_ref: AttemptResultRef::new(receipt.to_hex())?,
        now,
    })?;
    let actor = agent_dispatch_actor(&claimed.status.input)?;
    let binding =
        HostSelfDispatcher::for_leased_agent_attempt(vault, actor, attempt)?.task_host_binding()?;
    let typed = match &binding {
        Some(binding) => runner_workflow_done_answer(vault, binding)?,
        None => None,
    };
    let judged = match typed {
        Some(answer) => Some(answer),
        None => runner_done_question(vault, attempt.id)?.and_then(|question| {
            match decisions.task_decisions() {
                Ok(decisions) => Some(question.decide(&decisions)),
                Err(error) => {
                    tracing::warn!(%error, "the task surface's questions are invalid; Done asks up");
                    None
                }
            }
        }),
    };
    DreamerRunnerStore::new(vault).complete_with_confession(
        CompleteDreamerAttempt {
            id: attempt.id,
            lease_owner: LEASE_OWNER.to_owned(),
            attempt_count: attempt.attempt_count,
            now,
        },
        judged,
        None,
    )?;
    AgentDispatcher::new(vault).settle_child(&attempt.id, now)?;
    Ok(())
}
