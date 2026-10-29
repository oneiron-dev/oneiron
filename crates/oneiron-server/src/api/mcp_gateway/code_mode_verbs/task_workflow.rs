//! The strict library try a TASK-bound browser program takes before its
//! run's planner (CUA E4; owner pick C1 = A: the library record is the one
//! body, and a TASK binds it by `workflow:<id>` and its arguments).
//!
//! An agent TASK whose brief binds a library program gets one strict
//! `self.browser.library.run` of it before any planner or model call: only
//! a rule answers its routine steps, and a step only a model could answer
//! goes up at zero tokens. The try goes through the run's own door, so the
//! row's verb hooks, the vault's grants, the browser pack's admission, the
//! run's guest and its receipt writer are those of any browser call the
//! run makes; nothing here reads the library or drives the guest itself.
//!
//! A miss never refuses the TASK: it hands up to the planner with what
//! stopped the run, and the run's answer when it ran. Whether the TASK's
//! own done-means hold is the caller's to check after a `Done`.

use std::collections::BTreeMap;

use oneiron::EntityId;
use oneiron::code_run::{AgentVerbDoor, SelfAgentVerbCall};
use oneiron::engine_executor::EngineExecutorError;
use oneiron::memory::HostWriteOrigin;
use oneiron::runtime_hooks::InvocationId;
use oneiron::task_verb::sdk::AgentVerb;
use oneiron_browser::{
    BatchStopCause, LibraryRunInput, LibraryRunMode, LibraryRunOutput, SecretArg, SubgoalStatus,
};

use crate::mcp::EngineRunError;

/// The code a preflight hands up with when no cause of the try's own can
/// be carried (CUA E4, CALLS row): its call's input did not encode, the
/// door's answer does not read as a library run, or the run stopped short
/// of done with a batch that names neither a stop cause nor a code.
const PREFLIGHT_UNSTATED: &str = "library_run_unstated";

/// What a TASK-bound program's strict try came to.
#[derive(Debug, Clone)]
pub(crate) enum WorkflowPreflight {
    /// The program ran strict and met its postcondition. Its `model_free`
    /// says, from the run's receipts, whether any model answered; the
    /// TASK's own done-means are still the caller's to check.
    Done(LibraryRunOutput),
    /// The program did not finish, and the run goes to its planner with
    /// what stopped it. `receipt` is the library run's answer when it ran:
    /// its batch's failed-step receipt names the Expect it missed and what
    /// the page showed. It is none when the door refused the call before
    /// it ran (a retired or missing program, a gate, a guest that would
    /// not start), and `stop_cause` names the refusal's code as
    /// [`BatchStopCause::Browser`].
    Handoff {
        stop_cause: BatchStopCause,
        receipt: Option<LibraryRunOutput>,
    },
}

/// One strict try of the library program `workflow` with `args`, made
/// before any planner call of the TASK-bound run whose door, write origin
/// and step invocation these are (CUA E4).
///
/// The contract: the program runs once, strict, through `door` as the
/// run's own `self.browser.library.run`, so no model is asked; a miss of
/// any kind hands up and never refuses. The try ends in
/// - [`WorkflowPreflight::Done`] when the run met its postcondition;
/// - [`WorkflowPreflight::Handoff`] with the run's answer when it stopped
///   short, naming the batch's stop cause, else its failed-step receipt's.
///   A strict step only a model could answer stops it `decider_asked_up`
///   (`strict`) at zero tokens, by design;
/// - [`WorkflowPreflight::Handoff`] with no answer when the door refused
///   the call before it ran, naming the refusal's code as
///   [`BatchStopCause::Browser`].
///
/// It does not read the TASK's done-means: after `Done` the caller checks
/// them through the same door.
///
/// # Errors
///
/// The door's own stop, which the run parks or ends on as it does for any
/// of its calls: a verb hook's stop, or a model call no provider answered
/// (`ProviderUnavailable`, read by [`EngineRunError::provider_outage`]).
pub(crate) fn preflight_task_workflow(
    door: &dyn AgentVerbDoor,
    workflow: EntityId,
    args: &BTreeMap<String, String>,
    secret_args: &BTreeMap<String, SecretArg>,
    origin: &HostWriteOrigin,
    invocation: InvocationId,
) -> Result<WorkflowPreflight, EngineRunError> {
    let input = LibraryRunInput {
        workflow: workflow.to_hex(),
        args: args.clone(),
        base: None,
        mode: Some(LibraryRunMode::Strict),
        secret_args: secret_args.clone(),
    };
    let input = match serde_json::to_value(input) {
        Ok(input) => input,
        Err(error) => return Ok(unread(workflow, &error)),
    };
    let call = SelfAgentVerbCall {
        verb: AgentVerb::SelfBrowserLibraryRun,
        input,
    };
    let answer = match door.call(&call, origin, invocation) {
        Ok(Ok(answer)) => answer,
        // The call never ran: the planner takes the run, with the refusal.
        Ok(Err(refusal)) => {
            return Ok(WorkflowPreflight::Handoff {
                stop_cause: BatchStopCause::Browser { code: refusal.code },
                receipt: None,
            });
        }
        Err(error) => return Err(EngineRunError::Run(EngineExecutorError::Engine(error))),
    };
    // The door adds the engine, a takeover and a tab move beside the run's
    // own answer; the run's answer is read alone.
    let output: LibraryRunOutput = match serde_json::from_value(answer.output) {
        Ok(output) => output,
        Err(error) => return Ok(unread(workflow, &error)),
    };
    if output.status == SubgoalStatus::Done {
        return Ok(WorkflowPreflight::Done(output));
    }
    let batch = &output.batch;
    let stop_cause = batch
        .stop_cause
        .clone()
        .or_else(|| {
            batch
                .failed_receipt
                .as_ref()
                .map(|failed| failed.stop_cause.clone())
        })
        .unwrap_or_else(|| BatchStopCause::Browser {
            code: batch
                .error
                .clone()
                .unwrap_or_else(|| PREFLIGHT_UNSTATED.to_owned()),
        });
    Ok(WorkflowPreflight::Handoff {
        stop_cause,
        receipt: Some(output),
    })
}

/// The hand-up of a try whose call could not be written or whose answer
/// could not be read: the planner takes the run, naming
/// [`PREFLIGHT_UNSTATED`].
fn unread(workflow: EntityId, error: &serde_json::Error) -> WorkflowPreflight {
    tracing::warn!(
        %error,
        workflow = %workflow.to_hex(),
        "a TASK-bound program's strict library run was not read"
    );
    WorkflowPreflight::Handoff {
        stop_cause: BatchStopCause::Browser {
            code: PREFLIGHT_UNSTATED.to_owned(),
        },
        receipt: None,
    }
}
