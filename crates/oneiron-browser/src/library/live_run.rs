//! A library run (CUA E2): strict, where only a rule answers its routine
//! steps and a step only a model could answer goes up with no model asked,
//! or assisted, where the decision ladder answers as for any routine step;
//! whether a model answered any of its decisions, read from their receipts;
//! and what the library counts of it.

#[cfg(feature = "driver")]
use super::{LibraryRunInput, LibraryRunOutput, SecretArg, WorkflowLibrary, missed};
use super::{WorkflowProgram, WorkflowProof};
#[cfg(feature = "driver")]
use crate::{
    BatchInput, BrowserDriver, BrowserError, CheckReceipt, FailedStepReceipt, FieldWriter,
    ObserveInput, RoutineDecider, StepStop, SubgoalStatus, stop::elapsed_ms,
};
use crate::{BatchStopCause, FIELD_WRITER, STRICT_DENIED, StrictDenied};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How a library run takes its routine steps' decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LibraryRunMode {
    /// Only a rule answers: a step only a model could answer goes up to the
    /// planner (`decider_asked_up`, `strict`) before any model is asked.
    Strict,
    /// The decision ladder answers, a model's rung included.
    Assisted,
}

/// A filed program as a run reads it: the program, and the proof its
/// admission kept.
#[derive(Clone, Debug)]
pub struct FiledWorkflow {
    pub program: WorkflowProgram,
    pub proof: WorkflowProof,
}

/// One library run as the library counts it: its mode, whether it met its
/// postcondition, and what stopped it when it did not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunOutcome {
    pub mode: LibraryRunMode,
    pub done: bool,
    pub stop_cause: Option<BatchStopCause>,
}

/// The rung a rule answers at, as a decision's receipt names it.
const RULE_RUNG: &str = "rule";

/// The rung a person answers at: no model either.
const HUMAN_RUNG: &str = "human";

/// The code a library run's missed postcondition stops with.
#[cfg(feature = "driver")]
const POSTCONDITION_UNMET: &str = "postcondition_unmet";

/// The mode a run takes: the one asked, else the program's own.
#[must_use]
pub fn effective_mode(asked: Option<LibraryRunMode>, proof: &WorkflowProof) -> LibraryRunMode {
    asked.unwrap_or_else(|| default_mode(proof))
}

/// A program's own mode (CUA E2 default mode, CALLS row; Engine 10-21
/// 23:4x): strict when its admission's replay held values out from the
/// solved run's and a rule answered each of that replay's decisions (so,
/// too, when it took none); else assisted. A program shown on the solved
/// run's values only is never strict by default.
#[must_use]
pub fn default_mode(proof: &WorkflowProof) -> LibraryRunMode {
    let ruled = proof
        .replay_decisions
        .iter()
        .all(|decision| decision.get("rung").and_then(Value::as_str) == Some(RULE_RUNG));
    if proof.held_out && ruled {
        LibraryRunMode::Strict
    } else {
        LibraryRunMode::Assisted
    }
}

/// Whether no model answered any of `decisions` (CUA E2 `model_free`, CALLS
/// row), read from each decision's record and never from a mode: every
/// provider pin its receipt names (its providers, and those of its paired,
/// person and image readings), those of its presence step's receipt, and
/// the rung that answered, is the rule rung's or a person's. A model rung
/// that ran counts even where the decision then abstained. A strict
/// decision no rung gave a receipt for ([`StrictDenied`]) asked no model
/// and spent nothing. A Fill's writer call ([`FIELD_WRITER`]) is a model's
/// (CUA E6).
///
/// # Errors
///
/// The index of the first decision whose record shows neither its rungs nor
/// a strict denial: missing evidence proves nothing.
pub fn model_free(decisions: &[Value]) -> Result<bool, usize> {
    let mut free = true;
    for (index, decision) in decisions.iter().enumerate() {
        free &= decision_model_free(decision).ok_or(index)?;
    }
    Ok(free)
}

/// One decision's [`model_free`] reading; none when its record shows
/// neither its rungs nor a strict denial at zero tokens.
fn decision_model_free(decision: &Value) -> Option<bool> {
    if decision.get(FIELD_WRITER).is_some() {
        return Some(false);
    }
    if let Some(denied) = decision.get(STRICT_DENIED) {
        let denied = StrictDenied::deserialize(denied).ok()?;
        return (denied.tokens == 0).then_some(true);
    }
    let mut free = receipt_model_free(decision.get("receipt")?)?;
    if let Some(presence) = present(decision, "presence") {
        free &= receipt_model_free(presence.get("receipt")?)?;
    }
    if let Some(rung) = present(decision, "rung") {
        free &= rung_model_free(rung.as_str()?);
    }
    Some(free)
}

/// One receipt's [`model_free`] reading; none when it lists no providers,
/// or a pin names no rung.
fn receipt_model_free(receipt: &Value) -> Option<bool> {
    let mut rungs = Vec::new();
    for pin in receipt.get("providers")?.as_array()? {
        rungs.push(pin.get("rung")?);
    }
    for readings in ["paired", "person", "images"] {
        let Some(rows) = present(receipt, readings) else {
            continue;
        };
        for row in rows.as_array()? {
            rungs.push(row.get("provider")?.get("rung")?);
        }
    }
    if let Some(time) = present(receipt, "time")
        && let Some(answered) = present(time, "answered")
    {
        rungs.push(answered);
    }
    let mut free = true;
    for rung in rungs {
        free &= rung_model_free(rung.as_str()?);
    }
    Some(free)
}

/// The field `name` of `value`, when it holds one that is not null.
fn present<'v>(value: &'v Value, name: &str) -> Option<&'v Value> {
    value.get(name).filter(|field| !field.is_null())
}

/// Whether `rung` is no model's: the rule rung, or a person.
fn rung_model_free(rung: &str) -> bool {
    matches!(rung, RULE_RUNG | HUMAN_RUNG)
}

#[cfg(feature = "driver")]
/// Whether `batch` went up for no progress only once its last step ran
/// (FIX 8507): every effect of its `steps` landed, so its checks decide.
pub(super) fn no_progress_at_end(batch: &crate::BatchOutput, steps: usize) -> bool {
    batch.stop_cause == Some(BatchStopCause::NoProgress) && batch.completed == steps
}

#[cfg(feature = "driver")]
/// `batch`, whose checks all met after its no-progress stop at its end,
/// as done (FIX 8507); the driver's history withdraws that stop, so a
/// draft of the run reads its steps as working.
pub(super) fn met_after_all<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    batch: &mut crate::BatchOutput,
) {
    batch.status = SubgoalStatus::Done;
    batch.failed_step = None;
    batch.error = None;
    batch.stop_cause = None;
    batch.failed_receipt = None;
    driver.withdraw_no_progress();
}

#[cfg(feature = "driver")]
/// A run's arguments with its typed secret arguments in their place (FIX
/// 8346), and the names whose value is their slot's own text.
fn typed_args(
    input: &LibraryRunInput,
) -> Result<(std::collections::BTreeMap<String, String>, Vec<String>), BrowserError> {
    let mut args = input.args.clone();
    let mut text = Vec::new();
    for (name, arg) in &input.secret_args {
        let value = match arg {
            SecretArg::Handle(handle) if super::handle_form(handle) => handle.clone(),
            SecretArg::Handle(_) => {
                return Err(BrowserError::Input(format!(
                    "the secret argument {name}'s handle names no handle"
                )));
            }
            SecretArg::Text(value) => {
                text.push(name.clone());
                value.clone()
            }
        };
        args.insert(name.clone(), value);
    }
    Ok((args, text))
}

#[cfg(feature = "driver")]
/// Runs a library program live in its mode, its Fill steps' generation
/// through `writer`, then checks its postcondition on the page. A run that
/// missed it goes back to the planner with each check it missed, what its
/// read found, and the page.
pub(crate) fn run<D: BrowserDriver + ?Sized>(
    driver: &mut D,
    library: &mut dyn WorkflowLibrary,
    decider: &mut dyn RoutineDecider,
    writer: &dyn FieldWriter,
    input: LibraryRunInput,
) -> Result<LibraryRunOutput, BrowserError> {
    let started = std::time::Instant::now();
    let Some(FiledWorkflow { program, proof }) = library.program(&input.workflow)? else {
        // A retire the library's record proves answers its own code (FIX
        // 8073); a program it holds no record of stays missing.
        let workflow = input.workflow.clone();
        return Err(if library.is_retired(&workflow)? {
            BrowserError::WorkflowRetired(workflow)
        } else {
            BrowserError::NoWorkflow(workflow)
        });
    };
    let mode = effective_mode(input.mode, &proof);
    let (args, text) = typed_args(&input)?;
    let (steps, checks) = super::secret_slots::as_text(&program, &text).fill(&args)?;
    let step_count = steps.len();
    let mut batch = driver.batch_with(
        BatchInput {
            subgoal: Some(program.subgoal.clone()),
            steps,
            base: input.base.clone(),
            until_ms: None,
            no_model: mode == LibraryRunMode::Strict,
        },
        decider,
        writer,
    )?;
    // A run that went up for no progress after its last step still meets
    // its checks, read now (FIX 8507): all met, it is done; else it goes
    // up as it went, with what each missed check found.
    let at_end = no_progress_at_end(&batch, step_count);
    let misses = if batch.status == SubgoalStatus::Done || at_end {
        missed(driver, &checks)?
    } else {
        Vec::new()
    };
    let unmet: Vec<usize> = misses.iter().map(|(index, _)| *index).collect();
    if at_end {
        if misses.is_empty() {
            met_after_all(driver, &mut batch);
        } else if let Some(failed) = batch.failed_receipt.as_mut() {
            failed.missed = misses.into_iter().map(|(_, check)| check).collect();
        }
    } else if !misses.is_empty() {
        // A missed postcondition goes back to the planner, with each check
        // it missed and the page. Checks a cut tree left unproven are no
        // miss on their own.
        let misses: Vec<CheckReceipt> = misses.into_iter().map(|(_, check)| check).collect();
        let cause = if misses.iter().all(CheckReceipt::unproven) {
            BatchStopCause::IncompleteObservation
        } else {
            BatchStopCause::PostconditionUnmet
        };
        let observation = driver.observe(ObserveInput {
            base: input.base,
            ..ObserveInput::default()
        })?;
        let code = POSTCONDITION_UNMET.to_owned();
        // The session's history notes the miss after the run's steps (CUA
        // E7), so a draft of them never takes the run for one that worked.
        driver.note_stop(StepStop {
            step: "postcondition".to_owned(),
            cause: cause.clone(),
            error: code.clone(),
            receipt: None,
            effect_class: None,
        });
        batch.status = SubgoalStatus::NeedsAgent;
        batch.error = Some(code.clone());
        batch.stop_cause = Some(cause.clone());
        batch.failed_receipt = Some(FailedStepReceipt {
            step: None,
            stop_cause: cause,
            missed: misses,
            observation: Some(observation.clone()),
            error: Some(code),
            refusal: None,
            next: None,
        });
        batch.observation = Some(observation);
    }
    // The run's time ends with its checks, before the library counts it.
    batch.elapsed_ms = elapsed_ms(started);
    let (free, unproven) = match model_free(&batch.decisions) {
        Ok(free) => (free, None),
        Err(index) => (false, Some(index)),
    };
    let outcome = RunOutcome {
        mode,
        done: batch.status == SubgoalStatus::Done,
        stop_cause: batch.stop_cause.clone(),
    };
    library.record_run(&input.workflow, &outcome)?;
    Ok(LibraryRunOutput {
        workflow: input.workflow,
        status: batch.status,
        mode,
        model_free: free,
        model_free_unproven: unproven,
        unmet,
        batch,
    })
}
