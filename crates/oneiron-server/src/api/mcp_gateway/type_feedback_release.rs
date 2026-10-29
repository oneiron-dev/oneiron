//! Type feedback leaves an MCP answer on its own release (FIX 10390, CALLS
//! "feedback released apart from its answer"). The answer is released as it
//! stands without its feedback, under every check it meets today; each
//! step's feedback is then judged alone for the same destination, by the
//! rows the answer was derived from and every row the feedback names, with
//! the scan its carrier always had. A hold, or a check that cannot run,
//! withholds only that feedback's text, as its typed withheld projection:
//! the answer's status, steps, results, resume data and carrier stay as
//! released, and the step's row stays whole. A failed run's refusal carries
//! its kept feedback the same way (FIX 10389).
//!
//! The carriers are the known typed ones, each found by the host's own
//! record of what it is, never by its JSON's shape: an `execute_code`
//! answer's `program_steps`, a wait set's answer among its bridge steps, the
//! owner's feedback read, a run's history, a session-bound run's entry and
//! a foreign program's run (FIX 10389), called directly or from inside the
//! run. A foreign program's refusal keeps its program's feedback beside it
//! ([`source_run_error`]).

use super::{McpCallContext, McpGatewayError};
use crate::api::type_feedback_release::{
    FOREIGN_EXECUTE_CODE_VERB, FeedbackScan, OFF_RECORD_EXECUTE_VERB, program_steps_of,
    put_program_step, release_step_feedback,
};
use crate::server::SyncServer;
use oneiron::EntityId;
use oneiron::code_run::{
    CodeRunBridgeCall, CodeRunReplayRecord, KeptProgramSteps, ProgramPreparationNote,
    ProgramStepFeedback, ProgramStepFeedbackRelease, ProgramStepIdentity, SelfEffect,
    TYPE_FEEDBACK_NOT_KEPT, TaskWaitSetResult, TypeDiagnostics,
};
use oneiron::memory::foreign_code::ForeignCodeFailure;
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// The owner's read of one step's feedback.
const OWNER_FEEDBACK_VERB: &str = "vault.code.type_diagnostics";
/// A run's history, each step's feedback beside it.
const HISTORY_VERB: &str = "self.history";

/// A known typed carrier of step feedback.
#[derive(Clone, Copy)]
enum Carrier {
    /// A wait set's answer: its settled children's `program_steps`.
    WaitSet,
    /// The owner's read of one step's feedback: the whole answer.
    Owner,
    /// A run's history: each step's `type_diagnostics` and
    /// `preparation_note`.
    History,
    /// A door's answer carrying its run's `program_steps`, each released
    /// whole by its door: a session-bound run's entry, a foreign program's
    /// run.
    ProgramSteps,
}

impl Carrier {
    /// `value` without its feedback, and each feedback by its slot; `None`
    /// when it carries none, or not in the form its type gives it.
    fn take(self, value: &Value) -> Option<(Value, Vec<(usize, ProgramStepFeedback)>)> {
        match self {
            Self::WaitSet => {
                let answer: TaskWaitSetResult = serde_json::from_value(value.clone()).ok()?;
                if answer.program_steps.is_empty() {
                    return None;
                }
                let mut base = value.clone();
                base.as_object_mut()?.shift_remove("program_steps");
                Some((base, answer.program_steps.into_iter().enumerate().collect()))
            }
            Self::Owner => {
                match serde_json::from_value::<ProgramStepFeedbackRelease>(value.clone()).ok()? {
                    ProgramStepFeedbackRelease::Released(feedback) => {
                        Some((Value::Null, vec![(0, feedback)]))
                    }
                    ProgramStepFeedbackRelease::Withheld { .. } => None,
                }
            }
            Self::History => {
                let run = value.get("run")?.as_str()?;
                let mut feedback = Vec::new();
                for (slot, step) in value.get("steps")?.as_array()?.iter().enumerate() {
                    let Some(diagnostics) = step.get("type_diagnostics") else {
                        continue;
                    };
                    let type_diagnostics: TypeDiagnostics =
                        serde_json::from_value(diagnostics.clone()).ok()?;
                    let preparation_note: Option<ProgramPreparationNote> = step
                        .get("preparation_note")
                        .map(|note| serde_json::from_value(note.clone()))
                        .transpose()
                        .ok()?;
                    let identity = ProgramStepIdentity {
                        run: run.to_owned(),
                        program_seq: step.get("step")?.as_u64()?,
                        invocation: 0,
                    };
                    feedback.push((
                        slot,
                        ProgramStepFeedback {
                            check_ref: identity.check_ref(),
                            step: identity,
                            preparation_note,
                            type_diagnostics,
                        },
                    ));
                }
                if feedback.is_empty() {
                    return None;
                }
                let mut base = value.clone();
                for (slot, _) in &feedback {
                    if let Some(step) = base
                        .get_mut("steps")
                        .and_then(|steps| steps.get_mut(*slot))
                        .and_then(Value::as_object_mut)
                    {
                        step.shift_remove("type_diagnostics");
                        step.shift_remove("preparation_note");
                    }
                }
                Some((base, feedback))
            }
            Self::ProgramSteps => program_steps_of(value),
        }
    }

    /// Puts the withheld projection `withheld` in place of the feedback at
    /// `slot` of `value`, the carrier as it was recorded.
    fn put(self, value: &mut Value, slot: usize, withheld: Value) {
        match self {
            Self::WaitSet => {
                if let Some(item) = value
                    .get_mut("program_steps")
                    .and_then(|steps| steps.get_mut(slot))
                {
                    *item = withheld;
                }
            }
            Self::Owner => *value = withheld,
            Self::History => {
                if let Some(step) = value
                    .get_mut("steps")
                    .and_then(|steps| steps.get_mut(slot))
                    .and_then(Value::as_object_mut)
                {
                    step.shift_remove("type_diagnostics");
                    step.shift_remove("preparation_note");
                    step.insert("type_feedback".to_owned(), withheld);
                }
            }
            Self::ProgramSteps => put_program_step(value, slot, withheld),
        }
    }
}

/// A carrier held out of its answer until the answer is released: the
/// carrier as it was recorded, and its feedback by slot.
struct Held {
    carrier: Carrier,
    scan: FeedbackScan,
    original: Value,
    feedback: Vec<(usize, ProgramStepFeedback)>,
}

impl Held {
    /// Takes `value`'s feedback out of it, leaving the carrier without it.
    fn of(carrier: Carrier, scan: FeedbackScan, value: &mut Value) -> Option<Self> {
        let (base, feedback) = carrier.take(value)?;
        let original = std::mem::replace(value, base);
        Some(Self {
            carrier,
            scan,
            original,
            feedback,
        })
    }

    /// The carrier as it leaves for `actor`, and whether any of its feedback
    /// is withheld: as it was recorded, or with each feedback its release
    /// holds replaced by its withheld projection.
    fn release(
        self,
        server: &SyncServer,
        actor: &McpCallContext,
        rows: Option<&[EntityId]>,
    ) -> (Value, bool) {
        let Self {
            carrier,
            scan,
            mut original,
            feedback,
        } = self;
        let mut withheld_any = false;
        for (slot, feedback) in feedback {
            let released = release_feedback(server, actor, rows, feedback, scan);
            if matches!(released, ProgramStepFeedbackRelease::Withheld { .. }) {
                withheld_any = true;
                carrier.put(
                    &mut original,
                    slot,
                    serde_json::to_value(&released).unwrap_or(Value::Null),
                );
            }
        }
        (original, withheld_any)
    }
}

/// An `execute_code` answer's feedback, held out of it until it is
/// released: each program step's, and its bridge steps' carriers.
pub(super) struct HeldRunFeedback {
    program_steps: Vec<ProgramStepFeedback>,
    steps: Vec<HeldStep>,
}

/// One bridge step's carrier, held: the step's place in the answer's steps,
/// the outcome field its JSON text sits in, and that text as recorded.
struct HeldStep {
    index: usize,
    field: &'static str,
    recorded: String,
    held: Held,
}

/// A generated verb's feedback, held out of its answer: the owner's read of
/// one step's feedback, a run's history, or a session-bound run's entry.
pub(super) struct HeldVerbFeedback(Held);

/// A failed run's kept feedback, released apart beside its refusal (FIX
/// 10389): each kept step's, released or withheld for the caller's
/// destination; or the fact that it could not be read.
#[derive(Debug)]
pub(super) enum ErrorProgramSteps {
    Kept(Vec<ProgramStepFeedbackRelease>),
    NotKept,
}

/// `feedback` as `actor`'s destination is given it
/// ([`release_step_feedback`]). Never fails: only this feedback changes.
fn release_feedback(
    server: &SyncServer,
    actor: &McpCallContext,
    rows: Option<&[EntityId]>,
    feedback: ProgramStepFeedback,
    scan: FeedbackScan,
) -> ProgramStepFeedbackRelease {
    release_step_feedback(&server.vault, &actor.destination(), rows, feedback, scan)
}

/// An `execute_code` answer's feedback, held apart before its rows are read
/// and it is released: its `program_steps`, which `structured` never gets,
/// and the known carriers among its bridge steps, taken out of it: a wait
/// set's answer, and the owner's feedback read and a run's history, each
/// known by the call its record keeps, never by its output's shape.
pub(super) fn hold_run_feedback(
    structured: &mut Value,
    record: &CodeRunReplayRecord,
    program_steps: Vec<ProgramStepFeedback>,
) -> HeldRunFeedback {
    HeldRunFeedback {
        program_steps,
        steps: hold_step_feedback(structured, record),
    }
}

/// The known carriers among the bridge steps of `structured`.
fn hold_step_feedback(structured: &mut Value, record: &CodeRunReplayRecord) -> Vec<HeldStep> {
    let Some(steps) = structured.get_mut("steps").and_then(Value::as_array_mut) else {
        return Vec::new();
    };
    let mut held = Vec::new();
    for (index, step) in steps.iter_mut().enumerate() {
        let Some((carrier, scan, kind, field)) = step
            .get("seq")
            .and_then(Value::as_u64)
            .and_then(|seq| record.bridge_calls.iter().find(|call| call.seq == seq))
            .and_then(step_carrier)
        else {
            continue;
        };
        let Some(outcome) = step.get_mut("outcome") else {
            continue;
        };
        if outcome.get("kind").and_then(Value::as_str) != Some(kind) {
            continue;
        }
        let Some(Value::String(text)) = outcome.get_mut(field) else {
            continue;
        };
        let Ok(mut value) = serde_json::from_str::<Value>(text.as_str()) else {
            continue;
        };
        let Some(kept) = Held::of(carrier, scan, &mut value) else {
            continue;
        };
        let recorded = std::mem::replace(text, value.to_string());
        held.push(HeldStep {
            index,
            field,
            recorded,
            held: kept,
        });
    }
    held
}

/// The carrier a recorded bridge call's outcome is, its scan, the outcome
/// kind its recorder wrote and the field holding its JSON text.
fn step_carrier(
    call: &CodeRunBridgeCall,
) -> Option<(Carrier, FeedbackScan, &'static str, &'static str)> {
    let named = FeedbackScan::Named;
    match call.effect {
        SelfEffect::TasksWaitSet => Some((
            Carrier::WaitSet,
            FeedbackScan::Bytes,
            "task_wait_set",
            "json",
        )),
        SelfEffect::AgentVerb => match recorded_verb(call)? {
            OWNER_FEEDBACK_VERB => Some((Carrier::Owner, named, "agent_verb", "output")),
            HISTORY_VERB => Some((Carrier::History, named, "agent_verb", "output")),
            OFF_RECORD_EXECUTE_VERB | FOREIGN_EXECUTE_CODE_VERB => {
                Some((Carrier::ProgramSteps, named, "agent_verb", "output"))
            }
            _ => None,
        },
        _ => None,
    }
}

/// The verb a recorded agent-verb call's own request names.
fn recorded_verb(call: &CodeRunBridgeCall) -> Option<&str> {
    let rmpv::Value::Map(entries) = &call.request else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("verb"))
        .and_then(|(_, verb)| verb.as_str())
}

/// An `execute_code` answer without its feedback, released as it is
/// (`mcp_release_run_result`, by `rows`, those its verb answers listed and
/// its step log names), then its feedback released apart: each program
/// step's as `program_steps`, and each held bridge step's carrier back in
/// its step, as recorded or with the feedback its release holds withheld.
/// A refusal of the answer stays one; a hold on feedback changes only that
/// feedback. Nothing here waits.
pub(super) fn release_run_answer(
    server: &Arc<SyncServer>,
    actor: &McpCallContext,
    rows: Option<Vec<EntityId>>,
    held: HeldRunFeedback,
    result: Value,
) -> Result<Value, McpGatewayError> {
    let rows = rows.as_deref();
    let mut result = super::device_release::mcp_release_run_result(server, actor, rows, result)?;
    let program_steps = held
        .program_steps
        .into_iter()
        .map(|feedback| release_feedback(server, actor, rows, feedback, FeedbackScan::Named))
        .collect::<Vec<_>>();
    if let Some(structured) = result.get_mut("structuredContent") {
        for HeldStep {
            index,
            field,
            recorded,
            held: kept,
        } in held.steps
        {
            let (value, withheld) = kept.release(server, actor, rows);
            let text = if withheld {
                value.to_string()
            } else {
                recorded
            };
            if let Some(slot) = structured.pointer_mut(&format!("/steps/{index}/outcome/{field}")) {
                *slot = Value::String(text);
            }
        }
        if let Some(object) = structured.as_object_mut() {
            object.insert("program_steps".to_owned(), json!(program_steps));
        }
    }
    sync_content(&mut result);
    Ok(result)
}

/// Takes the feedback out of `tool`'s output before its answer is released:
/// the owner's read of one step's feedback, a run's history, or a
/// session-bound run's entry.
pub(super) fn hold_verb_feedback(tool: &str, output: &mut Value) -> Option<HeldVerbFeedback> {
    let carrier = match tool {
        OWNER_FEEDBACK_VERB => Carrier::Owner,
        HISTORY_VERB => Carrier::History,
        OFF_RECORD_EXECUTE_VERB | FOREIGN_EXECUTE_CODE_VERB => Carrier::ProgramSteps,
        _ => return None,
    };
    Held::of(carrier, FeedbackScan::Named, output).map(HeldVerbFeedback)
}

/// A generated verb's answer, released, with its held feedback back in its
/// output, as it was or with the feedback its release holds withheld.
pub(super) fn attach_verb_feedback(
    server: &SyncServer,
    actor: &McpCallContext,
    rows: Option<&[EntityId]>,
    held: Option<HeldVerbFeedback>,
    mut result: Value,
) -> Value {
    let Some(HeldVerbFeedback(held)) = held else {
        return result;
    };
    let (output, _) = held.release(server, actor, rows);
    if let Some(slot) = result.pointer_mut("/structuredContent/output") {
        *slot = output;
    }
    sync_content(&mut result);
    result
}

/// A verb-table row's feedback, held out of its action outcome: the row's
/// output rides string-encoded in its outcome, as a bridge step's does.
pub(super) struct HeldActionFeedback {
    recorded: String,
    held: HeldVerbFeedback,
}

/// Takes the feedback out of the row output `verb`'s action outcome
/// carries, before its answer is released: the owner's read of one step's
/// feedback, a run's history, or a session-bound run's entry. `None` when
/// the outcome carries no row output, or none with feedback in it.
pub(super) fn hold_action_feedback(
    verb: &str,
    output: &mut Value,
) -> Option<HeldActionFeedback> {
    let Value::String(text) = output.pointer_mut("/outcome/output")? else {
        return None;
    };
    let mut value: Value = serde_json::from_str(text.as_str()).ok()?;
    let held = hold_verb_feedback(verb, &mut value)?;
    let recorded = std::mem::replace(text, value.to_string());
    Some(HeldActionFeedback { recorded, held })
}

/// An `invoke_action` answer, released, with its row's held feedback back
/// in its outcome, as it was recorded or with the feedback its release
/// holds withheld.
pub(super) fn attach_action_feedback(
    server: &SyncServer,
    actor: &McpCallContext,
    rows: Option<&[EntityId]>,
    held: Option<HeldActionFeedback>,
    mut result: Value,
) -> Value {
    let Some(action) = held else {
        return result;
    };
    let (output, withheld) = action.held.0.release(server, actor, rows);
    let text = if withheld {
        output.to_string()
    } else {
        action.recorded
    };
    if let Some(slot) = result.pointer_mut("/structuredContent/output/outcome/output") {
        *slot = Value::String(text);
    }
    sync_content(&mut result);
    result
}

/// A failed run's refusal, released as it is (`mcp_release_error`, by
/// `rows`, those the run served before it failed), then the feedback its
/// steps kept before it failed released apart beside it (FIX 10389): read
/// by its run, never by running a step or a check again. A run that kept
/// none adds nothing; a read that fails adds that fact, never another
/// refusal. The refusal's code, kind, retry and every other field stay as
/// released.
pub(super) fn release_run_error(
    server: &SyncServer,
    actor: &McpCallContext,
    rows: Option<&[EntityId]>,
    run: EntityId,
    error: McpGatewayError,
) -> McpGatewayError {
    let error = super::device_release::mcp_release_error(server, actor, rows, error);
    let steps = match server.vault.kept_program_steps(run) {
        KeptProgramSteps::Kept(steps) if steps.is_empty() => return error,
        KeptProgramSteps::Kept(steps) => ErrorProgramSteps::Kept(
            steps
                .into_iter()
                .map(|feedback| {
                    release_feedback(server, actor, rows, feedback, FeedbackScan::Named)
                })
                .collect(),
        ),
        KeptProgramSteps::NotKept { detail } => {
            tracing::warn!(
                target: "oneiron::code_check",
                run = %run.to_hex(),
                %detail,
                "type feedback of a failed run not read"
            );
            ErrorProgramSteps::NotKept
        }
    };
    McpGatewayError {
        program_steps: Some(Box::new(steps)),
        ..error
    }
}

/// A foreign program's refusal (FIX 10389): its error under the gateway's
/// vocabulary, its code, kind and retry as they are today, and its
/// program's type feedback released apart beside it, by `rows`, those the
/// call served before it failed. The refusal itself is released by the
/// call's own path, as every refusal is; a refusal before the program's
/// source was admitted carries no feedback.
pub(super) fn source_run_error(
    server: &SyncServer,
    actor: &McpCallContext,
    rows: Option<&[EntityId]>,
    failure: ForeignCodeFailure,
) -> McpGatewayError {
    let error = super::mcp_facade_error(failure.error);
    if failure.program_steps.is_empty() {
        return error;
    }
    let steps = failure
        .program_steps
        .into_iter()
        .map(|feedback| release_feedback(server, actor, rows, feedback, FeedbackScan::Named))
        .collect();
    McpGatewayError {
        program_steps: Some(Box::new(ErrorProgramSteps::Kept(steps))),
        ..error
    }
}

/// A refusal's feedback in its `error.data`: `program_steps`, or
/// `program_steps_unavailable` naming why it has none to give.
pub(super) fn stamp_error_feedback(steps: ErrorProgramSteps, data: &mut Map<String, Value>) {
    match steps {
        ErrorProgramSteps::Kept(steps) => {
            data.insert("program_steps".to_owned(), json!(steps));
        }
        ErrorProgramSteps::NotKept => {
            data.insert(
                "program_steps_unavailable".to_owned(),
                Value::from(TYPE_FEEDBACK_NOT_KEPT),
            );
        }
    }
}

/// The answer's text copy of its structured content (`content[1]`, its
/// canonical JSON) states it again once its feedback is back in.
fn sync_content(result: &mut Value) {
    let Some(text) = result
        .get("structuredContent")
        .map(crate::mcp::mcp_canonical_json)
    else {
        return;
    };
    if let Some(slot) = result.pointer_mut("/content/1/text") {
        *slot = Value::String(text);
    }
}
