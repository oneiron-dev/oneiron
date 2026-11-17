//! Explicit, response-only tasks from an exact linked AG-UI capture.
//! This compiles source data, not an authority, an outcome label or an eval nomination.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::EvalSeat;
use crate::claim::ScopedReadReceipt;
use crate::ingest::{AgUiFileReadInput, AgUiRepairLinkStatus, AgUiSource};
use crate::memory::{Memory, MemoryResult};
use crate::{EntityId, Error, Result};

/// A task contract on the linked failure event in one exact capture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairTaskSource {
    pub claim_ref: String,
    pub source_hash: String,
    pub outcome_ordinal: usize,
    /// JSON pointer into the whole linked failure event, not its repair or outcome.
    pub task_pointer: String,
    /// The caller names the seat; the app's roles grant no engine identity.
    pub seat: EvalSeat,
}

#[doc(hidden)]
pub use oneiron_verb_wire::skill_optimize::eval_set::repair_task::{
    EvalRepairAction, EvalRepairGrader, EvalRepairPrecondition, EvalRepairTaskSpec, EvalRepairWorld,
};

/// A compiled response task. The answer and source evidence stay out of the
/// candidate input, and the answer is not in the task's own workspace or
/// history, by exact text. This is not a label, a
/// certificate of task quality or a measured pass.
#[derive(Debug, Clone)]
pub struct EvalRepairTask {
    pub source: EvalRepairTaskSource,
    pub failure_ordinal: usize,
    pub repair_ordinal: usize,
    pub source_rows: Vec<EntityId>,
    pub task_hash: [u8; 32],
    input: Value,
    expected_response: String,
}

impl EvalRepairTask {
    /// The same rebuilt, read-only world and intent for each response leg.
    /// It contains no observed outcome, outside repair or grader answer.
    #[must_use]
    pub fn response_input(&self) -> &Value {
        &self.input
    }

    /// Exact response equality, without trimming, case folding or a model call.
    /// A true result says only that this response meets this sourced check.
    #[must_use]
    pub fn grade_response(&self, response: &str) -> bool {
        response == self.expected_response
    }

    /// All task variants from this capture share one family root for this seat.
    #[must_use]
    pub fn family_root(&self) -> String {
        format!("entity:{}", self.source.claim_ref)
    }
}

#[derive(Debug, Clone)]
pub struct EvalRepairTaskRead {
    pub task: Option<EvalRepairTask>,
    pub receipt: ScopedReadReceipt,
}

/// Whether `answer` sits in `world`, which the candidate is shown: in a string
/// or an object key, or as a number's or a boolean's whole text. The answer is
/// trimmed of outer whitespace; an empty one leaks nothing. Exact text only:
/// a paraphrase passes, and a short answer that recurs by chance refuses.
fn answer_leaks(world: &Value, answer: &str) -> bool {
    fn holds(value: &Value, answer: &str) -> bool {
        match value {
            Value::String(text) => text.contains(answer),
            Value::Object(fields) => fields
                .iter()
                .any(|(key, value)| key.contains(answer) || holds(value, answer)),
            Value::Array(items) => items.iter().any(|item| holds(item, answer)),
            Value::Number(number) => number.to_string() == answer,
            Value::Bool(flag) => flag.to_string() == answer,
            Value::Null => false,
        }
    }
    let answer = answer.trim();
    !answer.is_empty() && holds(world, answer)
}

fn at_pointer<'a>(value: &'a Value, pointer: &str) -> Result<&'a Value> {
    if (!pointer.is_empty() && !pointer.starts_with('/'))
        || pointer
            .as_bytes()
            .windows(2)
            .any(|pair| pair[0] == b'~' && !matches!(pair[1], b'0' | b'1'))
        || pointer.ends_with('~')
    {
        return Err(Error::InvalidClaimBody("invalid Repair task JSON pointer"));
    }
    value
        .pointer(pointer)
        .ok_or(Error::InvalidClaimBody("Repair task field is missing"))
}

impl Memory<'_> {
    /// Compile an explicitly mapped task from the linked failure. Reads use the
    /// native AG-UI scoped reader and its exact fingerprint/owner checks. Missing
    /// or withheld captures return no task and the original read receipt.
    pub fn read_eval_repair_task(
        &self,
        source: &EvalRepairTaskSource,
    ) -> MemoryResult<EvalRepairTaskRead> {
        let read = self.read_ag_ui_file(&AgUiFileReadInput {
            claim_ref: source.claim_ref.clone(),
            source_hash: source.source_hash.clone(),
        })?;
        let Some(view) = read.source else {
            return Ok(EvalRepairTaskRead {
                task: None,
                receipt: read.receipt,
            });
        };
        source.seat.token()?;
        let source = EvalRepairTaskSource {
            claim_ref: view.claim_ref.clone(),
            source_hash: view.source_hash.clone(),
            outcome_ordinal: source.outcome_ordinal,
            task_pointer: source.task_pointer.clone(),
            seat: source.seat.clone(),
        };
        let link = view
            .repair_links
            .iter()
            .find(|link| {
                link.outcome_ordinal == source.outcome_ordinal
                    && link.status == AgUiRepairLinkStatus::Linked
            })
            .ok_or(Error::InvalidClaimBody(
                "Repair task requires a linked outcome",
            ))?;
        let failure_ordinal = link
            .failure_ordinal
            .ok_or(Error::InvalidClaimBody("Repair task has no linked failure"))?;
        let repair_ordinal = link
            .repair_ordinal
            .ok_or(Error::InvalidClaimBody("Repair task has no linked repair"))?;
        let events = AgUiSource::decode(&view.jsonl)
            .map_err(|_| Error::InvalidClaimBody("invalid Repair task capture"))?;
        let failure = events
            .get(failure_ordinal)
            .ok_or(Error::InvalidClaimBody("Repair task failure is missing"))?;
        let spec: EvalRepairTaskSpec =
            serde_json::from_value(at_pointer(failure.raw(), &source.task_pointer)?.clone())
                .map_err(|_| Error::InvalidClaimBody("invalid Repair task contract"))?;
        if spec.intent.trim().is_empty()
            || !spec.tools.is_empty()
            || spec.allowed_actions.as_slice() != [EvalRepairAction::Respond]
        {
            return Err(Error::InvalidClaimBody(
                "a text-response Repair task needs an intent, no tools and only respond",
            )
            .into());
        }
        for check in &spec.preconditions {
            if at_pointer(&spec.initial_state, &check.pointer)? != &check.equals {
                return Err(Error::InvalidClaimBody("Repair initial precondition failed").into());
            }
        }
        let observed = view
            .observations
            .iter()
            .find(|row| row.ordinal == source.outcome_ordinal)
            .and_then(|row| row.outcome.as_ref())
            .ok_or(Error::InvalidClaimBody(
                "Repair observed outcome is missing",
            ))?;
        let EvalRepairGrader::ObservedResponseEquals { pointer } = &spec.grader;
        let expected_response = at_pointer(observed, pointer)?
            .as_str()
            .ok_or(Error::InvalidClaimBody(
                "Repair response outcome must be text",
            ))?
            .to_owned();
        // A trace is a task only if its answer is not leaked in the workspace
        // or the history (ARCH-0053 #eval-trace-task): the rebuilt state and
        // the input. The intent is the task's own words and is not checked.
        if answer_leaks(&spec.initial_state, &expected_response)
            || answer_leaks(&spec.input, &expected_response)
        {
            return Err(Error::InvalidClaimBody(
                "Repair task answer is leaked in its workspace or history",
            )
            .into());
        }
        // The grader is hashed with the task, but is never part of a leg's input.
        let bytes = serde_json::to_vec(&(&source, &spec, &expected_response))
            .map_err(|_| Error::InvalidClaimBody("Repair task encoding failed"))?;
        let input = serde_json::json!({
            "world": spec.world,
            "initial_state": spec.initial_state,
            "preconditions": spec.preconditions,
            "intent": spec.intent,
            "input": spec.input,
            "tools": spec.tools,
            "allowed_actions": spec.allowed_actions,
        });
        Ok(EvalRepairTaskRead {
            task: Some(EvalRepairTask {
                source,
                failure_ordinal,
                repair_ordinal,
                source_rows: vec![EntityId::from_hex(&view.claim_ref)?],
                task_hash: *blake3::hash(&bytes).as_bytes(),
                input,
                expected_response,
            }),
            receipt: read.receipt,
        })
    }
}
