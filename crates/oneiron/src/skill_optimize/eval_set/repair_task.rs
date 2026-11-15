//! Explicit tasks from an exact linked AG-UI capture: a text response, or
//! calls to declared pure tools over a JSON state (census L1-20).
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
    EvalRepairAction, EvalRepairGrader, EvalRepairPrecondition, EvalRepairTaskSpec, EvalRepairTool,
    EvalRepairToolCall, EvalRepairToolEffect, EvalRepairWorld,
};

/// The most tool calls one grade applies; more grade false.
const MAX_REPAIR_TOOL_CALLS: usize = 256;

/// What the linked app observed, which the grader compares against.
#[derive(Debug, Clone)]
enum EvalRepairExpected {
    /// A text-response world's exact response.
    Response(String),
    /// A JSON-state-tools world's exact end state.
    State(Value),
}

/// A compiled task. The answer and source evidence stay out of the
/// candidate input, and the answer is not in the task's own workspace or
/// history, by exact text or, for an end state, by exact JSON. This is not a
/// label, a certificate of task quality or a measured pass.
#[derive(Debug, Clone)]
pub struct EvalRepairTask {
    pub source: EvalRepairTaskSource,
    pub failure_ordinal: usize,
    pub repair_ordinal: usize,
    pub source_rows: Vec<EntityId>,
    pub task_hash: [u8; 32],
    input: Value,
    /// The rebuilt state a tool world's calls start from.
    initial_state: Value,
    /// The declared tools the task offers; none for a text-response world.
    tools: Vec<EvalRepairTool>,
    expected: EvalRepairExpected,
}

impl EvalRepairTask {
    /// The same rebuilt, read-only world and intent for each leg, with the
    /// offered tools and what each does. It contains no observed outcome,
    /// outside repair or grader answer.
    #[must_use]
    pub fn response_input(&self) -> &Value {
        &self.input
    }

    /// Exact response equality, without trimming, case folding or a model call.
    /// A true result says only that this response meets this sourced check.
    /// A tool world's task grades no response.
    #[must_use]
    pub fn grade_response(&self, response: &str) -> bool {
        matches!(&self.expected, EvalRepairExpected::Response(expected) if expected == response)
    }

    /// The state `calls` leave, applied in order by fixed code to the rebuilt
    /// initial state through the offered tools. `None` when a call names a
    /// tool the task does not offer or cannot apply, or there are more than
    /// 256 calls. A text-response task offers no tool.
    #[must_use]
    pub fn apply_tool_calls(&self, calls: &[EvalRepairToolCall]) -> Option<Value> {
        if calls.len() > MAX_REPAIR_TOOL_CALLS {
            return None;
        }
        let mut state = self.initial_state.clone();
        for call in calls {
            let tool = self.tools.iter().find(|tool| tool.name == call.tool)?;
            apply_effect(&mut state, &tool.effect, &call.argument)?;
        }
        Some(state)
    }

    /// Whether `calls` leave the end state the app observed, by exact JSON
    /// equality and without a model call. Only a tool world's task grades
    /// calls; the candidate's own account of its end state is never graded.
    #[must_use]
    pub fn grade_tool_calls(&self, calls: &[EvalRepairToolCall]) -> bool {
        let EvalRepairExpected::State(expected) = &self.expected else {
            return false;
        };
        self.apply_tool_calls(calls)
            .is_some_and(|state| &state == expected)
    }

    /// The BLAKE3 hex of what the grader compares against: the observed
    /// response's bytes, or the observed end state's JSON text. A seed's
    /// outcome label names the outcome by this digest, never by its text.
    #[must_use]
    pub(super) fn outcome_digest(&self) -> String {
        match &self.expected {
            EvalRepairExpected::Response(answer) => blake3::hash(answer.as_bytes()),
            EvalRepairExpected::State(state) => blake3::hash(state.to_string().as_bytes()),
        }
        .to_hex()
        .to_string()
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

/// Whether the end state `state` sits in `world`, which the candidate is
/// shown: as `world` itself (a task no call needs to solve), as a value
/// inside it, or, for a text state, as an object key. Exact JSON only.
fn state_leaks(world: &Value, state: &Value) -> bool {
    world == state
        || match world {
            Value::Object(fields) => fields.iter().any(|(key, value)| {
                state.as_str() == Some(key.as_str()) || state_leaks(value, state)
            }),
            Value::Array(items) => items.iter().any(|item| state_leaks(item, state)),
            _ => false,
        }
}

/// RFC 6901 syntax: empty, or `/`-led with every `~` escaped as `~0` or `~1`.
fn pointer_is_valid(pointer: &str) -> bool {
    (pointer.is_empty() || pointer.starts_with('/'))
        && !pointer
            .as_bytes()
            .windows(2)
            .any(|pair| pair[0] == b'~' && !matches!(pair[1], b'0' | b'1'))
        && !pointer.ends_with('~')
}

fn at_pointer<'a>(value: &'a Value, pointer: &str) -> Result<&'a Value> {
    if !pointer_is_valid(pointer) {
        return Err(Error::InvalidClaimBody("invalid Repair task JSON pointer"));
    }
    value
        .pointer(pointer)
        .ok_or(Error::InvalidClaimBody("Repair task field is missing"))
}

/// A valid, non-root pointer split into its parent pointer and its last
/// reference token, unescaped.
fn split_last_token(pointer: &str) -> Option<(&str, String)> {
    let at = pointer.rfind('/')?;
    let token = pointer[at + 1..].replace("~1", "/").replace("~0", "~");
    Some((&pointer[..at], token))
}

/// An RFC 6901 array index: `0`, or digits with no leading zero.
fn array_index(token: &str) -> Option<usize> {
    if token.starts_with('+') || (token.starts_with('0') && token.len() != 1) {
        return None;
    }
    token.parse().ok()
}

/// Applies one declared effect to `state`; `None` when it cannot apply there.
fn apply_effect(state: &mut Value, effect: &EvalRepairToolEffect, argument: &Value) -> Option<()> {
    match effect {
        EvalRepairToolEffect::Set { pointer } => {
            if let Some(slot) = state.pointer_mut(pointer) {
                *slot = argument.clone();
                return Some(());
            }
            let (parent, key) = split_last_token(pointer)?;
            state
                .pointer_mut(parent)?
                .as_object_mut()?
                .insert(key, argument.clone());
            Some(())
        }
        EvalRepairToolEffect::Append { pointer } => {
            state
                .pointer_mut(pointer)?
                .as_array_mut()?
                .push(argument.clone());
            Some(())
        }
        EvalRepairToolEffect::Remove { pointer } => {
            if !argument.is_null() {
                return None;
            }
            let (parent, key) = split_last_token(pointer)?;
            match state.pointer_mut(parent)? {
                Value::Object(fields) => fields.remove(&key).map(|_| ()),
                Value::Array(items) => {
                    let index = array_index(&key)?;
                    (index < items.len()).then(|| {
                        items.remove(index);
                    })
                }
                _ => None,
            }
        }
    }
}

/// The declared tools a contract offers, after the checks its world and
/// grader need. A text-response world declares no tool, so it offers none.
fn offered_tools(spec: &EvalRepairTaskSpec) -> Result<Vec<EvalRepairTool>> {
    match (&spec.world, &spec.grader) {
        (EvalRepairWorld::TextResponse, EvalRepairGrader::ObservedResponseEquals { .. }) => {
            if spec.intent.trim().is_empty()
                || !spec.tools.is_empty()
                || spec.allowed_actions.as_slice() != [EvalRepairAction::Respond]
            {
                return Err(Error::InvalidClaimBody(
                    "a text-response Repair task needs an intent, no tools and only respond",
                ));
            }
            Ok(Vec::new())
        }
        (
            EvalRepairWorld::JsonStateTools { tools: declared },
            EvalRepairGrader::ObservedStateEquals { .. },
        ) => {
            if spec.intent.trim().is_empty()
                || spec.tools.is_empty()
                || spec.allowed_actions.as_slice() != [EvalRepairAction::CallTool]
            {
                return Err(Error::InvalidClaimBody(
                    "a tool-world Repair task needs an intent, offered tools and only call_tool",
                ));
            }
            for (at, tool) in declared.iter().enumerate() {
                let pointer = match &tool.effect {
                    EvalRepairToolEffect::Set { pointer }
                    | EvalRepairToolEffect::Append { pointer } => pointer,
                    EvalRepairToolEffect::Remove { pointer } if !pointer.is_empty() => pointer,
                    EvalRepairToolEffect::Remove { .. } => {
                        return Err(Error::InvalidClaimBody(
                            "Repair world tool declaration is invalid",
                        ));
                    }
                };
                if tool.name.trim().is_empty()
                    || !pointer_is_valid(pointer)
                    || declared[..at].iter().any(|other| other.name == tool.name)
                {
                    return Err(Error::InvalidClaimBody(
                        "Repair world tool declaration is invalid",
                    ));
                }
            }
            let mut offered = Vec::with_capacity(spec.tools.len());
            for (at, name) in spec.tools.iter().enumerate() {
                if spec.tools[..at].contains(name) {
                    return Err(Error::InvalidClaimBody("Repair task offers a tool twice"));
                }
                let tool = declared.iter().find(|tool| &tool.name == name).ok_or(
                    Error::InvalidClaimBody("Repair task offers a tool its world does not declare"),
                )?;
                offered.push(tool.clone());
            }
            Ok(offered)
        }
        _ => Err(Error::InvalidClaimBody(
            "Repair task grader does not fit its world",
        )),
    }
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
        // Tools outside the world's declared set are refused (ruling
        // L1-20-TOOLWORLD = B); a text-response world declares none.
        let tools = offered_tools(&spec)?;
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
        let expected = match &spec.grader {
            EvalRepairGrader::ObservedResponseEquals { pointer } => EvalRepairExpected::Response(
                at_pointer(observed, pointer)?
                    .as_str()
                    .ok_or(Error::InvalidClaimBody(
                        "Repair response outcome must be text",
                    ))?
                    .to_owned(),
            ),
            EvalRepairGrader::ObservedStateEquals { pointer } => {
                EvalRepairExpected::State(at_pointer(observed, pointer)?.clone())
            }
        };
        // A trace is a task only if its answer is not leaked in the workspace
        // or the history (ARCH-0053 #eval-trace-task): the rebuilt state and
        // the input. The intent is the task's own words and is not checked.
        let leaked = match &expected {
            EvalRepairExpected::Response(answer) => {
                answer_leaks(&spec.initial_state, answer) || answer_leaks(&spec.input, answer)
            }
            EvalRepairExpected::State(state) => {
                state_leaks(&spec.initial_state, state) || state_leaks(&spec.input, state)
            }
        };
        if leaked {
            return Err(Error::InvalidClaimBody(
                "Repair task answer is leaked in its workspace or history",
            )
            .into());
        }
        // The grader is hashed with the task, but is never part of a leg's input.
        let bytes = match &expected {
            EvalRepairExpected::Response(answer) => serde_json::to_vec(&(&source, &spec, answer)),
            EvalRepairExpected::State(state) => serde_json::to_vec(&(&source, &spec, state)),
        }
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
                initial_state: spec.initial_state,
                tools,
                expected,
            }),
            receipt: read.receipt,
        })
    }
}
