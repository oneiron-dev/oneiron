//! Moved from `crates/oneiron/src/skill_optimize/eval_set/repair_task.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// The world a task rebuilds: a JSON snapshot with no external state to
/// restore. A text-response world executes no tools. A JSON-state-tools world
/// declares pure tools over the snapshot, and fixed code applies a candidate's
/// calls to them (census L1-20, ruling L1-20-TOOLWORLD = B).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalRepairWorld {
    TextResponse,
    JsonStateTools {
        /// Every tool this world declares; the task offers some of them.
        tools: Vec<EvalRepairTool>,
    },
}

/// One pure tool a JSON-state-tools world declares: the name a task offers
/// and a call names, and its one effect on the state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairTool {
    pub name: String,
    pub effect: EvalRepairToolEffect,
}

/// What a declared tool does to the state, at a JSON pointer its declaration
/// fixes. It reads nothing but the state and the call's argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalRepairToolEffect {
    /// Writes the call's argument at `pointer`: replaces the value there, or
    /// adds the field to the object that would hold it.
    Set { pointer: String },
    /// Pushes the call's argument onto the array at `pointer`.
    Append { pointer: String },
    /// Removes the field or array item at `pointer`; the argument is null.
    Remove { pointer: String },
}

/// One tool call a candidate makes in a JSON-state-tools world.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairToolCall {
    pub tool: String,
    pub argument: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvalRepairAction {
    Respond,
    /// Calls the task's offered tools; the end state is graded.
    CallTool,
}

/// An actual equality check on the initial JSON snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairPrecondition {
    pub pointer: String,
    pub equals: Value,
}

/// A grader selected explicitly in the source task contract. Its expected
/// response or end state comes from the linked app observation, never from
/// candidate text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalRepairGrader {
    ObservedResponseEquals {
        /// JSON pointer into the registered observation's outcome value.
        pointer: String,
    },
    /// The state the candidate's tool calls leave equals, as exact JSON, the
    /// value at `pointer` in the registered observation's outcome.
    ObservedStateEquals {
        /// JSON pointer into the registered observation's outcome value.
        pointer: String,
    },
}

/// The complete source contract, at `EvalRepairTaskSource::task_pointer`.
/// No field has a default: empty state, preconditions and tools are explicit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairTaskSpec {
    pub world: EvalRepairWorld,
    pub initial_state: Value,
    pub preconditions: Vec<EvalRepairPrecondition>,
    pub intent: String,
    pub input: Value,
    pub tools: Vec<String>,
    pub allowed_actions: Vec<EvalRepairAction>,
    pub grader: EvalRepairGrader,
}
