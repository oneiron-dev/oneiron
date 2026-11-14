//! Moved from `crates/oneiron/src/skill_optimize/eval_set/repair_task.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;

/// The supported world is a read-only JSON snapshot and a text response.
/// It has no external state to restore and executes no tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvalRepairWorld {
    TextResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvalRepairAction {
    Respond,
}

/// An actual equality check on the initial JSON snapshot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairPrecondition {
    pub pointer: String,
    pub equals: Value,
}

/// A grader selected explicitly in the source task contract. Its expected
/// response comes from the linked app observation, never from candidate text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalRepairGrader {
    ObservedResponseEquals {
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
