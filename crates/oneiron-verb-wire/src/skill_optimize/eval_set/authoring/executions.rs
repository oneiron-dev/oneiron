//! Moved from `crates/oneiron/src/skill_optimize/eval_set/authoring/executions.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.evals.authoring.execute`'s input: none. The pass reads the whole
/// inventory, as the nightly pass does; the caller supplies no plan, skill,
/// lease or target.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringExecuteRequest {}

/// Who asked for a pass, as its admission checked them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalAuthoringCaller {
    /// The vault owner, on its own proof.
    Owner { person: EntityId },
    /// An agent, on the live owner Grant that listed the verb.
    Agent { agent: EntityId, grant: EntityId },
}

/// What one requested pass came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvalAuthoringOutcome {
    /// Admitted and no plan applying: the pass runs, or its host stopped
    /// first; the next lease of the attempt runs it on this record.
    Running,
    /// The plan's effects began and have not ended. A host that stopped
    /// here leaves it so until the attempt is leased again, which ends it
    /// `Failed`: what the effects did is not known.
    Applying,
    /// The inventory held nothing new to decide: no model call.
    NoWork,
    /// No Coach seat, no loadable approved skill, or no seat took the call.
    Unavailable,
    /// The model's answer held no plan.
    NoPlan,
    /// The engine refused the plan; nothing applied.
    Refused,
    /// The plan applied; the report says what each step did.
    Applied,
    /// The pass ended in an error, and its attempt failed with it.
    Failed,
}

/// The eval-authoring skill revision a pass loaded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringSkillRun {
    pub skill: EntityId,
    pub revision: String,
}
