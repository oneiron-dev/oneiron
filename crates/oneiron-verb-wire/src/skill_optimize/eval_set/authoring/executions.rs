//! Moved from `crates/oneiron/src/skill_optimize/eval_set/authoring/executions.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_optimize::eval_set::authoring::apply::EvalAuthoringReport;
use oneiron_base::edge::EdgeActorClass;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MEMORY_CODE_FORBIDDEN;
use oneiron_contracts::memory::MemoryError;
use oneiron_contracts::memory::MemoryResult;
use oneiron_store::dreamer_attempt_payload::DreamerAttemptPayload;
use oneiron_store::principal_record::NoStanding;
use oneiron_store::principal_record::PACT_STANDING_LAPSED;
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

/// One requested pass's kept record, by its Coach attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringExecution {
    pub attempt: EntityId,
    pub caller: EvalAuthoringCaller,
    pub requested_at: u64,
    pub outcome: EvalAuthoringOutcome,
    pub ended_at: Option<u64>,
    pub skill: Option<EvalAuthoringSkillRun>,
    /// The inventory the plan was made from, once the pass read one.
    pub inventory_digest: Option<String>,
    /// What the plan did; only an applied pass has one.
    pub report: Option<EvalAuthoringReport>,
}

/// `vault.evals.authoring.execute`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvalAuthoringExecuteAnswer {
    /// The request's own pass ran on this host; its kept record.
    Ran {
        execution: Box<EvalAuthoringExecution>,
    },
    /// The queue's eval-authoring job was not ready for this host, so no
    /// pass ran for this request; `vault.evals.authoring.result` reads the
    /// job's state.
    Waiting { attempt: EntityId },
}
