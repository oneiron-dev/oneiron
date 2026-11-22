//! `vault.code_run.resume_divergence.answer`'s wire types (L8-23): the owner's answer to the ask a
//! resumed pending step raised when its re-entered program changed an effect step.
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.code_run.resume_divergence.answer`'s input.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResumeDivergenceAnswer {
    /// The run whose pending step held (32 hex).
    pub run_ref: EntityId,
    /// The held step's seq.
    pub step_seq: u64,
    /// The held report's effect digest the ask names (64 hex).
    pub report_digest: String,
    /// What the run does with the changed effect steps.
    pub choice: ResumeDivergenceChoice,
}

/// The owner's answer on a held resume: re-fire the changed effect steps once, or leave them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResumeDivergenceChoice {
    /// The changed effect steps run live once, at their own seqs.
    Refire,
    /// The changed effect steps answer `effect_changed_left`; the step goes on without them.
    Leave,
}

/// `vault.code_run.resume_divergence.answer`'s answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResumeDivergenceAnswered {
    /// The run whose pending step held.
    pub run_ref: EntityId,
    /// The held step's seq.
    pub step_seq: u64,
    /// The held report's effect digest the answer names.
    pub report_digest: String,
    /// What the answer asked for.
    pub choice: ResumeDivergenceChoice,
    /// What it came to.
    pub outcome: ResumeDivergenceAnswerOutcome,
}

/// What the owner's answer to a resume-divergence ask came to (L8-23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResumeDivergenceAnswerOutcome {
    /// The changed effect steps run live once, at the run's next entry.
    RefireReleased,
    /// The changed effect steps are not made again: the step reads `effect_changed_left`.
    Left,
    /// An earlier answer settled the ask, or no ask waits on that run, step and digest.
    AlreadySettled,
}
