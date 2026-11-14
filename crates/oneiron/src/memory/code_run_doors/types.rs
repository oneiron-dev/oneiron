//! The code run door request and view records: the model-heal count, a
//! step's type feedback, a run's correction records, a run's step evidence
//! (FIX 4414) and a live session's model-heal count (FIX 4415).
//! These are local definitions; `memory::code_run_doors` re-exports them.

use serde::{Deserialize, Serialize};

use crate::code_run::{CodeRunCorrection, CodeRunCorrectionPolicy};

#[doc(hidden)]
pub use oneiron_verb_wire::memory::code_run_doors::types::{
    CodeRunCorrectionsRequest, CodeRunModelHealCountRequest, CodeRunModelHealCountView,
    CodeRunSessionModelHealCountRequest, CodeRunSessionModelHealCountView, CodeRunStepBody,
    CodeRunStepEvidenceRequest, CodeRunTypeDiagnosticsRequest,
};

/// Steps in a correction page when the request names no limit.
pub const CODE_RUN_CORRECTIONS_DEFAULT_STEPS: u32 = 32;
/// The most steps one correction page carries; a larger limit reads this
/// many, and `next_after_step` names where the following page starts.
pub const CODE_RUN_CORRECTIONS_MAX_STEPS: u32 = 128;

/// One page of a code run's correction records, oldest first: by step, then
/// by attempt. Each record carries the policy it ran under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRunCorrectionsView {
    pub run_ref: String,
    /// The response repair policy the executor runs now.
    pub policy: CodeRunCorrectionPolicy,
    /// Empty when the run recorded none in this page, which says nothing of
    /// whether the run exists.
    pub records: Vec<CodeRunCorrection>,
    /// The last step of this page when a later step recorded more: pass it
    /// as `after_step` to read the next page. None past the last record.
    pub next_after_step: Option<u64>,
}

/// One page of a canonical code run's step evidence, oldest step first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRunStepEvidenceView {
    pub run_ref: String,
    /// Count of checkpointed steps, not an in-flight step.
    pub completed_steps: u64,
    /// The response repair policy the executor runs now.
    pub policy: CodeRunCorrectionPolicy,
    /// Each step that committed a checkpoint or recorded a correction.
    pub steps: Vec<CodeRunStepEvidence>,
    /// The last step of this page when a later step holds evidence: pass it
    /// as `after_step` to read the next page. None past the last step.
    pub next_after_step: Option<u64>,
}

/// One step of a code run, as its run stored it. Each body is the run's own
/// stored body, never the model's raw reply or a console the model wrote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRunStepEvidence {
    pub step: u64,
    /// 64-hex chained state hash the step's checkpoint committed. None for
    /// a step that committed no checkpoint: each of its responses was
    /// rejected, and it holds no body.
    pub state_hash: Option<String>,
    /// The program the normalization left and the step ran, TypeScript or
    /// JavaScript as the model wrote it.
    pub source: Option<CodeRunStepBody>,
    /// The JavaScript a TypeScript program ran as (FIX 8276). None for a
    /// program that ran as written.
    pub executed_js: Option<CodeRunStepBody>,
    /// The observation the step committed: the answer of a program that
    /// finished, else the console the program printed.
    pub observation: Option<CodeRunStepBody>,
    /// The console a program that finished printed beside its answer, kept
    /// apart from it. None when it printed none, or did not finish: its
    /// observation is then its console.
    pub console: Option<CodeRunStepBody>,
    /// The step's correction records, one per model response, oldest
    /// attempt first.
    pub corrections: Vec<CodeRunCorrection>,
}
