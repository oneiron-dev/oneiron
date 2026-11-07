//! The code run door request and view records: the model-heal count, a
//! step's type feedback and a run's correction records.
//! These are local definitions; `memory::code_run_doors` re-exports them.

use serde::{Deserialize, Serialize};

use crate::code_run::{CodeRunCorrection, CodeRunCorrectionPolicy};

/// Names the one program step whose type feedback the owner reads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunTypeDiagnosticsRequest {
    /// The step's `check_ref`, as its feedback named it:
    /// `type_diagnostics:<run>:<step>:<invocation>`.
    pub check_ref: String,
    /// The live off-record session the step's run is bound to, for a run in
    /// one: its feedback is read on that session's route alone, never on
    /// the vault's when the session is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_ref: Option<String>,
}

/// Names the one model whose healed-turn tally the owner reads.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunModelHealCountRequest {
    /// The full `provider/name@revision` id the executor seat was configured
    /// with. No revision is filled in and no provider wire label resolves.
    pub model_id: String,
}

/// How many durable executor turns of this vault the model needed wire
/// healing for: a routing signal, not a correction receipt. It names no run,
/// turn, repair or retry outcome, because the tally stores none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRunModelHealCountView {
    /// The model id as the request named it.
    pub model_id: String,
    /// Zero when this vault holds no tally for the model, which says nothing
    /// of whether the model exists or serves.
    pub healed_turns: u64,
}

/// Steps in a correction page when the request names no limit.
pub const CODE_RUN_CORRECTIONS_DEFAULT_STEPS: u32 = 32;
/// The most steps one correction page carries; a larger limit reads this
/// many, and `next_after_step` names where the following page starts.
pub const CODE_RUN_CORRECTIONS_MAX_STEPS: u32 = 128;

/// Names the one code run whose correction records the owner reads, and the
/// page of its steps.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunCorrectionsRequest {
    /// 32-hex code-run id (the executor run, not an attempt's run
    /// correlation id).
    pub run_ref: String,
    /// The page starts at the first step after this one; at step 0 when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_step: Option<u64>,
    /// Steps in this page, each with every attempt it recorded;
    /// [`CODE_RUN_CORRECTIONS_DEFAULT_STEPS`] when absent, at most
    /// [`CODE_RUN_CORRECTIONS_MAX_STEPS`]. Must be positive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

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
