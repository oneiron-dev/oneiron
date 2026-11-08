//! The code run door request and view records: the model-heal count, a
//! step's type feedback, a run's correction records, a run's step evidence
//! (FIX 4414) and a live session's model-heal count (FIX 4415).
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

/// Names the one canonical code run whose step evidence the owner reads,
/// and the page of its steps (FIX 4414). It pages as
/// [`CodeRunCorrectionsRequest`] does.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunStepEvidenceRequest {
    /// 32-hex code-run id (the executor run, not an attempt's run
    /// correlation id).
    pub run_ref: String,
    /// The page starts at the first step after this one; at step 0 when
    /// absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_step: Option<u64>,
    /// Steps in this page; [`CODE_RUN_CORRECTIONS_DEFAULT_STEPS`] when
    /// absent, at most [`CODE_RUN_CORRECTIONS_MAX_STEPS`]. Must be positive.
    /// A page holds fewer when its bodies fill one reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
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

/// One stored body of a step, read as model context reads it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRunStepBody {
    /// The body's content handle in the run's output store.
    pub handle: String,
    /// The whole body's length in bytes.
    pub bytes: u64,
    /// Whether its producer finished writing it.
    pub complete: bool,
    /// The secret scan marked the body or it is under taint for its run:
    /// `text` is the withheld mark, none of its content.
    pub withheld: bool,
    /// The body's text: whole within one reply's bytes, else its head and a
    /// last line naming the whole stored body. A program's known custody
    /// values show as their handles.
    pub text: String,
}

/// Names the one live off-record session and the one model whose heal
/// tally the owner reads as that session reads it (FIX 4415).
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunSessionModelHealCountRequest {
    /// The live off-record session, a 1:1 of the owner's or a room the owner
    /// is in. A closed or unknown session is refused, never read as the
    /// vault's tally.
    pub session_ref: String,
    /// The full `provider/name@revision` id the executor seat was configured
    /// with. No revision is filled in and no provider wire label resolves.
    pub model_id: String,
}

/// One model's heal tally as one live session reads it: the vault's
/// canonical tally and the session's own private delta, apart and summed. A
/// routing signal, not a correction receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CodeRunSessionModelHealCountView {
    /// The session as the request named it.
    pub session_ref: String,
    /// The model id as the request named it.
    pub model_id: String,
    /// The vault's canonical tally: what `vault.code.model_heal_count` reads.
    pub canonical_healed_turns: u64,
    /// The healed turns this session's runs committed while it was off
    /// record, kept in its private overlay alone.
    pub session_healed_turns: u64,
    /// `canonical_healed_turns` plus `session_healed_turns`.
    pub healed_turns: u64,
}
