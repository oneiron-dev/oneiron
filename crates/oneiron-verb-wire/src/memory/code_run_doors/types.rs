//! Moved from `crates/oneiron/src/memory/code_run_doors/types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

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
