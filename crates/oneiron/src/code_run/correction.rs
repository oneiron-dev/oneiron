//! Durable code-run correction records (CODE-RUNTIME-02 slice 1: FIX 4411,
//! 4412, 4413).
//!
//! One record per model response the live REPL normalized at one step: the
//! run, the step, the attempt at that step, the configured model, the four
//! ONE-1929 packaging repairs and the outcome. A clean or normalized response
//! records with the checkpoint its step committed, in that commit's own
//! transaction. A rejected response records before its error returns, in its
//! own transaction on the run's route, and commits no checkpoint. A response
//! whose program fails before its first bridge call commits no step and
//! keeps no record; the reply the re-entry gets records as the step's next
//! attempt.
//!
//! A record holds ids, counts, flags and the executor's own rejection text.
//! It holds no response text, no program and no console the model wrote.
//!
//! The policy every record runs under is published as data (FIX 4413).
//! [`CODE_RUN_CORRECTION_POLICY`] is the one place it is set.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::CodeRunReplayRecord;
use crate::entity_id::bytes_to_hex_lower;
use crate::{EntityId, Error, ModelId, Result};

/// The version of the [`CodeRunCorrection`] row.
pub const CODE_RUN_CORRECTION_SCHEMA: u8 = 1;

/// What ONE-1929 had to remove from one model reply to reach a bare program.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecutorWireRepairs {
    /// Outer transport whitespace was trimmed from the program candidate.
    pub trimmed_transport_whitespace: bool,
    /// One whole markdown fence was stripped.
    pub stripped_code_fence: bool,
    /// One whole `<exec>` wrapper was stripped.
    pub stripped_exec_wrapper: bool,
    /// Console blocks the model wrote, deleted and never kept as output.
    pub discarded_console_blocks: u32,
}

impl ExecutorWireRepairs {
    /// Whether this turn needed ANY healing. One healed turn counts once, no
    /// matter how many of these repairs it took.
    #[must_use]
    pub const fn healed(self) -> bool {
        self.trimmed_transport_whitespace
            || self.stripped_code_fence
            || self.stripped_exec_wrapper
            || self.discarded_console_blocks != 0
    }
}

/// How the executor repairs one model response (FIX 4413).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunCorrectionPolicy {
    /// Normalization passes the executor runs over one model response.
    pub normalization_passes: u32,
    /// Times the executor asks the model again on its own after it rejects
    /// a response.
    pub model_repair_retries: u32,
}

/// The policy code mode runs today: one normalization pass per response and
/// no automatic model-repair retry. A rejected response ends its step's
/// attempt. A caller's re-entry asks the model again, and that response
/// records as the step's next attempt. A later ruling changes this constant
/// alone.
pub const CODE_RUN_CORRECTION_POLICY: CodeRunCorrectionPolicy = CodeRunCorrectionPolicy {
    normalization_passes: 1,
    model_repair_retries: 0,
};

impl CodeRunCorrectionPolicy {
    /// Whether an attempt that ended in `outcome` after `retries_used`
    /// automatic model-repair retries has no retry left. Only a rejected
    /// response exhausts its attempt.
    #[must_use]
    pub fn exhausted(self, outcome: &CodeRunCorrectionOutcome, retries_used: u32) -> bool {
        matches!(outcome, CodeRunCorrectionOutcome::Rejected { .. })
            && retries_used >= self.model_repair_retries
    }
}

/// What the normalization did with one model response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeRunCorrectionOutcome {
    /// The response was a bare program already: no repair was made.
    Clean,
    /// The response became a bare program after one or more repairs.
    Normalized,
    /// The normalization refused the response: no program ran and the step
    /// committed nothing.
    Rejected {
        /// The executor's stable text for the refusal, never the response's
        /// own words.
        reason: String,
    },
}

/// The checkpoint a clean or normalized response's step committed, as
/// `vault.runs.checkpoint` pages it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunCorrectionCheckpoint {
    pub step: u64,
    /// 64-hex chained state hash the checkpoint committed.
    pub state_hash: String,
}

impl CodeRunCorrectionCheckpoint {
    /// The checkpoint `record` commits for `step`: its last one, which must
    /// be that step's.
    pub(crate) fn committed(record: &CodeRunReplayRecord, step: u64) -> Result<Self> {
        match record.step_checkpoints.last() {
            Some(checkpoint) if checkpoint.seq == step => Ok(Self {
                step,
                state_hash: bytes_to_hex_lower(&checkpoint.state_hash),
            }),
            _ => Err(Error::InvariantViolation(
                "a correction record names a step its commit does not checkpoint",
            )),
        }
    }
}

/// One model response's correction record (FIX 4411, 4412).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CodeRunCorrection {
    /// [`CODE_RUN_CORRECTION_SCHEMA`].
    pub schema: u8,
    /// The executor run.
    pub run_id: EntityId,
    /// The step the response answered.
    pub step: u64,
    /// The response's attempt at this step, from 0. A rejected response and
    /// the re-entry that asks again record under different attempts.
    pub attempt: u64,
    /// When the record was written, in unix ms.
    pub recorded_at_ms: u64,
    /// The full validated `provider/name@revision` id the run was configured
    /// with, never a provider's wire label.
    pub model_id: String,
    /// The repairs the normalization made. For a rejected response, the
    /// repairs it made before the refusal.
    pub repairs: ExecutorWireRepairs,
    pub outcome: CodeRunCorrectionOutcome,
    /// The policy the response was normalized under.
    pub policy: CodeRunCorrectionPolicy,
    /// Automatic model-repair retries this attempt used.
    pub model_repair_retries_used: u32,
    /// The attempt ended rejected with no retry left. The next response at
    /// this step comes only from a caller's re-entry.
    pub exhausted: bool,
    /// The checkpoint the step committed; none for a rejected response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CodeRunCorrectionCheckpoint>,
}

/// One model response's correction facts, as the REPL holds them until the
/// write assigns the attempt and, for a committed step, the checkpoint.
#[derive(Debug, Clone)]
pub(crate) struct CodeRunCorrectionDraft<'a> {
    run_id: EntityId,
    step: u64,
    model: &'a ModelId,
    repairs: ExecutorWireRepairs,
    outcome: CodeRunCorrectionOutcome,
}

impl<'a> CodeRunCorrectionDraft<'a> {
    /// A response the normalization accepted: clean when it made no repair,
    /// normalized otherwise.
    pub(crate) fn accepted(
        run_id: EntityId,
        step: u64,
        model: &'a ModelId,
        repairs: ExecutorWireRepairs,
    ) -> Self {
        let outcome = if repairs.healed() {
            CodeRunCorrectionOutcome::Normalized
        } else {
            CodeRunCorrectionOutcome::Clean
        };
        Self {
            run_id,
            step,
            model,
            repairs,
            outcome,
        }
    }

    /// A response the normalization refused for `reason`, with the repairs
    /// it made before the refusal.
    pub(crate) fn rejected(
        run_id: EntityId,
        step: u64,
        model: &'a ModelId,
        repairs: ExecutorWireRepairs,
        reason: String,
    ) -> Self {
        Self {
            run_id,
            step,
            model,
            repairs,
            outcome: CodeRunCorrectionOutcome::Rejected { reason },
        }
    }

    pub(crate) const fn run_id(&self) -> EntityId {
        self.run_id
    }

    pub(crate) const fn step(&self) -> u64 {
        self.step
    }

    /// Whether the normalization refused this response.
    pub(crate) const fn is_rejected(&self) -> bool {
        matches!(self.outcome, CodeRunCorrectionOutcome::Rejected { .. })
    }

    /// The model whose heal tally this response's committed step advances:
    /// the run's model when the response needed any repair (ONE-1929).
    pub(crate) fn healed_model(&self) -> Option<&'a ModelId> {
        self.repairs.healed().then_some(self.model)
    }

    /// This response's record as attempt `attempt` of its step, with the
    /// checkpoint its step committed.
    pub(crate) fn record(
        &self,
        attempt: u64,
        checkpoint: Option<CodeRunCorrectionCheckpoint>,
    ) -> CodeRunCorrection {
        let policy = CODE_RUN_CORRECTION_POLICY;
        // Today's policy runs no automatic model-repair retry.
        let model_repair_retries_used = 0;
        CodeRunCorrection {
            schema: CODE_RUN_CORRECTION_SCHEMA,
            run_id: self.run_id,
            step: self.step,
            attempt,
            recorded_at_ms: crate::unix_millis_now(),
            model_id: self.model.as_str().to_owned(),
            repairs: self.repairs,
            exhausted: policy.exhausted(&self.outcome, model_repair_retries_used),
            outcome: self.outcome.clone(),
            policy,
            model_repair_retries_used,
            checkpoint,
        }
    }
}
