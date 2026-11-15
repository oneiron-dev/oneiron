//! Durable code-run correction records (CODE-RUNTIME-02 slice 1: FIX 4411,
//! 4412, 4413).
//!
//! One record per model response the live REPL normalized at one step: the
//! run, the step, the attempt at that step, the answering model, the four
//! ONE-1929 packaging repairs and the outcome. A clean or normalized response
//! records with the checkpoint its step committed, in that commit's own
//! transaction. A rejected response records before its error returns, in its
//! own transaction on the run's route, and commits no checkpoint. A response
//! whose program fails before its first bridge call commits no step; its
//! record is written alone, as a rejected one's is, with its accepted
//! outcome and no checkpoint (FIX 14992). The reply the re-entry gets
//! records as the step's next attempt.
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

#[doc(hidden)]
pub use oneiron_verb_wire::code_run::correction::{
    CodeRunCorrectionOutcome, CodeRunCorrectionPolicy, ExecutorWireRepairs,
};

/// The policy code mode runs today: one normalization pass per response and
/// no automatic model-repair retry. A rejected response ends its step's
/// attempt. A caller's re-entry asks the model again, and that response
/// records as the step's next attempt. A later ruling changes this constant
/// alone.
pub const CODE_RUN_CORRECTION_POLICY: CodeRunCorrectionPolicy = CodeRunCorrectionPolicy {
    normalization_passes: 1,
    model_repair_retries: 0,
};

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
    /// The full validated `provider/name@revision` id of the model that
    /// answered: the ladder rung its served receipt names, else the model the
    /// run was configured with (a seat id when no receipt names the rung).
    /// Never a provider's wire label.
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
    /// The checkpoint the step committed; none for a step that committed
    /// none: a rejected response, or one whose program failed before its
    /// first bridge call.
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
    answered_by: Option<ModelId>,
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
            answered_by: None,
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
            answered_by: None,
            repairs,
            outcome: CodeRunCorrectionOutcome::Rejected { reason },
        }
    }

    /// The validated model id from the reply's served receipt, when present.
    pub(crate) fn answered_by(mut self, model: Option<ModelId>) -> Self {
        self.answered_by = model;
        self
    }

    /// The model id the reply's served receipt named, which a step parked
    /// at its deadline keeps until its checkpoint commits this record.
    pub(crate) const fn answering_model(&self) -> Option<&ModelId> {
        self.answered_by.as_ref()
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
            model_id: self
                .answered_by
                .as_ref()
                .unwrap_or(self.model)
                .as_str()
                .to_owned(),
            repairs: self.repairs,
            exhausted: policy.exhausted(&self.outcome, model_repair_retries_used),
            outcome: self.outcome.clone(),
            policy,
            model_repair_retries_used,
            checkpoint,
        }
    }
}
