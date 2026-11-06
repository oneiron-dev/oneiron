//! The shadow runner's request, result and their parts (PR-S1): what a
//! caller asks an arm to run, by immutable identity only, and what the arm
//! answers, each part typed. An unavailable arm is a result with a typed
//! reason, never a loss and never a fix.

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::code_run::{CodeRunDeterminism, ProgramStepFeedback, SelfDurableWait};
use crate::engine_executor::{EngineExecutorStatus, WindowFullReason};

pub use crate::dreamer_runner::shadow_values::{
    ArtifactDigest, ArtifactDigestAlgorithm, EngineArtifactPin, ShadowBodyRef, ShadowRequestDigest,
    ShadowSource, ShadowStepIdentity, ShadowTarget,
};

/// An arm's guest clock and random seed, as a frame carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShadowDeterminism {
    pub frozen_unix_ms: u64,
    pub rng_seed: [u8; 32],
}

impl ShadowDeterminism {
    /// The run determinism these are.
    #[must_use]
    pub const fn to_code_run(self) -> CodeRunDeterminism {
        CodeRunDeterminism::new(self.frozen_unix_ms, self.rng_seed)
    }
}

impl From<CodeRunDeterminism> for ShadowDeterminism {
    fn from(determinism: CodeRunDeterminism) -> Self {
        Self {
            frozen_unix_ms: determinism.frozen_unix_ms,
            rng_seed: determinism.rng_seed,
        }
    }
}

pub use crate::dreamer_runner::shadow_values::{
    ShadowIsolationRequired, ShadowMeterContext, ShadowModelPin, ShadowSandboxBinding, ShadowScope,
};

/// One arm to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowRunRequest {
    pub protocol_version: u32,
    pub arm_id: EntityId,
    pub target: ShadowTarget,
    pub source: ShadowSource,
    /// The inputs the caller expects the arm granted, each of them frozen
    /// from its source before the arm starts.
    pub input_refs: Vec<ShadowBodyRef>,
    /// The other bodies the caller expects the arm granted.
    pub body_refs: Vec<ShadowBodyRef>,
    pub determinism: ShadowDeterminism,
    /// The sampling seed the captured request carried, if any.
    pub model_seed: Option<u64>,
    pub model_pin: ShadowModelPin,
    pub meter: ShadowMeterContext,
    pub sandbox: ShadowSandboxBinding,
    pub scope: ShadowScope,
}

pub use crate::dreamer_runner::shadow_values::{ShadowUnavailable, ShadowUnavailableReason};

/// Why an arm's window was full, as a frame carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum ShadowWindowFullReason {
    InFlight,
    Suppressed { cause: String },
    NothingToCompact,
}

impl From<&WindowFullReason> for ShadowWindowFullReason {
    fn from(reason: &WindowFullReason) -> Self {
        match reason {
            WindowFullReason::InFlight => Self::InFlight,
            WindowFullReason::Suppressed(suppression) => Self::Suppressed {
                cause: suppression.as_str().to_owned(),
            },
            WindowFullReason::NothingToCompact => Self::NothingToCompact,
        }
    }
}

/// How an arm ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ShadowStatus {
    /// The captured step ran to its end; `done` when its program finished
    /// the run. Never a whole run's completion.
    StepComplete {
        done: bool,
    },
    Yielded {
        next_step_seq: u64,
    },
    Waiting {
        wait: Box<SelfDurableWait>,
    },
    WindowFull {
        next_step_seq: u64,
        reason: ShadowWindowFullReason,
    },
    /// The step failed as a run's step fails: `kind` names how, never with
    /// the error's text.
    Failed {
        kind: String,
    },
    Unavailable {
        unavailable: ShadowUnavailable,
    },
}

impl ShadowStatus {
    /// An executor's status, as a frame carries it: a whole run's
    /// completion is its last step's, done.
    #[must_use]
    pub fn of_executor(status: &EngineExecutorStatus) -> Self {
        match status {
            EngineExecutorStatus::Complete => Self::StepComplete { done: true },
            EngineExecutorStatus::Waiting(wait) => Self::Waiting {
                wait: Box::new(wait.clone()),
            },
            EngineExecutorStatus::Yielded { next_step_seq } => Self::Yielded {
                next_step_seq: *next_step_seq,
            },
            EngineExecutorStatus::WindowFull {
                next_step_seq,
                reason,
            } => Self::WindowFull {
                next_step_seq: *next_step_seq,
                reason: reason.into(),
            },
        }
    }
}

pub use crate::dreamer_runner::shadow_values::{
    ShadowBridgeWindow, ShadowIsolation, ShadowModelReceipt, ShadowTraceEntry, ShadowTraceKind,
    ShadowUsage,
};

/// What one captured step's run in an arm left: its status, its bodies and
/// its two traces, kept apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowStepRun {
    pub status: ShadowStatus,
    pub outputs: Vec<ShadowBodyRef>,
    pub effect_trace: ShadowBodyRef,
    pub bridge_trace: ShadowBodyRef,
    pub bridge: ShadowBridgeWindow,
    /// The type feedback of the program the arm ran, as it stood when the
    /// step ended (FIX 10389, fork d): the arm's own, under the arm's
    /// identity, never its source run's step. `None` when the arm ran no
    /// program of its own, or its source's content is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_feedback: Option<ProgramStepFeedback>,
}

pub use crate::dreamer_runner::shadow_values::ShadowArmLease;

/// What one arm answered.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowRunResult {
    pub protocol_version: u32,
    pub arm_id: EntityId,
    pub target: ShadowTarget,
    /// The executable that ran, once resolved; `None` for the baseline and
    /// for a candidate that never loaded.
    pub resolved_artifact_digest: Option<ArtifactDigest>,
    pub step: Option<ShadowStepIdentity>,
    /// The digest of the start the step ran from.
    pub source_digest: Option<[u8; 32]>,
    pub request_digest: Option<ShadowRequestDigest>,
    pub status: ShadowStatus,
    pub outputs: Vec<ShadowBodyRef>,
    pub bridge_trace: Option<ShadowBodyRef>,
    pub effect_trace: Option<ShadowBodyRef>,
    pub bridge: Option<ShadowBridgeWindow>,
    pub model_receipts: Vec<ShadowModelReceipt>,
    pub isolation: ShadowIsolation,
    pub lease: Option<ShadowArmLease>,
    /// The type feedback of the program the arm ran, as it stood when the
    /// arm answered (FIX 10389, fork d); its later result is read under the
    /// arm's lease alone. `None` for an arm that ran no program of its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub type_feedback: Option<ProgramStepFeedback>,
}

impl ShadowRunResult {
    /// The result of `request` at `status`, before anything of it ran.
    #[must_use]
    pub fn of_request(request: &ShadowRunRequest, status: ShadowStatus) -> Self {
        Self {
            protocol_version: request.protocol_version,
            arm_id: request.arm_id,
            target: request.target.clone(),
            resolved_artifact_digest: None,
            step: None,
            source_digest: None,
            request_digest: None,
            status,
            outputs: Vec::new(),
            bridge_trace: None,
            effect_trace: None,
            bridge: None,
            model_receipts: Vec::new(),
            isolation: ShadowIsolation::TrustedInProcessBaseline,
            lease: None,
            type_feedback: None,
        }
    }

    /// The result of `request`, unavailable for `unavailable`.
    #[must_use]
    pub fn unavailable(request: &ShadowRunRequest, unavailable: ShadowUnavailable) -> Self {
        Self::of_request(request, ShadowStatus::Unavailable { unavailable })
    }
}
