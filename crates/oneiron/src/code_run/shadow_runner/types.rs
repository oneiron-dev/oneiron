//! The shadow runner's request, result and their parts (PR-S1): what a
//! caller asks an arm to run, by immutable identity only, and what the arm
//! answers, each part typed. An unavailable arm is a result with a typed
//! reason, never a loss and never a fix.

use serde::{Deserialize, Serialize};

use crate::code_run::{
    CapsuleRungBinding, CodeRunDeterminism, CodeRunRawOutput, ExecutorStepStart,
    ProgramStepFeedback, ReplayRoutePin, SelfDurableWait, StepReplayCapsule,
};
use crate::compaction::output::OutputRef;
use crate::engine_executor::{EngineExecutorStatus, WindowFullReason};
use crate::{EntityId, LlmUsage};

/// The algorithm an artifact digest is a digest of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactDigestAlgorithm {
    Blake3,
    Sha256,
}

/// One immutable artifact, by a digest that names its algorithm: a SHA-256
/// is never read as a BLAKE3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ArtifactDigest {
    pub algorithm: ArtifactDigestAlgorithm,
    pub digest: [u8; 32],
}

/// The executable identity of an engine an arm runs: its build, and the
/// patch over that build when there is one. The runner owns this shape; a
/// publisher candidate embeds it (L07-B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EngineArtifactPin {
    pub build: ArtifactDigest,
    pub patch: Option<ArtifactDigest>,
}

/// Which engine an arm runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target", rename_all = "snake_case")]
pub enum ShadowTarget {
    /// The engine this host runs, in its own process (PR-S1).
    Baseline,
    /// A publisher's candidate engine, by its id and pin. Until the
    /// candidate process runner lands (PR-S2) it is unavailable before any
    /// of its code is loaded.
    Candidate { id: String, pin: EngineArtifactPin },
}

/// One captured step of a canonical attempt: the key its capsule is kept
/// under, and the run it belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShadowStepIdentity {
    pub attempt: EntityId,
    pub lease_generation: u32,
    pub run: EntityId,
    pub step: u64,
}

impl ShadowStepIdentity {
    /// The step `capsule` captured.
    #[must_use]
    pub const fn of(capsule: &StepReplayCapsule) -> Self {
        Self {
            attempt: capsule.attempt,
            lease_generation: capsule.lease_generation,
            run: capsule.run,
            step: capsule.step,
        }
    }
}

/// A captured request's digest, saying which copy it is of (FIX 6144): the
/// request as it was sent, or its copy as stored, each secret in it masked
/// into its custody handle. A replay of a masked copy is never "as sent".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "of", content = "digest", rename_all = "snake_case")]
pub enum ShadowRequestDigest {
    AsSent([u8; 32]),
    AsStored([u8; 32]),
}

/// What an arm runs from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum ShadowSource {
    /// A captured request by its body ref and digest, and the step it was
    /// captured at: the shape a candidate process is handed (PR-S2).
    CapturedRequest {
        request: OutputRef,
        request_digest: ShadowRequestDigest,
        step: ShadowStepIdentity,
    },
    /// A step replay capsule by its key, with the request digest it must
    /// hold and, when the caller names it, the start it must hold.
    Capsule {
        step: ShadowStepIdentity,
        request_digest: ShadowRequestDigest,
        start: Option<ExecutorStepStart>,
    },
}

/// One whole body an arm holds or was granted, by its path and ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowBodyRef {
    /// Its path, as its run names its outputs.
    pub path: String,
    pub body: OutputRef,
    /// Whether its producer finished it; a partial body says so.
    pub complete: bool,
    /// The secret scan's reason when it marked the body: no read shows it.
    pub secret: Option<String>,
}

impl ShadowBodyRef {
    /// The ref of `output`, which the scan marked with `secret` if it did.
    #[must_use]
    pub(crate) fn of(output: &CodeRunRawOutput, secret: Option<&str>) -> Self {
        Self {
            path: output.path.clone(),
            body: output.output_ref(),
            complete: output.complete,
            secret: secret.map(str::to_owned),
        }
    }
}

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

/// The model an arm's call goes to: the rung that answered the captured
/// call, and the route it went out on. A strict call goes out on exactly
/// these, or not at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowModelPin {
    pub captured: CapsuleRungBinding,
    pub route: ReplayRoutePin,
}

/// What an arm's model calls are metered under, as the caller names it:
/// metadata the host checks, never authority. The host admits and meters
/// every call itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowMeterContext {
    /// The caller's run the arm's calls are receipted beside.
    pub host_run: String,
    /// Why the arm runs, as the receipts say.
    pub purpose: String,
    /// What one model call of the arm may spend.
    pub call_units: u64,
}

/// The isolation an arm must run under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowIsolationRequired {
    /// The trusted baseline, in the host's own process.
    TrustedInProcessBaseline,
    /// A sandboxed engine process (PR-S2).
    Sandboxed,
}

/// The sandbox an arm is bound to, as the host resolves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowSandboxBinding {
    pub isolation: ShadowIsolationRequired,
    pub profile_digest: Option<ArtifactDigest>,
    pub backend_binding_id: Option<String>,
}

/// How much of a run an arm runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowScope {
    /// The captured step alone, ending after it.
    CapturedStep,
    /// The whole run from the captured step.
    WholeRun,
}

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

/// Why an arm did not run, or stopped. None of these is a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowUnavailableReason {
    ProtocolUnsupported,
    CandidateEngineUnsupported,
    WholeRunUnsupported,
    ArtifactUnavailable,
    ArtifactDigestMismatch,
    SourceMissing,
    SourceWithheld,
    SourceDigestMismatch,
    RoutePinMissing,
    ModelUnavailable,
    RouteUnavailable,
    SandboxUnavailable,
    BridgeReplayMismatch,
    CapturedOutcomeMissing,
    Cancelled,
    HostAdmissionRefused {
        code: String,
    },
    ResourceUnavailable {
        resource: String,
    },
    /// A nested skill subtree, or a reader child, that was not captured as
    /// a replayable unit of its own.
    NestedReplayUnsupported,
    /// A call whose outcome the live guest read through a view the record
    /// does not keep (a revealed secret's answer).
    GuestViewCaptureMissing,
}

impl ShadowUnavailableReason {
    /// The reason's stable name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ProtocolUnsupported => "protocol_unsupported",
            Self::CandidateEngineUnsupported => "candidate_engine_unsupported",
            Self::WholeRunUnsupported => "whole_run_unsupported",
            Self::ArtifactUnavailable => "artifact_unavailable",
            Self::ArtifactDigestMismatch => "artifact_digest_mismatch",
            Self::SourceMissing => "source_missing",
            Self::SourceWithheld => "source_withheld",
            Self::SourceDigestMismatch => "source_digest_mismatch",
            Self::RoutePinMissing => "route_pin_missing",
            Self::ModelUnavailable => "model_unavailable",
            Self::RouteUnavailable => "route_unavailable",
            Self::SandboxUnavailable => "sandbox_unavailable",
            Self::BridgeReplayMismatch => "bridge_replay_mismatch",
            Self::CapturedOutcomeMissing => "captured_outcome_missing",
            Self::Cancelled => "cancelled",
            Self::HostAdmissionRefused { .. } => "host_admission_refused",
            Self::ResourceUnavailable { .. } => "resource_unavailable",
            Self::NestedReplayUnsupported => "nested_replay_unsupported",
            Self::GuestViewCaptureMissing => "guest_view_capture_missing",
        }
    }

    /// Whether the same request may be available later: a model, route or
    /// resource not there now, a host that refused admission now, or a
    /// cancelled arm. The rest hold for good for the same source and pins.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        matches!(
            self,
            Self::ModelUnavailable
                | Self::RouteUnavailable
                | Self::Cancelled
                | Self::HostAdmissionRefused { .. }
                | Self::ResourceUnavailable { .. }
        )
    }
}

/// Why an arm is unavailable: its reason, what caused it (a stable code,
/// never content), and whether a retry may find it available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowUnavailable {
    pub reason: ShadowUnavailableReason,
    pub cause: Option<String>,
    pub retryable: bool,
}

impl ShadowUnavailable {
    /// `reason`, caused by `cause`, with its own retryability.
    #[must_use]
    pub fn new(reason: ShadowUnavailableReason, cause: &str) -> Self {
        Self {
            retryable: reason.retryable(),
            reason,
            cause: Some(cause.to_owned()),
        }
    }
}

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

/// The isolation an arm really ran under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "isolation", rename_all = "snake_case")]
pub enum ShadowIsolation {
    /// The trusted baseline, in the host's own process: generated code in
    /// its sandbox, the engine around it the host's own. PR-S1 reports only
    /// this.
    TrustedInProcessBaseline,
    /// A sandboxed engine process, by its profile and backend binding.
    Sandboxed {
        profile_digest: ArtifactDigest,
        backend_binding_id: String,
    },
}

/// What one model call of an arm used.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ShadowUsage {
    /// The model answered, with this usage.
    Answered { usage: LlmUsage },
    /// The call went out and failed: what it used is unknown, and its
    /// reservation is charged.
    DispatchedUnknown,
    /// The call never went out: it used nothing.
    NotDispatched,
}

/// One model call of an arm, as the host admitted, sent and settled it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShadowModelReceipt {
    pub call_id: u32,
    /// The request as sent, in the arm's store, once the host built it.
    pub request: Option<ShadowBodyRef>,
    pub request_digest: ShadowRequestDigest,
    /// The pins the call had to go out on.
    pub expected: ShadowModelPin,
    /// The route the host's model would have sent it on, when it had one.
    pub served: Option<ReplayRoutePin>,
    /// The answer, in the arm's store.
    pub response: Option<ShadowBodyRef>,
    /// The run admission's receipts for the call, as they serialize.
    pub receipts: Vec<serde_json::Value>,
    pub usage: ShadowUsage,
    pub unavailable: Option<ShadowUnavailable>,
}

/// What kind of entry an arm's trace holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShadowTraceKind {
    /// A `self.*` call the arm's program made.
    Call,
    /// Speech the arm's reply carried after its program: a proposed intent
    /// only, never said.
    TrailingSpeech,
}

/// One entry of an arm's trace: in the proposed-effect trace, an effect the
/// arm's program asked for, as it asked, matched or not; in the bridge
/// trace, a recorded call it matched, with the outcome it was answered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowTraceEntry {
    pub kind: ShadowTraceKind,
    pub seq: u64,
    pub effect: String,
    /// Its canonical request, as MessagePack (trailing speech: its text).
    pub request: Vec<u8>,
    /// The recorded outcome it was answered with, as MessagePack; `None` in
    /// the proposed-effect trace.
    pub outcome: Option<Vec<u8>>,
}

/// Where a captured step's calls are in its run's bridge log, and how many
/// of them the arm matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShadowBridgeWindow {
    pub start: u64,
    pub end: u64,
    pub consumed: u64,
}

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

/// An opaque hold on an arm's bodies at its host: reads need it, and
/// releasing it frees them. A host gives one with every result that ran,
/// a failed or cancelled one too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ShadowArmLease(EntityId);

impl ShadowArmLease {
    /// A fresh lease.
    #[must_use]
    pub fn mint() -> Self {
        Self(EntityId::now())
    }

    /// Its name, for the host's own bookkeeping.
    #[must_use]
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

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
