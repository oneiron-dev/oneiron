//! Immutable shadow-run artifact, request-part and evidence vocabulary.

use crate::compaction::output::OutputRef;
use crate::dreamer_runner::step_replay::{
    CapsuleRequest, CapsuleRungBinding, ExecutorStepStart, ReplayRoutePin, StepReplayCapsule,
};
use crate::store::result_manifest::CodeRunRawOutput;
use crate::{EntityId, LlmUsage};
use serde::{Deserialize, Serialize};

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
    /// An erase retired the captured request or start body.
    SourceErased,
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
            Self::SourceErased => "source_erased",
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

impl ShadowRequestDigest {
    /// The digest of the copy of its request `capsule` keeps: the request as
    /// sent, or its masked copy as stored; `None` for a request the wall
    /// withheld (FIX 6254).
    #[must_use]
    pub fn of_capsule(capsule: &StepReplayCapsule) -> Option<Self> {
        match &capsule.request {
            CapsuleRequest::Kept { stored_hash, .. } if *stored_hash == capsule.request_hash => {
                Some(Self::AsSent(capsule.request_hash))
            }
            CapsuleRequest::Kept { stored_hash, .. } => Some(Self::AsStored(*stored_hash)),
            CapsuleRequest::Withheld { .. } => None,
        }
    }
}

/// The shadow protocol's version: a request or frame of another is
/// unavailable (`ProtocolUnsupported`). CALLS "shadow protocol version 1".
pub const SHADOW_PROTOCOL_VERSION: u32 = 1;
