//! Moved from `crates/oneiron/src/dreamer_runner/shadow_values.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::step_replay::ReplayRoutePin;
use crate::dreamer_runner::step_replay::StoredRungBinding;
use oneiron_model::llm::LlmUsage;
use serde::Deserialize;
use serde::Serialize;

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

/// The model an arm's call goes to: the rung that answered the captured
/// call, and the route it went out on. A strict call goes out on exactly
/// these, or not at all. The rung names its route prompt by its capsule's
/// body and digest only (FIX 6255): no prompt text is in a pin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShadowModelPin {
    pub captured: StoredRungBinding,
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

/// The shadow protocol's version: a request or frame of another is
/// unavailable (`ProtocolUnsupported`). CALLS "shadow protocol version 1".
pub const SHADOW_PROTOCOL_VERSION: u32 = 1;
