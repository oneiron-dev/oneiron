//! A publisher's candidates beyond an instruction (FIX 1661, 2144): a
//! candidate engine build, or a patch over its base build, each pinned by
//! its whole digest, and what a code fix keeps of the matched shadow pair it
//! runs for one. Nothing here fetches, installs or loads a candidate: the
//! host's shadow runner runs it in a sandboxed arm of its own, and until
//! that runner can (PR-S2a) every candidate arm is unavailable, kept so and
//! never a verdict. What the work row keeps of a pair is content-free: the
//! pin, the step and digests both arms ran from, each arm's status, isolation
//! and usage, and why a pair was not judged. No body, ref or lease of an arm
//! is kept.

use serde::{Deserialize, Serialize};

use crate::code_run::shadow_runner::{
    ArtifactDigest, ArtifactDigestAlgorithm, EngineArtifactPin, SHADOW_PROTOCOL_VERSION,
    ShadowArmLease, ShadowIsolation, ShadowMeterContext, ShadowRequestDigest, ShadowRunRequest,
    ShadowRunResult, ShadowStatus, ShadowStepIdentity, ShadowUnavailable, ShadowUsage,
};
use crate::compaction::output::OutputRef;
use crate::{EntityId, LlmInputUsage, LlmOutputUsage, Result};

/// What a publisher candidate is: an instruction the replay adds to the
/// failing agent's own, or a pinned engine the host's shadow runner runs in
/// a matched pair (FIX 1661, 2144). An engine candidate never becomes a
/// prompt string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublisherCandidateKind {
    /// The verified instruction file's text.
    Instruction { instruction: String },
    /// A candidate engine build, by its digest.
    EngineBuild { build: ArtifactDigest },
    /// A patch over its base build, by both digests.
    EnginePatch {
        build: ArtifactDigest,
        patch: ArtifactDigest,
    },
}

impl PublisherCandidateKind {
    /// The engine an engine candidate pins: its build, and its patch over
    /// that build. `None` for an instruction.
    #[must_use]
    pub fn engine_pin(&self) -> Option<EngineArtifactPin> {
        match self {
            Self::Instruction { .. } => None,
            Self::EngineBuild { build } => Some(EngineArtifactPin {
                build: *build,
                patch: None,
            }),
            Self::EnginePatch { build, patch } => Some(EngineArtifactPin {
                build: *build,
                patch: Some(*patch),
            }),
        }
    }
}

/// An artifact digest as the config and an exported token spell it: its
/// algorithm, a colon and all 64 lowercase hex digits (`blake3:…`,
/// `sha256:…`).
#[must_use]
pub fn artifact_digest_text(digest: &ArtifactDigest) -> String {
    let algorithm = match digest.algorithm {
        ArtifactDigestAlgorithm::Blake3 => "blake3",
        ArtifactDigestAlgorithm::Sha256 => "sha256",
    };
    format!(
        "{algorithm}:{}",
        crate::entity_id::bytes_to_hex_lower(&digest.digest)
    )
}

/// The digest `text` spells as [`artifact_digest_text`] does; `None` for
/// any other spelling, a shorter or upper-case one included.
#[must_use]
pub fn parse_artifact_digest_text(text: &str) -> Option<ArtifactDigest> {
    let (algorithm, hex) = text.split_once(':')?;
    let algorithm = match algorithm {
        "blake3" => ArtifactDigestAlgorithm::Blake3,
        "sha256" => ArtifactDigestAlgorithm::Sha256,
        _ => return None,
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(ArtifactDigest { algorithm, digest })
}

/// The host's shadow runner as a code fix drives it (FIX 1661, 2144), from
/// the Coach's blocking worker: each arm runs to its result on the host's
/// own runtime, and its bodies stay under its lease until it is released.
pub trait CodeFixShadowHost {
    /// Runs one arm of `request` to its result: run, or unavailable for a
    /// typed reason.
    ///
    /// # Errors
    ///
    /// A runner or storage failure, never an unavailable arm.
    fn run_arm(&self, request: ShadowRunRequest) -> Result<ShadowRunResult>;

    /// The whole body `body` of the arm `lease` holds, or why it cannot be
    /// read now.
    ///
    /// # Errors
    ///
    /// The arm's store failing.
    fn read_arm_body(
        &self,
        lease: &ShadowArmLease,
        body: OutputRef,
    ) -> Result<std::result::Result<Vec<u8>, ShadowUnavailable>>;

    /// Releases `lease`: its arm's bodies go.
    fn release_arm(&self, lease: &ShadowArmLease);

    /// What each arm's model calls are metered under: the same for both
    /// arms of a pair.
    fn arm_meter(&self) -> ShadowMeterContext;
}

/// One engine candidate's matched shadow pair as the failure's work row
/// keeps it (FIX 1661, 2144): content-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineCandidateRun {
    /// The candidate's build, and its patch over that build, whole.
    pub pin: EngineArtifactPin,
    /// The shadow protocol the pair ran at. A pair kept not run is tried
    /// once more once this engine speaks another.
    pub protocol_version: u32,
    /// The Coach's Grant that admitted the pair (FIX 6357), once one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<EntityId>,
    /// The captured step both arms ran from, once one was selected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step: Option<ShadowStepIdentity>,
    /// Which copy of the step's request both arms ran, by its digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<ShadowRequestDigest>,
    /// BLAKE3 of the start both arms ran from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_digest: Option<[u8; 32]>,
    /// Each arm that ran, in the order it ran: the candidate's, then the
    /// baseline's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arms: Vec<EngineArmSummary>,
    /// Judged, or why not.
    pub state: EnginePairState,
}

impl EngineCandidateRun {
    /// Whether the pair is tried again: kept not run at a shadow protocol
    /// other than this engine's (FIX 1661/2144). At one protocol it is tried
    /// once, whatever stopped it.
    pub(super) fn retries(&self) -> bool {
        matches!(self.state, EnginePairState::NotRun { .. })
            && self.protocol_version != SHADOW_PROTOCOL_VERSION
    }
}

/// What an engine candidate's pair came to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EnginePairState {
    /// Both arms ran their step to its end with every body whole, and the
    /// baseline failed the way the failure did: the run's outcome is the
    /// verdict, sealed by the export door.
    Judged,
    /// No verdict, for `reason`, and nothing exported.
    NotRun { reason: EngineNotRun },
}

/// Why an engine candidate's pair has no verdict. None of these is a loss or
/// a fix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineNotRun {
    /// The host has no shadow runner.
    NoRunner,
    /// The Coach's own Grant did not admit the pair (FIX 6357).
    Admission(EngineAdmission),
    /// The failing call has no captured executor step to run from: no
    /// capsule of it, or a workflow step's.
    NoCapturedStep,
    /// The captured step could not be read for an arm: the runner's reason.
    Source(ShadowUnavailable),
    /// An arm was unavailable: which, and the runner's reason, cause and
    /// retryability.
    Unavailable {
        arm: EngineArm,
        unavailable: ShadowUnavailable,
    },
    /// An arm ran and stopped short of its step's end: it failed, waits,
    /// yielded or filled its window.
    Ended {
        arm: EngineArm,
        status: EngineArmStatus,
    },
    /// An arm's evidence could not be read whole: a body partial, missing or
    /// undecodable.
    PartialEvidence { arm: EngineArm },
    /// An arm answered for another target, step, request, start or model
    /// pin than the pair named.
    Mismatch { arm: EngineArm },
    /// The candidate arm did not run sandboxed, or not the executable it
    /// pinned.
    NotIsolated,
    /// The baseline did not fail the way the failure did.
    NotReproduced,
    /// The ladder failed, abstained or answered off the contract.
    Undecided,
}

/// Why the Coach's Grant did not admit a pair (FIX 6357).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineAdmission {
    /// No live Grant of the Coach's, from an owner of this vault, confers
    /// read now on every world the failing run touched.
    NoGrant,
    /// The failing run's worlds cannot be proved, so no Grant can be held to
    /// them.
    ScopeUnproved,
    /// The Grant no longer reaches the run's worlds when the arms' bodies
    /// would be read.
    Lapsed,
}

/// Which arm of a pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineArm {
    /// The engine this host runs, trusted in its own process.
    Baseline,
    /// The publisher's candidate engine, sandboxed.
    Candidate,
}

/// What one arm of a pair answered, content-free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineArmSummary {
    /// Which arm it was.
    pub arm: EngineArm,
    /// The arm's id, fresh for it.
    pub arm_id: EntityId,
    /// The executable that ran, once its runner resolved one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_artifact_digest: Option<ArtifactDigest>,
    /// The digest of the start the arm's step ran from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_digest: Option<[u8; 32]>,
    /// Which copy of the step's request the arm ran, by its digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_digest: Option<ShadowRequestDigest>,
    /// How it ended.
    pub status: EngineArmStatus,
    /// The isolation the arm really ran under.
    pub isolation: ShadowIsolation,
    /// What each of its model calls used.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<EngineCallUsage>,
}

impl EngineArmSummary {
    /// What `result`, the arm `arm`'s, keeps.
    pub(super) fn of(arm: EngineArm, result: &ShadowRunResult) -> Self {
        Self {
            arm,
            arm_id: result.arm_id,
            resolved_artifact_digest: result.resolved_artifact_digest,
            source_digest: result.source_digest,
            request_digest: result.request_digest,
            status: EngineArmStatus::of(&result.status),
            isolation: result.isolation.clone(),
            calls: result
                .model_receipts
                .iter()
                .map(|receipt| EngineCallUsage::of(&receipt.usage))
                .collect(),
        }
    }
}

/// How an arm ended, content-free: a waiting arm keeps no wait.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum EngineArmStatus {
    /// Its captured step ran to its end; `done` when its program finished
    /// the run.
    StepComplete { done: bool },
    /// It yielded before its step's end.
    Yielded { next_step_seq: u64 },
    /// It parked on a wait.
    Waiting,
    /// Its window filled before its step's end.
    WindowFull { next_step_seq: u64 },
    /// Its step failed: `kind` names how, never with the error's text.
    Failed { kind: String },
    /// It did not run, or stopped, for the runner's typed reason.
    Unavailable { unavailable: ShadowUnavailable },
}

impl EngineArmStatus {
    /// The content-free form of `status`.
    pub(super) fn of(status: &ShadowStatus) -> Self {
        match status {
            ShadowStatus::StepComplete { done } => Self::StepComplete { done: *done },
            ShadowStatus::Yielded { next_step_seq } => Self::Yielded {
                next_step_seq: *next_step_seq,
            },
            ShadowStatus::Waiting { .. } => Self::Waiting,
            ShadowStatus::WindowFull { next_step_seq, .. } => Self::WindowFull {
                next_step_seq: *next_step_seq,
            },
            ShadowStatus::Failed { kind } => Self::Failed { kind: kind.clone() },
            ShadowStatus::Unavailable { unavailable } => Self::Unavailable {
                unavailable: unavailable.clone(),
            },
        }
    }
}

/// What one model call of an arm used, as its receipt says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum EngineCallUsage {
    /// The model answered, using these.
    Answered {
        input: LlmInputUsage,
        output: LlmOutputUsage,
    },
    /// The call went out and failed: what it used is unknown.
    DispatchedUnknown,
    /// The call never went out.
    NotDispatched,
}

impl EngineCallUsage {
    /// The counts of `usage`, without the provider's raw report.
    pub(super) fn of(usage: &ShadowUsage) -> Self {
        match usage {
            ShadowUsage::Answered { usage } => Self::Answered {
                input: usage.input,
                output: usage.output,
            },
            ShadowUsage::DispatchedUnknown => Self::DispatchedUnknown,
            ShadowUsage::NotDispatched => Self::NotDispatched,
        }
    }
}
