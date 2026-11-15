//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/code_fix/publisher.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::dreamer_runner::shadow_values::ArtifactDigest;
use crate::dreamer_runner::shadow_values::EngineArtifactPin;
use crate::dreamer_runner::shadow_values::ShadowUsage;
use oneiron_model::llm::LlmInputUsage;
use oneiron_model::llm::LlmOutputUsage;
use serde::Deserialize;
use serde::Serialize;

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
    /// On a shared vault, every Grant that would admit the pair has lost its
    /// pact membership (FIX 7548), at either check: kept, and tried again
    /// once a covering Grant stands.
    PactStandingLapsed,
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
    pub fn of(usage: &ShadowUsage) -> Self {
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
