//! Moved from `crates/oneiron/src/code_run/contribution.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::code_run::contribution::admission::ForkMismatch;
pub use crate::code_run::contribution::execution::ExecutedBody;
pub use crate::code_run::contribution::execution::ExecutedStepStatus;
pub use crate::code_run::contribution::execution::ForkEvidenceMode;
pub use crate::code_run::contribution::execution::ForkJudge;
pub use crate::code_run::contribution::execution::ForkScore;
pub use crate::code_run::contribution::owner::OwnerJudgment;
pub(crate) use crate::code_run::contribution::owner::OwnerPairChoice;
pub(crate) use crate::code_run::contribution::owner::OwnerPairRoute;
pub use crate::code_run::contribution::source_admission::ContributionSourceConsumer;
pub use crate::code_run::contribution::source_admission::ContributionSourcePurpose;
pub use crate::code_run::contribution::source_admission::ContributionSourceReadRequest;
use crate::dreamer_runner::shadow_values::ShadowUnavailable;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use serde::Deserialize;
use serde::Serialize;

/// Why a matched pair cannot be run. None of these is a verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionReplayUnavailable {
    /// The anchor cannot judge a new output (a world outcome) or does not
    /// settle correctness. An owner verdict's pair is judged by the owner
    /// (FIX 3609).
    AnchorNotReplayable,
    /// The anchor does not resolve to a frozen case and rubric now.
    AnchorUnresolved,
    /// No capsule of the step the check regenerates.
    NoCapsule,
    /// That step's capsule was never finalized: no rung's answer was
    /// recorded for it.
    CapsuleNotFinalized,
    /// The capsule's or a fork's body is gone, withheld or no longer its
    /// hash, or its exposure no longer sits where it was captured.
    Unreadable,
    /// An erase retired the capsule's request or a fork's response body, or
    /// a fork writer found the capsule's content erased (FIX 6256).
    Erased,
    /// No knowledge exposure of the target in a captured step: the skill's
    /// body, or the edge's source's, as the host put it in the run's task,
    /// and no call of the skill's load, nor delivery of its body, that a
    /// step's replay context kept (FIX 3608). A result-only use, and an
    /// ancestor the run read through a verb, is not replayed.
    NoExposure,
    /// The target reached the run only as site knowledge on a browser
    /// observation (FIX 11436): it is recorded, but it has no byte span in
    /// the run's task to leave out.
    SiteObservation,
    /// The step carries the target at more than one revision.
    AmbiguousExposure,
    /// The target's record is at another revision than the one the step saw.
    SkillRevisionMoved,
    /// A stored fork came from another capsule or was scored by another
    /// rubric than the pair's now.
    ForksDiverged,
    /// The capsule's model, or the route prompt it answered under, is not
    /// served now.
    ModelUnavailable,
    /// The forks did not finish by the clock, or the scorer did not decide.
    /// A fork writer that found a subject of the pair gone now stops here
    /// too: a soft delete may be restored, so the stop is never lasting
    /// (FIX 6256). So does a pair whose reader is not admitted to its
    /// source now (FIX 20607): a Grant given later may admit it.
    Unfinished,
    /// An engine step's fork's program did not run against the captured
    /// step now (FIX 3607), for the shadow runner's own reason, one a retry
    /// may clear (no runtime now, a cancelled run). The pair waits for that
    /// one retry; a reason that holds then, or a lasting one, puts the pair
    /// in the `Text` mode instead. Never a loss of the program. A callable's
    /// or a delivery's pair (FIX 3608) stops here too when a branch of its
    /// caller's step did not run against the step's recorded calls, or the
    /// next step's request cannot take a branch's observation, for the
    /// shadow runner's reason.
    ProgramReplay(ShadowUnavailable),
}

impl ContributionReplayUnavailable {
    /// The reason's stable name; a program replay's is the shadow runner's
    /// own reason's name.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AnchorNotReplayable => "anchor_not_replayable",
            Self::AnchorUnresolved => "anchor_unresolved",
            Self::NoCapsule => "no_capsule",
            Self::CapsuleNotFinalized => "capsule_not_finalized",
            Self::Unreadable => "unreadable",
            Self::Erased => "erased",
            Self::NoExposure => "no_exposure",
            Self::SiteObservation => "site_observation",
            Self::AmbiguousExposure => "ambiguous_exposure",
            Self::SkillRevisionMoved => "skill_revision_moved",
            Self::ForksDiverged => "forks_diverged",
            Self::ModelUnavailable => "model_unavailable",
            Self::Unfinished => "unfinished",
            Self::ProgramReplay(unavailable) => unavailable.reason.as_str(),
        }
    }

    /// Whether the reason holds for good: the pair is recorded unavailable
    /// and no later pass pays for it again. A model not served now, an
    /// anchor that does not resolve now and a pass that ran out of time or
    /// met a subject gone now are asked again, as is a program replay the
    /// shadow runner says a retry may find available.
    #[must_use]
    pub const fn lasting(&self) -> bool {
        match self {
            Self::ProgramReplay(unavailable) => !unavailable.retryable,
            reason => !matches!(
                reason,
                Self::AnchorUnresolved | Self::ModelUnavailable | Self::Unfinished
            ),
        }
    }
}

/// Which side of the pair a fork is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkTreatment {
    /// The step as captured.
    WithSkill,
    /// The step with the target's exposure removed (the skill's body, or the
    /// edge's source's), and nothing else changed; for a callable's load or
    /// a delivered body (FIX 3608), the next step's request as its caller's
    /// step makes it once that load or body is absent.
    WithoutSkill,
}

/// A fork's frozen scoring identity: the canonical rubric digest and the
/// scorer-byte digest as resolved at prepare, before either fork. Both
/// forks of a pair copy it; admission rehashes the candidate against it.
/// The identity a fork is scored under is this and its score's evidence
/// mode, the execution pin in the `Executed` mode included (FIX 3607): both
/// forks of a pair share all of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForkScoringIdentity {
    pub rubric: [u8; 32],
    pub scorer: [u8; 32],
}

impl ForkScoringIdentity {
    fn of(anchor: &ReplayAnchor) -> Result<Self> {
        let encode =
            |error: serde_json::Error| Error::InvalidConfig(format!("replay anchor: {error}"));
        Ok(Self {
            rubric: *blake3::hash(&serde_json::to_vec(&anchor.rubric).map_err(encode)?).as_bytes(),
            scorer: *blake3::hash(anchor.scorer.as_bytes()).as_bytes(),
        })
    }
}

/// The frozen case and rubric both forks are scored against: the case is
/// the capsule's input, the rubric what the scorer resolved for the
/// candidate's anchor and axis.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayAnchor {
    pub rubric: serde_json::Value,
    /// The scorer and its revision.
    pub scorer: String,
}
pub mod admission;
pub mod execution;
pub mod owner;
pub mod source_admission;
