//! Regen request and outcome decision path over behavior fingerprints.

use super::{GeneratedLens, LensBehaviorDiff, LensBehaviorFingerprint, LensVersionStamp};

/// Where a regeneration attempt stopped. Every variant preserves the last-good body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LensRegenFailurePhase {
    SummaryPromptRerun,
    Compile,
    Validate,
    GoldenRender,
    BehaviorDiff,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LensRegenFailure {
    phase: LensRegenFailurePhase,
    message: String,
}

impl LensRegenFailure {
    #[must_use]
    pub fn new(phase: LensRegenFailurePhase, message: impl Into<String>) -> Self {
        Self {
            phase,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn phase(&self) -> LensRegenFailurePhase {
        self.phase
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// A regeneration request carries the target contract stamp and nothing else — no
/// prompt, no source, no hash. The concrete regenerator is already bound to the lens
/// artifact's summary prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LensRegenRequest {
    target_version: LensVersionStamp,
}

impl LensRegenRequest {
    #[must_use]
    pub const fn new(target_version: LensVersionStamp) -> Self {
        Self { target_version }
    }

    #[must_use]
    pub const fn target_version(self) -> LensVersionStamp {
        self.target_version
    }
}

/// A validated lens paired with the behavior it produced over the golden corpus.
#[derive(Debug, Clone, PartialEq)]
pub struct LensEvaluatedRevision {
    lens: GeneratedLens,
    behavior: LensBehaviorFingerprint,
}

impl LensEvaluatedRevision {
    /// Trusted caller-owned seam. `behavior` must be the fingerprint produced by
    /// rendering `lens` over the same golden corpus used for the comparison.
    /// This constructor does not and cannot re-render to prove that pairing.
    #[must_use]
    pub const fn new(lens: GeneratedLens, behavior: LensBehaviorFingerprint) -> Self {
        Self { lens, behavior }
    }

    #[must_use]
    pub const fn lens(&self) -> &GeneratedLens {
        &self.lens
    }

    #[must_use]
    pub const fn behavior(&self) -> &LensBehaviorFingerprint {
        &self.behavior
    }

    #[must_use]
    pub fn into_lens(self) -> GeneratedLens {
        self.lens
    }
}

/// The injected regeneration seam. It is narrow on purpose: no model client, prompt
/// router, async worker, executor dependency, or cloud/local routing policy enters this
/// module. An implementation may schedule or await work internally before returning.
pub trait LensRegenerator {
    /// Re-run the summary prompt, compile/validate the candidate, render that
    /// candidate over the configured golden corpus, and return its fingerprint.
    /// Every failure is returned as a typed phase; never manufacture a blank lens.
    fn regenerate(
        &self,
        request: &LensRegenRequest,
    ) -> std::result::Result<LensEvaluatedRevision, LensRegenFailure>;
}

/// The adoption decision. There is no `None`, empty-body, or error-only return, so
/// fail-blank is impossible at this boundary.
#[derive(Debug, Clone, PartialEq)]
pub enum LensRegenOutcome {
    AutoAdopt {
        candidate: LensEvaluatedRevision,
        diff: LensBehaviorDiff,
    },
    NeedsHumanStamp {
        last_good: LensEvaluatedRevision,
        candidate: Box<LensEvaluatedRevision>,
        diff: LensBehaviorDiff,
    },
    RolledBack {
        last_good: LensEvaluatedRevision,
        failure: LensRegenFailure,
    },
}

impl LensRegenOutcome {
    /// The revision that remains mountable without any further approval.
    #[must_use]
    pub const fn active_revision(&self) -> &LensEvaluatedRevision {
        match self {
            Self::AutoAdopt { candidate, .. } => candidate,
            Self::NeedsHumanStamp { last_good, .. } | Self::RolledBack { last_good, .. } => {
                last_good
            }
        }
    }

    #[must_use]
    pub const fn diff(&self) -> Option<&LensBehaviorDiff> {
        match self {
            Self::AutoAdopt { diff, .. } | Self::NeedsHumanStamp { diff, .. } => Some(diff),
            Self::RolledBack { .. } => None,
        }
    }

    #[must_use]
    pub fn pending_candidate(&self) -> Option<&LensEvaluatedRevision> {
        match self {
            Self::NeedsHumanStamp { candidate, .. } => Some(candidate.as_ref()),
            Self::AutoAdopt { .. } | Self::RolledBack { .. } => None,
        }
    }
}

/// Run one regeneration and decide adoption.
///
/// The decision is binary: the same bound data reads may auto-adopt, changed bound data
/// reads need a human stamp. There is no severity score, no heuristic, and no fourth
/// outcome. The returned value performs nothing — the caller enacts adoption, routes the
/// candidate through the existing Proposed-approval flow, or keeps the last-good body.
#[must_use]
pub fn regenerate_lens<R: LensRegenerator + ?Sized>(
    regenerator: &R,
    request: &LensRegenRequest,
    last_good: LensEvaluatedRevision,
) -> LensRegenOutcome {
    // Regeneration always targets the live pair; a stale-targeted request is rejected
    // before the regenerator is ever invoked.
    if request.target_version() != LensVersionStamp::current() {
        return LensRegenOutcome::RolledBack {
            last_good,
            failure: LensRegenFailure::new(
                LensRegenFailurePhase::Validate,
                "regen request must target the live version pair",
            ),
        };
    }

    let candidate = match regenerator.regenerate(request) {
        Ok(candidate) => candidate,
        Err(failure) => return LensRegenOutcome::RolledBack { last_good, failure },
    };

    if candidate.lens().version_stamp() != request.target_version() {
        return LensRegenOutcome::RolledBack {
            last_good,
            failure: LensRegenFailure::new(
                LensRegenFailurePhase::Validate,
                "regenerated lens version does not match requested target",
            ),
        };
    }

    let diff = match LensBehaviorDiff::between(last_good.behavior(), candidate.behavior()) {
        Ok(diff) => diff,
        Err(error) => {
            return LensRegenOutcome::RolledBack {
                last_good,
                failure: LensRegenFailure::new(
                    LensRegenFailurePhase::BehaviorDiff,
                    error.to_string(),
                ),
            };
        }
    };

    if diff.has_data_read_change() {
        LensRegenOutcome::NeedsHumanStamp {
            last_good,
            candidate: Box::new(candidate),
            diff,
        }
    } else {
        LensRegenOutcome::AutoAdopt { candidate, diff }
    }
}
