//! Classification seam: the judge trait, the deterministic rule tier, and verdict routing.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::CallPurpose;

use super::types::{
    AttemptOutcome, AttributionVerdict, DeviationCause, FollowedState, HunkVerdict, JudgeRequest,
    OutcomeEvidence,
};

/// [`CallPurpose::Other`] name for the LLM classification tier. Ambiguous
/// evidence rides the EXISTING engine LLM call surface under this purpose —
/// this module mints no client stack of its own (see [`AttributionJudge`]).
pub const ATTRIBUTION_CALL_PURPOSE_NAME: &str = "skill_attribution";

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Classifies one piece of evidence, or ABSTAINS (`Ok(None)`) when it cannot.
///
/// Abstention is a first-class answer: a judge that guesses on unsettled facts
/// is exactly the false-pass bias [`run_attribution_audit`](crate::skill_attribution::run_attribution_audit) exists to expose.
///
/// The production LLM tier is a host-supplied implementation calling the
/// engine's existing LLM surface under [`attribution_call_purpose`]; this
/// module never constructs a client.
pub trait AttributionJudge {
    /// Returns the verdict for `evidence`, or `None` to abstain.
    fn judge(&self, evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>>;

    /// Labels each changed hunk of `request` (ARCH-0056 §5 #attribution-split),
    /// or ABSTAINS with `None`.
    ///
    /// Owes exactly [`JudgeRequest::regions`] answers, in hunk order: one per
    /// hunk, or one for an outcome with no edit. Each answer carries the
    /// judge's confidence. An answer that is `unclear`, or held below
    /// [`JudgeRequest::floor`], MUST carry a short note saying why — the
    /// engine refuses one without. That is why doubt is answered here and
    /// never from [`Self::judge`], which has no note to give. The engine still
    /// applies the floor and the lane's labels itself, so no judge can charge
    /// past them.
    ///
    /// The default is [`Self::judge`]'s one verdict on every hunk, fully
    /// confident: a judge that cannot split gives the 100% case of the same
    /// split, never a second path.
    fn judge_hunks(&self, request: &JudgeRequest<'_>) -> Result<Option<Vec<HunkVerdict>>> {
        Ok(self
            .judge(request.evidence)?
            .map(|verdict| vec![HunkVerdict::certain(verdict); request.regions()]))
    }

    /// Exact judge skill revision, if known. Used to mark its old verdicts
    /// when a replacement is admitted; unstamped verdicts remain unknown.
    fn judge_revision(&self) -> Option<&str> {
        None
    }
}

/// The [`CallPurpose`] an LLM-tier judge must stamp, so attribution calls are
/// budgeted and audited as their own class rather than hiding inside another
/// purpose's totals.
#[must_use]
pub fn attribution_call_purpose() -> CallPurpose {
    CallPurpose::Other {
        name: ATTRIBUTION_CALL_PURPOSE_NAME.to_owned(),
    }
}

/// The deterministic routing tier (ARCH-0053 §4).
///
/// | outcome | followed skill | skill covered step | verdict |
/// |---|---|---|---|
/// | failed | yes | yes | `SkillDefect` — the content was wrong |
/// | failed | ignored | — | `ExecutionLapse` — the executor ignored it |
/// | failed | partly | — | abstain — assess the partial work |
/// | failed | deviated with reason | — | resolved cause routes defect, discovery or lapse; otherwise abstain |
/// | failed | yes | no | `Discovery` — the content was missing |
/// | succeeded | — | — | abstain — a win attributes nothing here |
/// | any fact unsettled | | | abstain — the LLM tier's case |
///
/// A SUCCEEDED attempt abstains on purpose: this projector routes BLAME.
/// Crediting a win is the reliability posterior's job (ONE-1738), which reads
/// the same receipts.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleAttributionJudge;

impl AttributionJudge for RuleAttributionJudge {
    fn judge_revision(&self) -> Option<&str> {
        Some("rule-attribution@1")
    }
    fn judge(&self, evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
        if evidence.outcome != AttemptOutcome::Failed {
            return Ok(None);
        }
        if let Some(state) = &evidence.followed_state {
            match state {
                FollowedState::Ignored => return Ok(Some(AttributionVerdict::ExecutionLapse)),
                FollowedState::Partly => return Ok(None),
                FollowedState::DeviatedWithReason { cause, .. } => {
                    return Ok(match cause {
                        Some(DeviationCause::ExecutorError) => {
                            Some(AttributionVerdict::ExecutionLapse)
                        }
                        Some(DeviationCause::IncorrectInstruction) if evidence.skill.is_some() => {
                            Some(AttributionVerdict::SkillDefect)
                        }
                        Some(DeviationCause::MissingInstruction) if evidence.skill.is_some() => {
                            Some(AttributionVerdict::Discovery)
                        }
                        _ => None,
                    });
                }
                FollowedState::Followed => {}
            }
        } else {
            let Some(followed_skill) = evidence.followed_skill else {
                return Ok(None);
            };
            if !followed_skill {
                return Ok(Some(AttributionVerdict::ExecutionLapse));
            }
        }
        // The remaining branches attribute to the SKILL, so an evidence row
        // with no skill in the manifest cannot be routed: fail to the actor's
        // lane would be a fabrication, so abstain.
        let Some(skill_covered_step) = evidence.skill_covered_step else {
            return Ok(None);
        };
        if evidence.skill.is_none() {
            return Ok(None);
        }
        Ok(Some(if skill_covered_step {
            AttributionVerdict::SkillDefect
        } else {
            AttributionVerdict::Discovery
        }))
    }
}

/// The entity a verdict routes to, or `None` when it charges nobody.
///
/// Three labels route to nothing on purpose: an environment verdict blames no
/// entity at all, an unclear one holds until the Dreamer has clustered it, and
/// a preference shift is [`crate::edit_distance::attribution`]'s to turn into
/// a proposal (the attempt lane never admits one). None of them leaves a
/// judgment row, rather than charging the nearest actor.
pub(super) fn verdict_subject(
    verdict: AttributionVerdict,
    evidence: &OutcomeEvidence,
) -> Option<EntityId> {
    match verdict {
        AttributionVerdict::ExecutionLapse => Some(evidence.actor),
        AttributionVerdict::SkillDefect | AttributionVerdict::Discovery => evidence.skill,
        AttributionVerdict::Environment
        | AttributionVerdict::PreferenceShift
        | AttributionVerdict::Unclear => None,
    }
}
