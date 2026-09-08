//! Classification seam: the judge trait, the deterministic rule tier, and verdict routing.

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::llm::CallPurpose;

use super::types::{AttemptOutcome, AttributionVerdict, OutcomeEvidence};

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
/// is exactly the false-pass bias [`run_attribution_audit`] exists to expose.
///
/// The production LLM tier is a host-supplied implementation calling the
/// engine's existing LLM surface under [`attribution_call_purpose`]; this
/// module never constructs a client.
pub trait AttributionJudge {
    /// Returns the verdict for `evidence`, or `None` to abstain.
    fn judge(&self, evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>>;
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
/// | failed | no | — | `ExecutionLapse` — the executor departed from it |
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
    fn judge(&self, evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
        if evidence.outcome != AttemptOutcome::Failed {
            return Ok(None);
        }
        let Some(followed_skill) = evidence.followed_skill else {
            return Ok(None);
        };
        if !followed_skill {
            return Ok(Some(AttributionVerdict::ExecutionLapse));
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

/// The entity a verdict routes to, or `None` when the evidence cannot carry it.
///
/// The two AMENDMENT-lane arms route to nothing HERE on purpose. This ledger
/// is the attempt lane's, and neither class names an attempt subject: an
/// environment verdict blames no entity at all, and a preference shift is
/// [`crate::edit_distance::attribution`]'s to turn into a proposal. A judge
/// that returns one anyway leaves no judgment row rather than charging the
/// nearest actor.
pub(super) fn verdict_subject(
    verdict: AttributionVerdict,
    evidence: &OutcomeEvidence,
) -> Option<EntityId> {
    match verdict {
        AttributionVerdict::ExecutionLapse => Some(evidence.actor),
        AttributionVerdict::SkillDefect | AttributionVerdict::Discovery => evidence.skill,
        AttributionVerdict::Environment | AttributionVerdict::PreferenceShift => None,
    }
}
