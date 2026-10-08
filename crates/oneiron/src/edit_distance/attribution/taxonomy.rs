//! Amendment taxonomy: classes, causes, evidence and judgment types.

use crate::claim::{PREDICATE_ACTOR_EDIT_COST, PREDICATE_SKILL_EDIT_COST};
use crate::edit_distance::delta::delta_from_reconstructed;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill_attribution::{
    AttemptOutcome, AttributionJudge, AttributionLane, AttributionSplit, AttributionVerdict,
    EditHunk, JudgeRequest, OutcomeEvidence, classify_split,
};

// ---------------------------------------------------------------------------
// Taxonomy
// ---------------------------------------------------------------------------

/// The ARCH-0056 §5 amendment classes.
///
/// Deliberately an ALIAS of [`AttributionVerdict`] rather than a parallel enum:
/// the two lanes classify the same question about different evidence, and one
/// taxonomy is what keeps a downstream reader from having to learn two.
pub type AmendmentClass = AttributionVerdict;

/// Why the decider amended — the one fact the attempt lane never has to ask.
///
/// An attempt that FAILED is wrong by construction. An amendment rode an
/// APPROVAL, so wrongness is a question, and these three answers are what the
/// pre-filter in [`classify_amendment`] reasons over. `None` on the evidence
/// means the question is unsettled, and the judge abstains rather than guessing
/// — the false-pass bias [`run_judge_audit`](crate::edit_distance::attribution::run_judge_audit) exists to expose starts exactly
/// there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AmendmentCause {
    /// The proposal was wrong on its own terms. Routes down SK-04's ladder.
    ProposalWrong,
    /// The proposal was right when made; an external fact moved under it.
    ExternalChange,
    /// The proposal was not wrong; the decider wanted it otherwise.
    DeciderPreference,
}

impl AmendmentCause {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProposalWrong => "proposal_wrong",
            Self::ExternalChange => "external_change",
            Self::DeciderPreference => "decider_preference",
        }
    }

    /// Parses a pinned on-disk token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "proposal_wrong" => Some(Self::ProposalWrong),
            "external_change" => Some(Self::ExternalChange),
            "decider_preference" => Some(Self::DeciderPreference),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// One amendment, as the judge sees it: whose proposal was edited, in what
/// scope, and the facts that settle the class.
///
/// The `Option` facts are unsettled-by-default on purpose. A door that observed
/// an amendment but cannot say WHY records what it knows and lets the judge
/// abstain; inventing a cause to fill the slot is the failure this whole module
/// is instrumented against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmendmentEvidence {
    /// The receipt ED-01 measured this amendment's Δ against.
    pub receipt_id: String,
    /// The actor whose proposal was amended.
    pub actor: EntityId,
    /// The SKILL the proposal rode, when it rode one.
    pub skill: Option<EntityId>,
    /// The `(subject, scope)` axis the resulting cost row is keyed on.
    pub scope: String,
    /// Why the decider amended (see [`AmendmentCause`]).
    pub cause: Option<AmendmentCause>,
    /// Did the actor actually follow what the skill said?
    pub followed_skill: Option<bool>,
    /// Did the skill contain content covering what the decider changed?
    pub skill_covered_step: Option<bool>,
    /// Unix seconds the amendment was observed.
    pub at: u64,
}

impl AmendmentEvidence {
    /// Builds evidence for one observed amendment, with every routing fact
    /// unsettled.
    #[must_use]
    pub fn new(receipt_id: impl Into<String>, actor: EntityId, scope: impl Into<String>) -> Self {
        Self {
            receipt_id: receipt_id.into(),
            actor,
            skill: None,
            scope: scope.into(),
            cause: None,
            followed_skill: None,
            skill_covered_step: None,
            at: 0,
        }
    }

    /// Stamps when the amendment was observed.
    #[must_use]
    pub const fn at(mut self, at: u64) -> Self {
        self.at = at;
        self
    }

    /// Names the SKILL the amended proposal rode.
    #[must_use]
    pub const fn with_skill(mut self, skill: EntityId) -> Self {
        self.skill = Some(skill);
        self
    }

    /// Settles why the decider amended.
    #[must_use]
    pub const fn with_cause(mut self, cause: AmendmentCause) -> Self {
        self.cause = Some(cause);
        self
    }

    /// Settles the two facts SK-04's ladder reasons over.
    #[must_use]
    pub const fn with_routing_facts(
        mut self,
        followed_skill: bool,
        skill_covered_step: bool,
    ) -> Self {
        self.followed_skill = Some(followed_skill);
        self.skill_covered_step = Some(skill_covered_step);
        self
    }

    /// The attempt-lane shape of this evidence, for the delegated arm.
    ///
    /// [`AttemptOutcome::Failed`] is the honest stamp and not a convenience:
    /// this projection is only ever built for
    /// [`AmendmentCause::ProposalWrong`], and a proposal that had to be
    /// corrected did not succeed on its own terms.
    fn as_outcome_evidence(&self) -> OutcomeEvidence {
        let mut probe = OutcomeEvidence::new(
            self.receipt_id.as_str(),
            self.actor,
            AttemptOutcome::Failed,
            self.at,
        );
        probe.skill = self.skill;
        probe.followed_skill = self.followed_skill;
        probe.skill_covered_step = self.skill_covered_step;
        probe
    }
}

/// One class's share of a routed amendment, and who that share charges.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AmendmentShare {
    pub class: AmendmentClass,
    /// This class's share of the amendment's edit mass, in `0..=1`.
    pub share: f32,
    /// SKILL for a defect or a discovery, ACTOR for a lapse, `None` for the
    /// classes that name no owner.
    pub subject: Option<EntityId>,
}

/// One routed amendment: the label + share split, who each share charges,
/// and the Δ behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct AmendmentJudgment {
    /// The receipt this judgment routed.
    pub receipt_id: String,
    /// One entry per class the judge gave any changed hunk, shares summing to
    /// one (ARCH-0056 §5 #attribution-split). A single verdict is one class at
    /// `1.0`.
    pub split: Vec<AmendmentShare>,
    /// The `(subject, scope)` axis the cost row is keyed on.
    pub scope: String,
    /// Receipt ids this verdict rests on (trace-or-derivation).
    pub evidence_receipts: Vec<String>,
    /// ED-01's measured edit mass for this amendment.
    pub d_norm: f32,
    pub at: u64,
}

impl AmendmentJudgment {
    /// The share `class` holds, `0` when it holds none.
    #[must_use]
    pub fn share_of(&self, class: AmendmentClass) -> f32 {
        self.split
            .iter()
            .filter(|share| share.class == class)
            .map(|share| share.share)
            .sum()
    }

    /// The one class, when a single class holds the whole amendment.
    #[must_use]
    pub fn sole_class(&self) -> Option<AmendmentClass> {
        match self.split.as_slice() {
            [only] => Some(only.class),
            _ => None,
        }
    }

    /// Whether every share is `unclear`: nothing in this amendment may be
    /// acted on until the Dreamer has clustered it.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.split
            .iter()
            .all(|share| share.class == AmendmentClass::Unclear)
    }
}

/// One minted PREFERENCE proposal: the durable consequence of a
/// [`AmendmentClass::PreferenceShift`], and ED-04's inlet.
///
/// It names no subject deliberately. A preference shift says the proposal was
/// not wrong — so there is nobody to charge, and the thing worth mining is the
/// Δ itself, which the cited receipt resolves.
#[derive(Debug, Clone, PartialEq)]
pub struct PreferenceProposal {
    /// The amendment receipt whose Δ carries the preference.
    pub receipt_id: String,
    /// The scope the preference was expressed in.
    pub scope: String,
    /// Receipt ids the originating judgment rested on.
    pub evidence_receipts: Vec<String>,
    /// The `preference_shift` share of the amendment's edit mass: the part of
    /// the edit this note speaks for.
    pub share: f32,
    pub at: u64,
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Classifies one amendment into a label + share split, or ABSTAINS
/// (`Ok(None)`) when the facts do not settle it.
///
/// | cause | class of every hunk |
/// |---|---|
/// | external change | `Environment` |
/// | decider preference | `PreferenceShift` |
/// | proposal wrong | *the judge's, hunk by hunk* |
/// | unsettled | abstain |
///
/// `hunks` are the changed regions as the host cut them; each weighs its own
/// edit mass, measured here with the pinned reconstructed-lane metric. With no
/// hunks the amendment is one region and the split is one class at 100% — the
/// same path, not a second one. A settled cause answers for every hunk; the
/// `ProposalWrong` arm hands the judge SK-04's own evidence shape, and the
/// judge may split it across any label the amendment lane admits.
/// [`RuleAttributionJudge`](crate::skill_attribution::RuleAttributionJudge) is
/// the deterministic pass; a host-supplied judge is the model tier.
///
/// Every answer then meets `floor` (the `attribution_unclear_floor` setting):
/// a hunk held below it is `unclear`.
///
/// # Errors
///
/// Whatever `judge` returns.
pub fn classify_amendment(
    evidence: &AmendmentEvidence,
    judge: &dyn AttributionJudge,
    hunks: &[EditHunk<'_>],
    floor: f32,
) -> Result<Option<AttributionSplit>> {
    let settled = match evidence.cause {
        None => return Ok(None),
        Some(AmendmentCause::ExternalChange) => Some(AmendmentClass::Environment),
        Some(AmendmentCause::DeciderPreference) => Some(AmendmentClass::PreferenceShift),
        Some(AmendmentCause::ProposalWrong) => None,
    };
    let masses: Vec<f64> = hunks
        .iter()
        .map(|hunk| {
            delta_from_reconstructed(hunk.before, hunk.after)
                .ops_summary
                .edit_mass()
        })
        .collect();
    let probe = evidence.as_outcome_evidence();
    let request = JudgeRequest {
        lane: AttributionLane::Amendment,
        evidence: &probe,
        hunks,
    };
    match settled {
        Some(class) => classify_split(&SettledCause(class), &request, &masses, floor),
        None => classify_split(judge, &request, &masses, floor),
    }
}

/// The answer a settled cause gives: its class, certain, for every hunk.
struct SettledCause(AmendmentClass);

impl AttributionJudge for SettledCause {
    fn judge(&self, _evidence: &OutcomeEvidence) -> Result<Option<AttributionVerdict>> {
        Ok(Some(self.0))
    }
}

/// The entity a class charges, or `None` when it charges nobody.
pub(super) fn class_subject(
    class: AmendmentClass,
    evidence: &AmendmentEvidence,
) -> Option<EntityId> {
    match class {
        AmendmentClass::ExecutionLapse => Some(evidence.actor),
        AmendmentClass::SkillDefect | AmendmentClass::Discovery => evidence.skill,
        AmendmentClass::Environment | AmendmentClass::PreferenceShift | AmendmentClass::Unclear => {
            None
        }
    }
}

/// Which `*.edit_cost` row a class earns, or `None` when it earns none.
///
/// `Discovery` earns nothing HERE: missing content is SK-04's edit-proposal
/// case, and charging the skill for content it never claimed to have would
/// double-book a signal that already has a consequence.
pub(super) const fn cost_predicate(class: AmendmentClass) -> Option<&'static str> {
    match class {
        AmendmentClass::ExecutionLapse => Some(PREDICATE_ACTOR_EDIT_COST),
        AmendmentClass::SkillDefect => Some(PREDICATE_SKILL_EDIT_COST),
        AmendmentClass::Discovery
        | AmendmentClass::Environment
        | AmendmentClass::PreferenceShift
        | AmendmentClass::Unclear => None,
    }
}
