//! Amendment taxonomy: classes, causes, evidence and judgment types.

use crate::claim::{PREDICATE_ACTOR_EDIT_COST, PREDICATE_SKILL_EDIT_COST};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::skill_attribution::{
    AttemptOutcome, AttributionJudge, AttributionVerdict, OutcomeEvidence,
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
/// — the false-pass bias [`run_judge_audit`] exists to expose starts exactly
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

/// One routed amendment: the class, who owns it, and the Δ behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct AmendmentJudgment {
    /// The receipt this judgment routed.
    pub receipt_id: String,
    pub class: AmendmentClass,
    /// SKILL for a defect or a discovery, ACTOR for a lapse, `None` for the
    /// two classes that name no owner.
    pub subject: Option<EntityId>,
    /// The `(subject, scope)` axis the cost row is keyed on.
    pub scope: String,
    /// Receipt ids this verdict rests on (trace-or-derivation).
    pub evidence_receipts: Vec<String>,
    /// ED-01's measured edit mass for this amendment.
    pub d_norm: f32,
    pub at: u64,
}

/// One minted PREFERENCE proposal: the durable consequence of a
/// [`AmendmentClass::PreferenceShift`], and ED-04's inlet.
///
/// It names no subject deliberately. A preference shift says the proposal was
/// not wrong — so there is nobody to charge, and the thing worth mining is the
/// Δ itself, which the cited receipt resolves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferenceProposal {
    /// The amendment receipt whose Δ carries the preference.
    pub receipt_id: String,
    /// The scope the preference was expressed in.
    pub scope: String,
    /// Receipt ids the originating judgment rested on.
    pub evidence_receipts: Vec<String>,
    pub at: u64,
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Classifies one amendment, or ABSTAINS (`Ok(None)`) when the facts do not
/// settle it.
///
/// | cause | followed skill | skill covered it | class |
/// |---|---|---|---|
/// | external change | — | — | `Environment` |
/// | decider preference | — | — | `PreferenceShift` |
/// | proposal wrong | | | *delegated to `judge`* |
/// | unsettled | | | abstain |
///
/// The delegated arm is SK-04's table verbatim (lapse / defect / discovery),
/// reached by handing it the same evidence in its own shape. `judge` is the
/// tier seam: [`RuleAttributionJudge`] for the deterministic pass, a
/// host-supplied implementation for the model tier.
///
/// # Errors
///
/// Whatever `judge` returns.
pub fn classify_amendment(
    evidence: &AmendmentEvidence,
    judge: &dyn AttributionJudge,
) -> Result<Option<AmendmentClass>> {
    match evidence.cause {
        None => Ok(None),
        Some(AmendmentCause::ExternalChange) => Ok(Some(AmendmentClass::Environment)),
        Some(AmendmentCause::DeciderPreference) => Ok(Some(AmendmentClass::PreferenceShift)),
        Some(AmendmentCause::ProposalWrong) => judge.judge(&evidence.as_outcome_evidence()),
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
        AmendmentClass::Environment | AmendmentClass::PreferenceShift => None,
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
        | AmendmentClass::PreferenceShift => None,
    }
}
