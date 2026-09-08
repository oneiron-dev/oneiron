//! Verdict taxonomy and row shapes: evidence in, judgments and edit proposals out.

use crate::entity_id::EntityId;

/// Schema version for every row this module persists.
pub const SKILL_ATTRIBUTION_SCHEMA_VERSION: u64 = 1;

// ---------------------------------------------------------------------------
// Verdict taxonomy (ARCH-0053 §4 — EmbodiSkill's)
// ---------------------------------------------------------------------------

/// How an attempt's outcome — or an amendment — is attributed.
///
/// The taxonomy lives in ARCH-0053/0056 prose; this is its first code home.
///
/// **One enum, two inlets.** The first three arms are the ATTEMPT lane's
/// (ARCH-0053 §4): an attempt failed, and the question is who to charge. The
/// last two are the AMENDMENT lane's (ARCH-0056 §5, ED-03/ONE-1759), where an
/// approval carries an edit and the extra question is whether anything was
/// WRONG at all. They share this enum rather than forking a parallel taxonomy
/// because the wrong-on-its-own-terms case routes through the very same
/// skill/actor ladder — [`crate::edit_distance::attribution`] pre-filters the
/// two amendment-only causes and delegates the rest to [`AttributionJudge`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttributionVerdict {
    /// The skill's content was wrong. Routes against the SKILL entity; the
    /// reliability CLAIM is ONE-1738's projection over these judgments.
    SkillDefect,
    /// The executor fumbled a skill that was correct. Routes against the ACTOR
    /// entity; `actor.lesson` / `actor.failure_mode` writes are ONE-1739's.
    ExecutionLapse,
    /// The skill was missing content the attempt needed. Deliberately NOT a
    /// claim on anything (§4): it becomes a skill EDIT PROPOSAL.
    Discovery,
    /// AMENDMENT lane only: the proposal was right when it was made, and an
    /// external fact moved under it. Blames nobody, and deliberately so —
    /// there is no ENVIRONMENT entity to carry a claim, and minting one would
    /// turn "nothing to attribute" into an attribution.
    Environment,
    /// AMENDMENT lane only: the proposal was not wrong; the decider wanted it
    /// otherwise. Routes to a PREFERENCE proposal
    /// ([`crate::edit_distance::attribution::pending_preference_proposals`]),
    /// never to an edit-cost claim — taste is a fact about the decider, not a
    /// defect in anyone's work.
    PreferenceShift,
}

impl AttributionVerdict {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SkillDefect => "skill_defect",
            Self::ExecutionLapse => "execution_lapse",
            Self::Discovery => "discovery",
            Self::Environment => "environment",
            Self::PreferenceShift => "preference_shift",
        }
    }

    /// Parses a stable wire string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "skill_defect" => Some(Self::SkillDefect),
            "execution_lapse" => Some(Self::ExecutionLapse),
            "discovery" => Some(Self::Discovery),
            "environment" => Some(Self::Environment),
            "preference_shift" => Some(Self::PreferenceShift),
            _ => None,
        }
    }

    /// True when this verdict routes to a gated skill EDIT PROPOSAL rather
    /// than to a claim on any entity (§4: discovery is not a claim).
    #[must_use]
    pub const fn mints_edit_proposal(self) -> bool {
        matches!(self, Self::Discovery)
    }
}

/// Terminal outcome of the attempt the evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AttemptOutcome {
    Succeeded,
    Failed,
}

impl AttemptOutcome {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }

    /// Parses a stable wire string.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "succeeded" => Some(Self::Succeeded),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// One attributable outcome, as recorded by the caller that observed it.
///
/// The `receipt_ref` is the id of the terminal PACK RECEIPT the attempt's
/// close stamped ([`crate::receipt::attempt_pack_receipt_id`]) — a string on
/// the landed spine, not an entity id. [`record_attribution_evidence`]
/// resolves it, and the `skill` must appear in that receipt's manifest, so a
/// verdict is always traceable back to the record that produced it.
///
/// The two `Option<bool>` facts are the routing inputs. `None` means the
/// evidence did not settle that fact — the rule tier then ABSTAINS rather than
/// guessing, and the ambiguous case is what the LLM tier exists for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeEvidence {
    /// RS1 receipt id of the attempt's terminal receipt.
    pub receipt_ref: String,
    /// The executing actor (agent, human, peer, connector — §4 r1).
    pub actor: EntityId,
    /// The SKILL entity implicated by the attempt's pack manifest, when one is.
    pub skill: Option<EntityId>,
    pub outcome: AttemptOutcome,
    /// Did the actor actually follow what the skill said?
    pub followed_skill: Option<bool>,
    /// Did the skill contain content covering the step that failed?
    pub skill_covered_step: Option<bool>,
    /// Unix seconds the outcome was observed.
    pub at: u64,
}

impl OutcomeEvidence {
    /// Builds evidence for one observed outcome. The routing facts default to
    /// unsettled; set them with [`Self::with_routing_facts`].
    #[must_use]
    pub fn new(
        receipt_ref: impl Into<String>,
        actor: EntityId,
        outcome: AttemptOutcome,
        at: u64,
    ) -> Self {
        Self {
            receipt_ref: receipt_ref.into(),
            actor,
            skill: None,
            outcome,
            followed_skill: None,
            skill_covered_step: None,
            at,
        }
    }

    /// Names the SKILL entity the attempt's pack manifest implicated.
    #[must_use]
    pub fn with_skill(mut self, skill: EntityId) -> Self {
        self.skill = Some(skill);
        self
    }

    /// Settles the two routing facts the rule tier reasons over.
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
}

/// One persisted, routed verdict. The stack's layers 2 and 3 read these rows:
/// ONE-1738 projects `skill.reliability` from the skill-subject judgments,
/// ONE-1739 writes `actor.*` from the actor-subject ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributionJudgment {
    /// Monotonic id: the evidence sequence this judgment was routed from.
    pub sequence: u64,
    pub verdict: AttributionVerdict,
    /// SKILL entity for `SkillDefect`/`Discovery`, ACTOR entity for
    /// `ExecutionLapse` — the routing decision, made concrete.
    pub subject: EntityId,
    /// RS1 receipt ids this verdict rests on (trace-or-derivation).
    pub evidence_receipts: Vec<String>,
    pub at: u64,
}

/// One minted skill EDIT PROPOSAL: the durable consequence of a DISCOVERY
/// verdict (§4 — discovery is never a claim).
///
/// The proposal names the skill that lacked content and CITES the judgment
/// that demanded it, so the gated apply can re-read the routing decision
/// rather than trusting the proposal's own word for why it exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkillEditProposal {
    /// The [`AttributionJudgment::sequence`] this proposal was minted from.
    pub judgment_sequence: u64,
    /// The SKILL entity whose content the attempt found missing.
    pub skill: EntityId,
    /// RS1 receipt ids the originating judgment rested on.
    pub evidence_receipts: Vec<String>,
    /// Unix seconds of the outcome that produced it.
    pub at: u64,
}
