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
/// **One enum, two inlets.** The ATTEMPT lane (ARCH-0053 §4) judges a failed
/// attempt; the AMENDMENT lane (ARCH-0056 §5, ED-03/ONE-1759) judges an
/// approval that carried an edit, where the extra question is whether anything
/// was WRONG at all. They share this enum rather than forking a parallel
/// taxonomy because the wrong-on-its-own-terms case routes through the very
/// same skill/actor ladder — [`crate::edit_distance::attribution`] pre-filters
/// the amendment causes and delegates the rest to
/// [`AttributionJudge`](crate::skill_attribution::AttributionJudge). Every label
/// is valid in both lanes except [`Self::PreferenceShift`]
/// ([`Self::valid_in`]).
///
/// A verdict is a SPLIT, not one label (owner, 2026-10-08): the judge labels
/// each changed hunk, and [`AttributionSplit`] carries each label's share of
/// the edit mass. One label at 100% is the simple case.
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
    /// Either lane: the work was right when it was made, and an external fact
    /// moved under it. Blames nobody, and deliberately so — there is no
    /// ENVIRONMENT entity to carry a claim, and minting one would turn
    /// "nothing to attribute" into an attribution.
    Environment,
    /// AMENDMENT lane only: the proposal was not wrong; the decider wanted it
    /// otherwise. Routes to a PREFERENCE proposal
    /// ([`crate::edit_distance::attribution::pending_preference_proposals`]),
    /// never to an edit-cost claim — taste is a fact about the decider, not a
    /// defect in anyone's work. A failed attempt is measured against its own
    /// stated goal, so taste never explains one.
    PreferenceShift,
    /// Either lane: no label fits, or the judge's confidence fell below the
    /// [`attribution_unclear_floor`](crate::learning_setting::ATTRIBUTION_UNCLEAR_FLOOR)
    /// setting (ARCH-0056 §5 #unclear). It HOLDS: it charges nobody and makes
    /// no reliability update. Its note lands in the unclear ledger
    /// ([`crate::skill_attribution::unclear_attributions`]), where the Dreamer
    /// clusters the notes into a new label once a pattern forms.
    Unclear,
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
            Self::Unclear => "unclear",
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
            "unclear" => Some(Self::Unclear),
            _ => None,
        }
    }

    /// Every label, in the order a split lists its shares.
    pub const ALL: [Self; 6] = [
        Self::SkillDefect,
        Self::ExecutionLapse,
        Self::Discovery,
        Self::Environment,
        Self::PreferenceShift,
        Self::Unclear,
    ];

    /// Whether the judge may answer this label in `lane` (ARCH-0056 §5
    /// #label-lanes). Only taste is lane-bound: an outside fact can break an
    /// attempt as well as an approval, but a failed attempt is measured
    /// against its stated goal, and taste shows up as an amendment.
    #[must_use]
    pub const fn valid_in(self, lane: AttributionLane) -> bool {
        !matches!(
            (self, lane),
            (Self::PreferenceShift, AttributionLane::Attempt)
        )
    }

    /// True when this verdict routes to a gated skill EDIT PROPOSAL rather
    /// than to a claim on any entity (§4: discovery is not a claim).
    #[must_use]
    pub const fn mints_edit_proposal(self) -> bool {
        matches!(self, Self::Discovery)
    }
}

/// The two inlets the one judge serves (ARCH-0056 §5 #label-lanes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttributionLane {
    /// A failed attempt (ARCH-0053 §4).
    Attempt,
    /// An approval that carried an edit (ARCH-0056 §5).
    Amendment,
}

impl AttributionLane {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attempt => "attempt",
            Self::Amendment => "amendment",
        }
    }

    /// Parses a pinned on-disk token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "attempt" => Some(Self::Attempt),
            "amendment" => Some(Self::Amendment),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Split verdicts (ARCH-0056 §5 #attribution-split)
// ---------------------------------------------------------------------------

/// One changed region of an edit, as the host that holds both texts cut it.
///
/// The judge reads the two sides to label the region; the engine measures the
/// region's edit mass itself, with the pinned ED metric, so a host decides
/// where a hunk starts and ends but never how much it weighs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EditHunk<'a> {
    pub before: &'a str,
    pub after: &'a str,
}

/// What the judge is asked about one outcome.
#[derive(Debug, Clone, Copy)]
pub struct JudgeRequest<'a> {
    pub lane: AttributionLane,
    pub evidence: &'a OutcomeEvidence,
    /// The changed hunks, in text order. Empty when the outcome carries no
    /// edit (a failed attempt): the judge then answers once, for the whole
    /// outcome.
    pub hunks: &'a [EditHunk<'a>],
    /// The `attribution_unclear_floor` in force. An answer held below it is
    /// `unclear`, and like every `unclear` answer it must say why.
    pub floor: f32,
}

impl JudgeRequest<'_> {
    /// How many answers the judge owes: one per hunk, or one for an outcome
    /// with no edit.
    #[must_use]
    pub fn regions(&self) -> usize {
        self.hunks.len().max(1)
    }
}

/// The judge's answer for one hunk (or for a whole outcome with no edit).
#[derive(Debug, Clone, PartialEq)]
pub struct HunkVerdict {
    pub verdict: AttributionVerdict,
    /// The judge's confidence in `verdict`, in `0..=1`. Below the
    /// `attribution_unclear_floor` setting the hunk is recorded as `unclear`.
    pub confidence: f32,
    /// Why, in the judge's own words. Expected on every `unclear` answer: the
    /// note is what the Dreamer clusters.
    pub note: Option<String>,
}

impl HunkVerdict {
    /// A verdict the judge is certain of — the deterministic tier's only kind.
    #[must_use]
    pub const fn certain(verdict: AttributionVerdict) -> Self {
        Self {
            verdict,
            confidence: 1.0,
            note: None,
        }
    }

    /// A verdict held at `confidence`.
    #[must_use]
    pub const fn with_confidence(verdict: AttributionVerdict, confidence: f32) -> Self {
        Self {
            verdict,
            confidence,
            note: None,
        }
    }

    /// Attaches the judge's note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// One label's share of an outcome's edit mass.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AttributionShare {
    pub verdict: AttributionVerdict,
    /// In `0..=1`; an outcome's shares sum to one.
    pub share: f32,
}

/// Why a hunk was recorded as `unclear`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnclearReason {
    /// The judge answered `unclear`: no label fits.
    NoLabelFits,
    /// The judge named a label below the `attribution_unclear_floor` setting.
    BelowFloor,
    /// The judge named a label its lane does not admit.
    OutsideLane,
}

impl UnclearReason {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoLabelFits => "no_label_fits",
            Self::BelowFloor => "below_floor",
            Self::OutsideLane => "outside_lane",
        }
    }

    /// Parses a pinned on-disk token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "no_label_fits" => Some(Self::NoLabelFits),
            "below_floor" => Some(Self::BelowFloor),
            "outside_lane" => Some(Self::OutsideLane),
            _ => None,
        }
    }
}

/// One `unclear` hunk, as the Dreamer will cluster it.
#[derive(Debug, Clone, PartialEq)]
pub struct UnclearNote {
    pub reason: UnclearReason,
    /// The label the judge leaned to, when it named one.
    pub leaning: Option<AttributionVerdict>,
    pub confidence: f32,
    /// This hunk's share of the outcome's edit mass.
    pub share: f32,
    pub note: Option<String>,
}

/// One judged outcome: a label + share vector summing to one, and a note for
/// every hunk that landed `unclear`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AttributionSplit {
    /// One entry per label that holds a positive share, in
    /// [`AttributionVerdict::ALL`] order.
    pub shares: Vec<AttributionShare>,
    pub unclear: Vec<UnclearNote>,
}

impl AttributionSplit {
    /// The share `verdict` holds, `0` when it holds none.
    #[must_use]
    pub fn share_of(&self, verdict: AttributionVerdict) -> f32 {
        self.shares
            .iter()
            .find(|share| share.verdict == verdict)
            .map_or(0.0, |share| share.share)
    }

    /// The one label, when a single label holds the whole outcome.
    #[must_use]
    pub fn sole(&self) -> Option<AttributionVerdict> {
        match self.shares.as_slice() {
            [only] => Some(only.verdict),
            _ => None,
        }
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

/// Observed use of one loaded skill in a terminal attempt (ARCH-0053 §4).
/// A deviation keeps the actor's own stated reason, not just a false score.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FollowedState {
    Followed,
    Partly,
    Ignored,
    DeviatedWithReason {
        reason: String,
        /// A resolved cause is a fact from the receipt source, not a verdict.
        /// If unsettled, the rule judge abstains and an injected judge can
        /// inspect the original reason instead of guessing from its wording.
        cause: Option<DeviationCause>,
    },
}

/// Structured cause of a stated departure, when the source can establish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviationCause {
    IncorrectInstruction,
    MissingInstruction,
    ExecutorError,
}

/// One attributable outcome, as recorded by the caller that observed it.
///
/// The `receipt_ref` is the id of the terminal PACK RECEIPT the attempt's
/// close stamped ([`crate::receipt::attempt_pack_receipt_id`]) — a string on
/// the landed spine, not an entity id. [`record_attribution_evidence`](crate::skill_attribution::record_attribution_evidence)
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
    /// Four-state TASK-lane observation; the older boolean inlet remains for
    /// amendment evidence and callers that cannot yet resolve a full state.
    pub followed_state: Option<FollowedState>,
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
            followed_state: None,
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

    /// Records the observed state for one loaded skill. The receipt sweep uses
    /// this instead of reducing partly/deviated evidence to a boolean.
    #[must_use]
    pub fn with_followed_state(mut self, state: FollowedState) -> Self {
        self.followed_state = Some(state);
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
