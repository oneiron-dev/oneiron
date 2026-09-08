//! Ladder state machine, transitions, human verdicts, lineage and delta-shape types.

use crate::entity_id::EntityId;
use crate::task_verb::TaskAssignee;

/// What a consult TASK is asking for.
///
/// `None` on the wire — and `Question` — are the SAME ONE-1699 shape: the
/// ref-only ask that landed before this ticket. Only `EntityDelta` requires
/// the typed artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsultPurpose {
    Question,
    EntityDelta,
}

impl ConsultPurpose {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Question => "question",
            Self::EntityDelta => "entity_delta",
        }
    }

    /// Parses one wire token, or `None` for an unknown one.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "question" => Some(Self::Question),
            "entity_delta" => Some(Self::EntityDelta),
            _ => None,
        }
    }
}

/// The STRUCTURAL descriptor of one proposed delta: operation family, target
/// class, and normalized field/edge paths. Deliberately value-free — a new
/// value in a known field is the same shape, a new field or operation family
/// is a new shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityDeltaShape {
    pub operation_kind: String,
    pub target_entity_type: u8,
    pub normalized_paths: Vec<String>,
}

impl EntityDeltaShape {
    /// Whether this descriptor decodes to exactly one structural shape.
    ///
    /// An untrimmed, control-bearing, empty, or duplicated path (or an
    /// operation kind of the same) leaves the shape AMBIGUOUS: two different
    /// deltas could normalize onto it. The novelty guard treats ambiguity as
    /// novelty, so this predicate decides whether an auto-through-grant is
    /// even representable.
    #[must_use]
    pub fn is_decodable(&self) -> bool {
        if !is_normalized_token(&self.operation_kind) || self.normalized_paths.is_empty() {
            return false;
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.normalized_paths.len());
        for path in &self.normalized_paths {
            if !is_normalized_token(path) || seen.contains(&path.as_str()) {
                return false;
            }
            seen.push(path);
        }
        true
    }
}

/// One structural token: non-empty, trimmed, and free of control characters.
fn is_normalized_token(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && !value.contains('\0')
}

/// The typed entity-delta a cross-actor consult carries. Every field is a REF:
/// discussion, explanations, and negotiation turns stay in MESSAGE/TURN records
/// reachable through `message_thread_ref` and never enter the TASK state
/// machine as prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntityDeltaArtifact {
    pub target_ref: EntityId,
    pub base_state_ref: Option<EntityId>,
    /// Existing durable typed artifact entity; never an inline raw patch.
    pub delta_ref: EntityId,
    pub shape: EntityDeltaShape,
    pub proposer_actor_ref: EntityId,
    pub owning_actor_ref: EntityId,
    pub message_thread_ref: Option<EntityId>,
}

/// Why a consult TASK exists in another task's lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsultLineageRelation {
    Counter,
    Appeal,
    Escalation,
}

impl ConsultLineageRelation {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Appeal => "appeal",
            Self::Escalation => "escalation",
        }
    }

    /// Parses one wire token, or `None` for an unknown one.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "counter" => Some(Self::Counter),
            "appeal" => Some(Self::Appeal),
            "escalation" => Some(Self::Escalation),
            _ => None,
        }
    }
}

/// A counter/appeal/escalation task's link to the record it answers. Absent on
/// an original request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsultLineage {
    pub relation: ConsultLineageRelation,
    pub parent_task_ref: EntityId,
}

/// Owner-agent deliberation or magistrate evaluation is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkingState {
    pub started_at: u64,
    /// Rounds of deliberation already spent. A repeated no-progress loop is a
    /// [`InterruptionKind::Pathology`] signal the caller reads off this.
    pub decision_round: u32,
}

/// Closed classifier for every admitted interruption. There is no `Other`
/// variant, so no branch can grow its way into asking a human.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptionKind {
    Contested,
    Critical,
    Pathology,
}

impl InterruptionKind {
    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Contested => "contested",
            Self::Critical => "critical",
            Self::Pathology => "pathology",
        }
    }
}

/// Progress is durably paused for a typed reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptedState {
    pub kind: InterruptionKind,
    /// `true` admits a human. It persists as ONE-1699's
    /// `TaskExecutionState::Interrupted` — not as a second consent system.
    pub consent_required: bool,
    pub case_ref: EntityId,
    pub interrupted_at: u64,
}

/// Terminal ladder outcome. `Rejected` is a completed decision; `Failed` is
/// retry/infrastructure semantics. Collapsing them would erase the difference
/// between "the owner said no" and "the machine broke".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LadderTerminalDisposition {
    Approved,
    Overridden,
    Rejected,
    Failed,
    Escalated,
    Countered,
    Abandoned,
}

impl LadderTerminalDisposition {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Overridden => "overridden",
            Self::Rejected => "rejected",
            Self::Failed => "failed",
            Self::Escalated => "escalated",
            Self::Countered => "countered",
            Self::Abandoned => "abandoned",
        }
    }

    /// Parses one wire token, or `None` for an unknown one.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "approved" => Some(Self::Approved),
            "overridden" => Some(Self::Overridden),
            "rejected" => Some(Self::Rejected),
            "failed" => Some(Self::Failed),
            "escalated" => Some(Self::Escalated),
            "countered" => Some(Self::Countered),
            "abandoned" => Some(Self::Abandoned),
            _ => None,
        }
    }

    /// Whether this outcome leaves the TASK non-terminal. `Escalated` hands
    /// the case to a follow-on assignee, so ONE-1699 persists it as
    /// `Interrupted` rather than as a terminal record.
    #[must_use]
    pub const fn defers_to_follow_on(self) -> bool {
        matches!(self, Self::Escalated)
    }
}

/// Immutable disposition plus its durable `result_ref`.
///
/// `result_ref` is a plain [`EntityId`], not an option: a terminal state
/// without a durable result is UNREPRESENTABLE rather than merely rejected,
/// and `EntityId` already refuses the all-zero sentinel at construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LadderTerminalState {
    pub disposition: LadderTerminalDisposition,
    pub result_ref: EntityId,
    /// Set exactly on [`LadderTerminalDisposition::Countered`]: the NEW task
    /// that replaced this one.
    pub counter_task_ref: Option<EntityId>,
    pub finished_at: u64,
}

impl LadderTerminalState {
    /// A terminal state is well-formed when its counter link matches its
    /// disposition: `Countered` names its successor, nothing else may.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        matches!(self.disposition, LadderTerminalDisposition::Countered)
            == self.counter_task_ref.is_some()
    }
}

/// The three top-level ladder phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsultLadderState {
    Working(WorkingState),
    Interrupted(InterruptedState),
    Terminal(LadderTerminalState),
}

impl ConsultLadderState {
    /// The terminal state, if the ladder has settled.
    #[must_use]
    pub const fn terminal(&self) -> Option<&LadderTerminalState> {
        match self {
            Self::Terminal(terminal) => Some(terminal),
            Self::Working(_) | Self::Interrupted(_) => None,
        }
    }
}

/// The three ladder moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LadderTransition {
    Interrupt(InterruptedState),
    Resume(WorkingState),
    Finish(LadderTerminalState),
}

/// Why a transition was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LadderTransitionError {
    /// A settled task never reopens — appeal, counter, and escalation mint new
    /// lineage-bearing records instead.
    TerminalImmutable,
    /// A consent-required interruption resumes only through a human verdict.
    ConsentRequired,
    /// A move with no meaning from this phase (including a no-op re-interrupt).
    InvalidTransition,
    /// A persisted ONE-1699 terminal record carried no `result_ref`, so it
    /// cannot be lifted into a ladder terminal state.
    MissingResultRef,
}

/// The whole ladder state machine, as one pure function.
///
/// # Errors
///
/// Returns [`LadderTransitionError`] for every refused move; the input state
/// is never mutated, so a refused transition preserves the original
/// field-for-field by construction.
pub fn transition_ladder(
    state: &ConsultLadderState,
    transition: LadderTransition,
) -> std::result::Result<ConsultLadderState, LadderTransitionError> {
    if state.terminal().is_some() {
        return Err(LadderTransitionError::TerminalImmutable);
    }
    match (state, transition) {
        (ConsultLadderState::Working(_), LadderTransition::Interrupt(next)) => {
            Ok(ConsultLadderState::Interrupted(next))
        }
        // Re-interrupting is how a contested case becomes a consent-required
        // one (a magistrate recusal, say). A re-interrupt to the SAME state is
        // a caller no-op, not a transition.
        (ConsultLadderState::Interrupted(current), LadderTransition::Interrupt(next)) => {
            if *current == next {
                Err(LadderTransitionError::InvalidTransition)
            } else {
                Ok(ConsultLadderState::Interrupted(next))
            }
        }
        (ConsultLadderState::Interrupted(current), LadderTransition::Resume(next)) => {
            if current.consent_required {
                Err(LadderTransitionError::ConsentRequired)
            } else {
                Ok(ConsultLadderState::Working(next))
            }
        }
        (
            ConsultLadderState::Working(_) | ConsultLadderState::Interrupted(_),
            LadderTransition::Finish(terminal),
        ) => {
            if terminal.is_well_formed() {
                Ok(ConsultLadderState::Terminal(terminal))
            } else {
                Err(LadderTransitionError::InvalidTransition)
            }
        }
        (ConsultLadderState::Working(_), LadderTransition::Resume(_))
        | (ConsultLadderState::Terminal(_), _) => Err(LadderTransitionError::InvalidTransition),
    }
}

/// The closed set of human verdicts. Override carries BOTH a durable delta and
/// a durable rationale by construction, and escalation reuses ONE-1699's
/// [`TaskAssignee`] — there is no stringly verdict parser and no `Other` arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HumanVerdict {
    Approve {
        rationale_ref: Option<EntityId>,
    },
    Reject {
        rationale_ref: Option<EntityId>,
    },
    OverrideWithDiff {
        delta_ref: EntityId,
        rationale_ref: EntityId,
    },
    Escalate {
        assignee: TaskAssignee,
        rationale_ref: EntityId,
    },
}

impl HumanVerdict {
    /// Stable wire token for the variant.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve { .. } => "approve",
            Self::Reject { .. } => "reject",
            Self::OverrideWithDiff { .. } => "override_with_diff",
            Self::Escalate { .. } => "escalate",
        }
    }
}

/// The ladder outcome one human verdict settles on.
#[must_use]
pub const fn terminal_for_human_verdict(verdict: HumanVerdict) -> LadderTerminalDisposition {
    match verdict {
        HumanVerdict::Approve { .. } => LadderTerminalDisposition::Approved,
        HumanVerdict::Reject { .. } => LadderTerminalDisposition::Rejected,
        HumanVerdict::OverrideWithDiff { .. } => LadderTerminalDisposition::Overridden,
        HumanVerdict::Escalate { .. } => LadderTerminalDisposition::Escalated,
    }
}
