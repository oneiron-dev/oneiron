//! Agent-health vocabulary: the `HEALTH_*` dial catalog and the card table.
//! Entry: `AgentHealthCard`, its tone, move, counter, confidence and outcome.
//! Owns `CARDS`, `Finding` and the `health:` card key and reference.

use serde::{Deserialize, Serialize};

use super::{
    AgentHealthCoachAsk, CARD_REF_PREFIX, ConcernMoveReceipt, HealthBriefPin, HealthCauseSource,
    HealthReviewReceipt, HealthSilenceActivity,
};
use crate::EntityId;
use crate::attempt_queue::AttemptId;
use crate::learning_setting::SettingSpec;
use crate::self_heal::AgentHealthSignal;
use crate::side_table::{self, Named, SideTable};

/// The review runs at all (1) or not (0).
pub const HEALTH_REVIEW: SettingSpec = SettingSpec {
    key: "health.review",
    min: 0.0,
    max: 1.0,
    seed: 1.0,
};

/// `loop`: identical calls in a row, with no other call between them.
pub const HEALTH_LOOP_REPEATS: SettingSpec = SettingSpec {
    key: "health.loop.repeats",
    min: 2.0,
    max: 100.0,
    seed: 3.0,
};

/// `failed_check_repeat`: the same tool run failing the same way, the canon
/// failure-ladder N.
pub const HEALTH_CHECK_FAILS: SettingSpec = SettingSpec {
    key: "health.check.fails",
    min: 2.0,
    max: 100.0,
    seed: 3.0,
};

/// `long_wait`: the share of an attempt's life spent waiting, not on a person.
pub const HEALTH_WAIT_SHARE: SettingSpec = SettingSpec {
    key: "health.wait.share",
    min: 0.05,
    max: 1.0,
    seed: 0.5,
};

/// `long_wait`: the shortest attempt life the share is judged over.
pub const HEALTH_WAIT_MINUTES: SettingSpec = SettingSpec {
    key: "health.wait.minutes",
    min: 1.0,
    max: 1440.0,
    seed: 10.0,
};

/// `silent`: minutes a leased attempt may go without activity of its own, a
/// call or a model step at its lease generation (OF-568 L5).
pub const HEALTH_SILENT_MINUTES: SettingSpec = SettingSpec {
    key: "health.silent.minutes",
    min: 1.0,
    max: 10080.0,
    seed: 30.0,
};

/// `misalignment`: widen proposals one attempt raised in the review window
/// that the board has not approved, pending or declined.
pub const HEALTH_WIDEN_DENIALS: SettingSpec = SettingSpec {
    key: "health.widen.denials",
    min: 1.0,
    max: 100.0,
    seed: 3.0,
};

/// `cost_spike`: an attempt's own spend over this many times its task type's
/// p90, or the plan's expected spend while the type has too few runs.
pub const HEALTH_COST_SPIKE: SettingSpec = SettingSpec {
    key: "health.cost.spike",
    min: 1.0,
    max: 100.0,
    seed: 3.0,
};

/// Hours an open card waits on its leader before the owner gets a copy.
pub const HEALTH_ESCALATE_TTL_HOURS: SettingSpec = SettingSpec {
    key: "health.escalate.ttl_hours",
    min: 1.0,
    max: 720.0,
    seed: 24.0,
};

/// The lowest card impact that still makes a card: struggling 100, off
/// course 150, concern 200, so a concern always does. A finding below it
/// writes its DIAGNOSTIC and no card.
pub const HEALTH_CARD_FLOOR: SettingSpec = SettingSpec {
    key: "health.card.floor",
    min: 0.0,
    max: 200.0,
    seed: 0.0,
};

/// `duplicate_work`: the least spend, in policy-budget units (tokens), that a
/// duplicate must cost to make a finding, so a cheap repeat is ignored. 0
/// keeps every duplicate.
pub const HEALTH_DUP_MIN_COST: SettingSpec = SettingSpec {
    key: "health.dup.min_cost",
    min: 0.0,
    max: 10_000_000.0,
    seed: 2_000.0,
};

/// The owner gets a copy of every card at once (1) or only of a concern, a
/// card on the project's leader, a card with no other recipient and a card
/// left open past the TTL (0). It only adds the owner: a concern always
/// reaches the owner, whatever this says.
pub const HEALTH_OWNER_COPY: SettingSpec = SettingSpec {
    key: "health.card.owner_copy",
    min: 0.0,
    max: 1.0,
    seed: 0.0,
};

/// Hours back one review reads receipts and settled attempts.
pub const HEALTH_REVIEW_WINDOW_HOURS: SettingSpec = SettingSpec {
    key: "health.review.window_hours",
    min: 1.0,
    max: 720.0,
    seed: 24.0,
};

/// `cost_spike`: the settled runs of a task type its p90 needs; with fewer,
/// the plan's expected spend is the baseline, at low confidence. It sets
/// the baseline only, never which work runs.
pub const HEALTH_COST_MIN_RUNS: SettingSpec = SettingSpec {
    key: "health.cost.min_runs",
    min: 1.0,
    max: 10_000.0,
    seed: 10.0,
};

/// Open cards, keyed `(actor, signal, task or zero)`.
pub(super) const CARDS: SideTable<([u8; 16], [u8; 1], [u8; 16]), AgentHealthCard, Named> =
    SideTable::new(&side_table::COACH_AGENT_HEALTH_CARD);

/// How a card reads (agent-mind §3.5).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthTone {
    /// Loops, failed checks, silence, long waits, cost.
    Struggling,
    /// Drift from the brief. No v1 signal reads this way.
    OffCourse,
    /// Misalignment. Always reaches the owner.
    Concern,
}

impl AgentHealthTone {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Struggling => "struggling",
            Self::OffCourse => "off_course",
            Self::Concern => "concern",
        }
    }

    #[must_use]
    pub const fn of(signal: AgentHealthSignal) -> Self {
        match signal {
            AgentHealthSignal::Misalignment => Self::Concern,
            AgentHealthSignal::Loop
            | AgentHealthSignal::FailedCheckRepeat
            | AgentHealthSignal::CostSpike
            | AgentHealthSignal::LongWait
            | AgentHealthSignal::Silent
            | AgentHealthSignal::DuplicateWork
            | AgentHealthSignal::UnsupportedDone => Self::Struggling,
        }
    }

    pub(super) const fn impact(self) -> u16 {
        match self {
            Self::Struggling => 100,
            Self::OffCourse => 150,
            Self::Concern => 200,
        }
    }
}

/// A move the card proposes. A leader or the owner takes it; the Coach never
/// does.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthMove {
    /// Say a note to the agent.
    Note,
    /// Steer it at its next safe breakpoint.
    Steer,
    /// Change its budget.
    Budget,
    /// Give the task to another seat.
    Reassign,
    /// Ask the Coach: a skill edit, or a prompt-inject plus fork-resume.
    AskCoach,
    /// Hold the run, resumably.
    Hold,
}

/// What lowers a signal, or names another possible cause.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthCounter {
    /// The repeated call got different answers: it may be polling.
    ResultsChanged,
    /// The repeated call was refused each time: the cause may be systemic.
    RefusedCalls,
    /// Most of the wait was in the queue: the cause may be systemic.
    QueueWait,
    /// Too few runs of the task type for a p90: the spend was held against
    /// the plan's expected spend.
    FewRuns,
    /// The attribution judge labelled the attempt's outcome `environment`: an
    /// outside fact may be the cause, and the card's `causes` name each label
    /// (OF-568 L10).
    EnvironmentCause,
    /// Another session of the same agent, another attempt or another lease
    /// generation of this one, made a call since this attempt's claim: it
    /// may be at work there. The card's `silence` names it; it never stands
    /// for this attempt's activity (OF-568 L5).
    OtherSessionActive,
}

/// Low when counter-evidence stands against the signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthConfidence {
    High,
    Low,
}

/// Set by the leader or the owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AgentHealthOutcome {
    Open,
    Confirmed,
    Dismissed,
    Unresolved,
}

impl AgentHealthOutcome {
    /// Parses an outcome a person sets; `open` is the review's alone.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "confirmed" => Some(Self::Confirmed),
            "dismissed" => Some(Self::Dismissed),
            "unresolved" => Some(Self::Unresolved),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Confirmed => "confirmed",
            Self::Dismissed => "dismissed",
            Self::Unresolved => "unresolved",
        }
    }
}

/// One agent-health card (agent-mind §3.5): one per actor, signal and task.
/// Repeats merge into it. It holds refs and numbers, never a diary body.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentHealthCard {
    /// The agent the card is about.
    pub subject: EntityId,
    pub signal: AgentHealthSignal,
    pub task: Option<EntityId>,
    /// The newest attempt the evidence came from.
    pub attempt: Option<EntityId>,
    /// Every attempt a merged finding named, oldest first: the nightly pass
    /// reads each one's late labels (FIX 8258). Neither `evidence` nor the
    /// watermark counts them.
    pub witnessed_attempts: Vec<EntityId>,
    pub tone: AgentHealthTone,
    /// 1: deterministic counts over receipts.
    pub tier: u8,
    pub confidence: AgentHealthConfidence,
    /// The `agent_health` DIAGNOSTIC events, newest last.
    pub diagnostics: Vec<EntityId>,
    /// Receipt and attempt ids, newest last.
    pub evidence: Vec<EntityId>,
    pub window_from: u64,
    pub window_to: u64,
    /// The number the dial was held against, and the dial.
    pub measured: i64,
    pub dial: i64,
    pub counter_evidence: Vec<AgentHealthCounter>,
    /// The agent said it was stuck: its TASK is Blocked.
    pub agent_blocked: bool,
    /// The attempt whose sealed receipt holds the agent's confession.
    pub confession: Option<EntityId>,
    pub moves: Vec<AgentHealthMove>,
    /// The leader, the spawner, the owners when they get a copy, and the Coach
    /// once an `environment` label stands in `causes` (OF-568 L10).
    pub recipients: Vec<EntityId>,
    pub owner_copy: bool,
    pub outcome: AgentHealthOutcome,
    pub outcome_by: Option<EntityId>,
    pub outcome_at: Option<u64>,
    /// Evidence count when the outcome was set. A settled card reopens only
    /// when its evidence grows past it.
    pub watermark: usize,
    pub opened_at: u64,
    pub updated_at: u64,
    /// The newest ask of the Coach (`ask_coach`), and its answer once drafted.
    #[serde(default)]
    pub coach: Option<AgentHealthCoachAsk>,
    /// The typed brief the newest finding's review observed on the TASK
    /// (`brief`): a witness, never a launch snapshot. An ask and an outcome
    /// receipt each keep their own copy.
    pub observed_brief: Option<HealthBriefPin>,
    /// The deterministic evaluator that judged the newest finding,
    /// `coach.agent_health.<signal>.v1`: the reviewer an outcome scores.
    pub reviewer: String,
    /// The `agent-health-review` skill revision whose policy seeded a dial of
    /// the newest finding's scope (`policy`): the revision an owner's outcome
    /// scores. `None` when owner rows, fits and the compiled seeds decided
    /// every dial.
    pub reviewer_revision: Option<EntityId>,
    /// Every outcome set on the card, oldest first, kept across reopens
    /// (`outcomes`).
    pub review_outcomes: Vec<HealthReviewReceipt>,
    /// The attribution judge's labels on the exact attempts behind the card
    /// when one is `environment` (OF-568 L10): each with its share and judge
    /// revision, oldest first, kept after its judge is displaced. The
    /// DIAGNOSTICs cite their source ids; `evidence` and the watermark never
    /// count them.
    pub causes: Vec<HealthCauseSource>,
    /// The activity the newest `silent` finding judged its attempt by
    /// (OF-568 L5): its own call and model step at its lease generation, its
    /// actor's newest call that names no attempt, and another session's
    /// newest call. While the card is open, a review that finds the attempt
    /// active again refreshes it to the activity it read (FIX 8376). `None`
    /// on every other signal. Neither `evidence` nor the watermark counts it,
    /// so it never reopens a settled card.
    pub silence: Option<HealthSilenceActivity>,
    /// Every note and steer taken through the card (`moves`), oldest first,
    /// kept across merges and reopens. Neither `evidence` nor the watermark
    /// counts them, so a move never reopens a settled card.
    pub moves_taken: Vec<ConcernMoveReceipt>,
}

impl AgentHealthCard {
    /// The card's handle: `health:<subject>:<signal>:<task or zeros>`.
    #[must_use]
    pub fn card_ref(&self) -> String {
        card_ref(&card_key(self.subject, self.signal, self.task))
    }
}

/// One detection before it merges into its card.
pub(super) struct Finding {
    pub(super) subject: EntityId,
    pub(super) signal: AgentHealthSignal,
    pub(super) task: Option<EntityId>,
    pub(super) attempt: Option<AttemptId>,
    pub(super) evidence: Vec<EntityId>,
    pub(super) window: (u64, u64),
    /// The stable number the DIAGNOSTIC carries, and the dial.
    pub(super) actual: i64,
    pub(super) dial: i64,
    /// The number the card shows; it may move while the evidence holds.
    pub(super) measured: i64,
    pub(super) counter: Vec<AgentHealthCounter>,
    pub(super) confession: Option<EntityId>,
    /// The agent said it was stuck: a Blocked TASK, or a blocked report since
    /// its attempt began.
    pub(super) blocked: bool,
    /// The TASK's typed brief as this review observed it (`brief`).
    pub(super) observed_brief: Option<HealthBriefPin>,
    /// The activity `silent` judged its attempt by (`silence`); `None` for
    /// every other signal.
    pub(super) silence: Option<HealthSilenceActivity>,
}

pub(super) fn card_key(
    subject: EntityId,
    signal: AgentHealthSignal,
    task: Option<EntityId>,
) -> ([u8; 16], [u8; 1], [u8; 16]) {
    let code = AgentHealthSignal::all()
        .iter()
        .position(|known| *known == signal)
        .unwrap_or_default() as u8;
    (
        *subject.as_bytes(),
        [code],
        task.map_or([0; 16], |task| *task.as_bytes()),
    )
}

pub(super) fn card_ref(key: &([u8; 16], [u8; 1], [u8; 16])) -> String {
    let signal = AgentHealthSignal::all()
        .get(usize::from(key.1[0]))
        .map_or("unknown", |signal| signal.as_str());
    format!(
        "{CARD_REF_PREFIX}{}:{signal}:{}",
        crate::entity_id::bytes_to_hex_lower(&key.0),
        crate::entity_id::bytes_to_hex_lower(&key.2)
    )
}

pub(crate) fn parse_card_ref(card: &str) -> Option<([u8; 16], [u8; 1], [u8; 16])> {
    let mut parts = card.strip_prefix(CARD_REF_PREFIX)?.split(':');
    let subject = EntityId::from_hex(parts.next()?).ok()?;
    let signal = AgentHealthSignal::from_wire(parts.next()?)?;
    let task = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let task = if task.bytes().all(|byte| byte == b'0') && task.len() == 32 {
        None
    } else {
        Some(EntityId::from_hex(task).ok()?)
    };
    Some(card_key(subject, signal, task))
}
