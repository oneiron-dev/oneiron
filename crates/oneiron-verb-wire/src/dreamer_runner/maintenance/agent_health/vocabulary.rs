//! Moved from `crates/oneiron/src/dreamer_runner/maintenance/agent_health/vocabulary.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use oneiron_store::diagnostic_record::event::AgentHealthSignal;
use serde::Deserialize;
use serde::Serialize;

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

    pub const fn impact(self) -> u16 {
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

pub fn card_key(
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
