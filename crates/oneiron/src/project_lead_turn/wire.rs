//! The verbs' requests and answers.

use serde::{Deserialize, Serialize};

use super::{
    LeadTurn, LeadTurnCause, LeadTurnOpen, LeadTurnOutcome, LeadTurnRegistration, LeadTurnSettings,
};
use crate::EntityId;

/// `vault.projects.lead_turns.set`: the owner names a project's lead, its model, the actors whose
/// plain GPU jobs are the company's, and the settings (a field left out takes its default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeadTurnsSetRequest {
    pub project: EntityId,
    /// The lead's agent.
    pub lead: EntityId,
    /// The model the owner names for the lead (at most 128 bytes).
    pub lead_model: String,
    #[serde(default)]
    pub plain_job_starters: Vec<EntityId>,
    #[serde(default)]
    pub settings: LeadTurnSettings,
}

/// A request naming one project: `.release`, `.owed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeadTurnsProjectRequest {
    pub project: EntityId,
}

/// `vault.projects.lead_turns.hold`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeadTurnsHoldRequest {
    pub project: EntityId,
    /// Why (at most 256 bytes).
    pub reason: String,
}

/// `vault.projects.lead_turns.claim`: the lead claims the owed turn. `turn`, when given, must be
/// the owed turn's number.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeadTurnsClaimRequest {
    pub project: EntityId,
    #[serde(default)]
    pub turn: Option<u64>,
}

/// The seat's own outcome of its turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LeadTurnSeatOutcome {
    Succeeded,
    Failed,
    /// It did not run (the lane's week cap, its quota window).
    Refused,
}

impl From<LeadTurnSeatOutcome> for LeadTurnOutcome {
    fn from(outcome: LeadTurnSeatOutcome) -> Self {
        match outcome {
            LeadTurnSeatOutcome::Succeeded => Self::Succeeded,
            LeadTurnSeatOutcome::Failed => Self::Failed,
            LeadTurnSeatOutcome::Refused => Self::Refused,
        }
    }
}

/// One file a finish hands the turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeadTurnFileBody {
    /// One of the registration's file names.
    pub name: String,
    /// The file's text.
    pub body: String,
}

/// `vault.projects.lead_turns.finish`: the lead closes its claimed turn.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeadTurnsFinishRequest {
    pub project: EntityId,
    pub turn: u64,
    pub outcome: LeadTurnSeatOutcome,
    /// The seat's status label (at most 64 bytes), e.g. `SUCCESS`.
    pub status: String,
    #[serde(default)]
    pub rc: Option<i32>,
    /// The model the seat ran (at most 128 bytes).
    pub model: String,
    #[serde(default)]
    pub files: Vec<LeadTurnFileBody>,
    /// When the lead wants its next turn ("a decision is due"): the timer falls due at the
    /// earlier of this and its own due time, never sooner than `min_timer_gap_secs` after this
    /// turn opened.
    #[serde(default)]
    pub next_turn_at_ms: Option<u64>,
}

/// `vault.projects.lead_turns.list`: the turn lines after `after`, oldest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeadTurnsListRequest {
    pub project: EntityId,
    #[serde(default)]
    pub after: Option<u64>,
    /// At most 100; default 50.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `vault.projects.lead_turns.file`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeadTurnsFileRequest {
    pub project: EntityId,
    pub turn: u64,
    pub name: String,
}

/// A turn as the seat takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeadTurnTicket {
    pub project: EntityId,
    pub turn: u64,
    pub opened_at_ms: u64,
    pub causes: Vec<LeadTurnCause>,
    pub cause_count: u64,
    /// The model the owner names for the lead.
    pub lead_model: String,
    /// The names the turn keeps.
    pub files: Vec<String>,
    /// Set once claimed.
    pub claimed_at_ms: Option<u64>,
    pub lease_until_ms: Option<u64>,
}

/// `vault.projects.lead_turns.owed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeadTurnsOwedView {
    /// The owed turn; `None` when none is owed.
    pub owed: Option<LeadTurnTicket>,
    /// Whether a hold refuses turns now.
    pub held: bool,
    /// The number of the claimed turn still running.
    pub running: Option<u64>,
}

/// `vault.projects.lead_turns.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeadTurnsListView {
    pub registration: LeadTurnRegistration,
    /// One line per turn, oldest first.
    pub turns: Vec<LeadTurn>,
    /// The `after` that reads the next page; `None` on the last one.
    pub next_after: Option<u64>,
}

impl LeadTurnsListView {
    /// The owed turn, as the registration holds it.
    #[must_use]
    pub fn owed(&self) -> Option<&LeadTurnOpen> {
        self.registration.owed.as_ref()
    }
}

/// `vault.projects.lead_turns.file`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeadTurnFileView {
    pub turn: u64,
    pub name: String,
    pub blake3: String,
    pub bytes: u64,
    pub body: String,
}
