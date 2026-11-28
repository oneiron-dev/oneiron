//! A company lead's turns (FIX NEON-LEAD-TURN-TRIGGER; Engine ACCEPT PLAN-NEON-LEAD-TURN-TRIGGER,
//! 28 Nov 14:15). A company is a project; its lead is an attached external seat (an agent that
//! reaches the engine over its own credential), never a model the engine runs. The engine owes
//! the lead a turn and keeps one line per turn; it never starts, resumes or messages the seat.
//!
//! - The owner names the lead, the lead's model and the settings
//!   (`vault.projects.lead_turns.set`): one registration per project.
//! - A cause owes a turn: a GPU job of the company leaves live (a line unit whose family is the
//!   project, or a plain job by a starter the registration lists), or the timer falls due
//!   (`every_secs` after the last turn opened). The job's own end write folds the cause into the
//!   project's one owed turn, inline in the registration row ([`store`]), so the hook reads one
//!   registration by key and writes at most that one row. Later causes fold into the same turn.
//! - The lead's own wake tool reads the owed turn (`vault.projects.lead_turns.owed`, LM-5),
//!   claims it (`.claim`, a lease), runs its harness, and closes it (`.finish`) with its outcome
//!   and the named files, which the turn keeps under their names.
//! - A hold (`.hold`, `.release`) refuses turns: each cause while it stands folds into one held
//!   line, written when the hold lifts or the timer falls due. A failed or lapsed turn places the
//!   hold the registration's `failure_hold` names.
//! - `.list` reads one line per turn; `.file` reads one kept file.
//!
//! Every number the policy needs is a registration setting ([`LeadTurnSettings`]), with its
//! default in one place (lead 25 Nov 00:04, policy as settings).

pub(crate) mod doors;
pub(crate) mod store;
pub(crate) mod tables;
mod wire;

pub use self::store::LEAD_TURN_TIMER_JOB_CODE;
pub(crate) use self::store::{
    PROJECT_LEAD_TURN_TIMER_JOB, erase_lead_turn_entity_in_txn, gpu_job_left_live_in_txn,
};
pub use self::wire::{
    LeadTurnFileBody, LeadTurnFileView, LeadTurnSeatOutcome, LeadTurnTicket, LeadTurnsClaimRequest,
    LeadTurnsFileRequest, LeadTurnsFinishRequest, LeadTurnsHoldRequest, LeadTurnsListRequest,
    LeadTurnsListView, LeadTurnsOwedView, LeadTurnsProjectRequest, LeadTurnsSetRequest,
};

use serde::{Deserialize, Serialize};

use crate::EntityId;

/// The owner names a project's lead, its model and its settings.
pub const LEAD_TURNS_SET_VERB: &str = "vault.projects.lead_turns.set";
/// The owner, or a Grant that reaches the project, holds its turns.
pub const LEAD_TURNS_HOLD_VERB: &str = "vault.projects.lead_turns.hold";
/// The owner, or a Grant that reaches the project, lifts the hold.
pub const LEAD_TURNS_RELEASE_VERB: &str = "vault.projects.lead_turns.release";
/// The lead reads its owed turn.
pub const LEAD_TURNS_OWED_VERB: &str = "vault.projects.lead_turns.owed";
/// The lead claims its owed turn.
pub const LEAD_TURNS_CLAIM_VERB: &str = "vault.projects.lead_turns.claim";
/// The lead closes its claimed turn.
pub const LEAD_TURNS_FINISH_VERB: &str = "vault.projects.lead_turns.finish";
/// One line per turn.
pub const LEAD_TURNS_LIST_VERB: &str = "vault.projects.lead_turns.list";
/// One file a turn kept.
pub const LEAD_TURNS_FILE_VERB: &str = "vault.projects.lead_turns.file";

/// Every verb of a project's lead turns.
pub const LEAD_TURNS_VERBS: [&str; 8] = [
    LEAD_TURNS_SET_VERB,
    LEAD_TURNS_HOLD_VERB,
    LEAD_TURNS_RELEASE_VERB,
    LEAD_TURNS_OWED_VERB,
    LEAD_TURNS_CLAIM_VERB,
    LEAD_TURNS_FINISH_VERB,
    LEAD_TURNS_LIST_VERB,
    LEAD_TURNS_FILE_VERB,
];

/// What a turn that did not succeed, or a claim whose lease ran out, does to later turns.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LeadTurnFailureHold {
    /// The engine holds the turns until the next day boundary of `day_offset_secs` (the lane's
    /// runner rule: "A turn without status SUCCESS stops turns until the next day").
    #[default]
    UntilNextDay,
    /// The engine holds the turns until the owner or a Grant releases them.
    UntilRelease,
    /// No hold: the failed line is the only record.
    None,
}

/// A registration's settings. A field a request leaves out takes its default here, the one place
/// the defaults live (policy as settings, lead 25 Nov 00:04).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct LeadTurnSettings {
    /// The timer falls due this long after the last turn opened. Default 21600 (6 h, the needs
    /// file's "otherwise about one every 6 hours").
    pub every_secs: u64,
    /// The soonest a lead's own `next_turn_at_ms` makes the timer due after its turn opened, so a
    /// seat cannot ask for a turn a minute away. Default 900 (ACCEPT condition 3).
    pub min_timer_gap_secs: u64,
    /// A claimed turn ends `lapsed` this long after its claim when no finish came. Default 3600
    /// (more than the harness's 45-minute print timeout).
    pub lease_secs: u64,
    /// The names a turn keeps. A succeeded finish carries each; a `.json` name holds one JSON
    /// object. Default DECISION.md, DECISION.json and STATE.md.
    pub files: Vec<String>,
    /// The largest file a turn keeps, in bytes. Default 262144 (256 KiB).
    pub max_file_bytes: u64,
    /// The most causes a turn lists; past it only the count grows. Default 32.
    pub max_causes: u32,
    /// Whether a company job leaving live owes a turn. Default true.
    pub on_job_end: bool,
    /// What a failed or lapsed turn does. Default `until_next_day`.
    pub failure_hold: LeadTurnFailureHold,
    /// The day boundary `until_next_day` lifts at, as seconds east of UTC. Default 32400 (JST,
    /// the lane's day).
    pub day_offset_secs: i64,
}

impl Default for LeadTurnSettings {
    fn default() -> Self {
        Self {
            every_secs: 21_600,
            min_timer_gap_secs: 900,
            lease_secs: 3_600,
            files: ["DECISION.md", "DECISION.json", "STATE.md"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            max_file_bytes: 262_144,
            max_causes: 32,
            on_job_end: true,
            failure_hold: LeadTurnFailureHold::UntilNextDay,
            day_offset_secs: 32_400,
        }
    }
}

/// Why a turn is owed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LeadTurnCause {
    /// The timer fell due at `due_at_ms`.
    Timer { due_at_ms: u64 },
    /// A job of the company left live: `end` is its end (`exited`, `cancelled`, `time_limit`,
    /// ..., `stopped_at_maximum` or `held_before_start`).
    JobEnded {
        job: EntityId,
        end: String,
        at_ms: u64,
    },
}

/// A turn not yet claimed, or the causes a hold refused, kept inline in the registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeadTurnOpen {
    pub opened_at_ms: u64,
    /// The first causes, at most the registration's `max_causes`.
    pub causes: Vec<LeadTurnCause>,
    /// Every cause folded in, listed or not.
    pub cause_count: u64,
}

impl LeadTurnOpen {
    fn opened_at(now_ms: u64) -> Self {
        Self {
            opened_at_ms: now_ms,
            causes: Vec::new(),
            cause_count: 0,
        }
    }

    /// Folds `cause` in; false, changing nothing, when the same job already ended into it.
    fn fold(&mut self, cause: LeadTurnCause, max_causes: u32) -> bool {
        if let LeadTurnCause::JobEnded { job, .. } = &cause
            && self.causes.iter().any(
                |seen| matches!(seen, LeadTurnCause::JobEnded { job: listed, .. } if listed == job),
            )
        {
            return false;
        }
        self.cause_count += 1;
        if self.causes.len() < max_causes as usize {
            self.causes.push(cause);
        }
        true
    }
}

/// Who placed a hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LeadTurnHoldBy {
    Owner,
    /// An agent under this Grant (the referee's, or any the owner gave the hold verb).
    Grant {
        grant: EntityId,
    },
    /// The engine, after a turn that failed or lapsed (`failure_hold`).
    Engine,
}

/// A hold on a project's turns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeadTurnHold {
    pub by: LeadTurnHoldBy,
    pub at_ms: u64,
    pub reason: String,
    /// When the engine lifts it by itself; `None` until a release.
    pub lifts_at_ms: Option<u64>,
    /// The turn that placed it, for an engine hold.
    pub turn: Option<u64>,
}

impl LeadTurnHold {
    /// Whether the hold still refuses turns at `now_ms`.
    #[must_use]
    pub fn stands_at(&self, now_ms: u64) -> bool {
        self.lifts_at_ms.is_none_or(|at| now_ms < at)
    }
}

/// The turn a lead claimed and has not closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeadTurnClaim {
    pub seq: u64,
    pub lease_until_ms: u64,
}

/// One project's lead turns: what the owner set, and where the turns stand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeadTurnRegistration {
    pub project: EntityId,
    /// The lead's agent; `None` after its erase.
    pub lead: Option<EntityId>,
    /// The model the owner names for the lead. The engine shows it to the seat and records what
    /// the seat reports; it cannot check what an external harness ran.
    pub lead_model: String,
    /// The actors whose plain GPU jobs (a job no line unit claims) are the company's. One actor
    /// is in at most one registration.
    pub plain_job_starters: Vec<EntityId>,
    pub settings: LeadTurnSettings,
    pub hold: Option<LeadTurnHold>,
    /// The number the next turn line takes; the owed turn takes it at its claim.
    pub next_seq: u64,
    /// The owed turn, not yet claimed.
    pub owed: Option<LeadTurnOpen>,
    /// The causes a standing hold refused since its last held line.
    pub held: Option<LeadTurnOpen>,
    pub claimed: Option<LeadTurnClaim>,
    /// When the timer falls due next.
    pub next_due_ms: u64,
    /// False once the timer stopped: the lead was erased, or no live Grant of the lead lists
    /// `.claim` and reaches the project. A new set arms it again.
    pub armed: bool,
    pub set_at_ms: u64,
    pub revision: u64,
}

/// How a turn ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LeadTurnOutcome {
    /// The seat closed it: its turn ran and succeeded.
    Succeeded,
    /// The seat closed it: its turn ran and failed.
    Failed,
    /// The seat closed it without running (the lane's week cap, its quota window).
    Refused,
    /// A hold refused it.
    Held,
    /// Its claim's lease ran out with no finish.
    Lapsed,
    /// No live Grant of the lead lists `.claim` and reaches the project: the timer stopped.
    LeadWithoutGrant,
}

/// A file a turn kept, as its line shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeadTurnFileRef {
    pub name: String,
    /// The vault's content hash (plain BLAKE3, 64 hex; `b3sum` checks it).
    pub blake3: String,
    pub bytes: u64,
}

/// One turn line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LeadTurn {
    pub seq: u64,
    pub opened_at_ms: u64,
    pub causes: Vec<LeadTurnCause>,
    pub cause_count: u64,
    pub claimed_at_ms: Option<u64>,
    pub lease_until_ms: Option<u64>,
    pub ended_at_ms: Option<u64>,
    pub outcome: Option<LeadTurnOutcome>,
    /// The seat's own status label (at most 64 bytes).
    pub status: Option<String>,
    /// The seat's exit code.
    pub rc: Option<i32>,
    /// The model the owner named when the turn was claimed or written.
    pub model_named: String,
    /// The model the seat reports it ran.
    pub model_reported: Option<String>,
    pub files: Vec<LeadTurnFileRef>,
    /// Whether this turn placed the failure hold.
    pub placed_hold: bool,
}

/// One kept file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LeadTurnFile {
    pub(crate) name: String,
    pub(crate) blake3: String,
    pub(crate) body: String,
}

/// The project whose registration lists a plain-job starter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LeadTurnStarter {
    pub(crate) project: EntityId,
}
