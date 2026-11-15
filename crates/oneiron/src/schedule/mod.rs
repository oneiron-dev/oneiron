//! The Schedule primitive (DESIGN 15-setting-primitive, stage 0.2): one record that a job is due
//! at a time, in place of a due table, a runner and a wake source per job.
//!
//! The engine owns no timer (ARCH-0026): a host calls [`Vault::housekeeping`] on its own tick,
//! and the pass runs every armed job that is due ([`Vault::run_due`]); a stopped vault asks
//! [`Vault::housekeeping_wake_at`] when to start again, which reads the first due job that wakes
//! a host.
//!
//! - A job kind is a [`JobSpec`], declared in code beside its handler and listed in the job
//!   registry. It holds no choice: who may arm it, what happens when it is late, its backoff.
//! - An armed job is one `SCHEDULE` row, keyed by the job's code and its subject, and one entry of
//!   the derived `SCHEDULE_DUE` index, written in the same transaction.
//! - A run writes its start marker, runs, and writes its result, each in its own transaction. A
//!   start marker found by a later pass is a run that was interrupted: a failure.
//! - One catch-up rule ([`Trigger::next_due`]): a late schedule runs once, then goes on from now.
//! - One backoff ([`retry_after`]).
//! - Verbs: `vault.schedules.list`, `.arm`, `.disarm`, `.run`.
//! - A job whose cadence is a Setting key ([`When::Setting`]) is armed by the engine from the
//!   key's value in force, and re-armed in the write that changes the key
//!   ([`rearm_on_change`]).
//!
//! Stage 0.2 lands the primitive unused: no engine job is in the registry yet, and the sweeps
//! keep their own schedule beside it. Stage 5a-1 adds what the sweeps need to move onto it:
//! engine arming inside a write, the cadence key, a run that left items, an engine "run now"
//! and the run it answers, one job alone, what a pass lends its runs and what they report back,
//! and a due time pulled forward inside a write.

mod arm;
mod jobs;
mod run;
pub(crate) mod tables;
mod zones;

pub use oneiron_schedule_contract::{
    CivilDate, RETRY_CAP_SECS, RETRY_FIRST_SECS, Ran, Trigger, Weekday, ZoneRules, retry_after,
};

pub use self::arm::ScheduleView;
#[cfg(oneiron_test_support)]
pub(crate) use self::arm::plant_start_marker_in_txn;
pub(crate) use self::arm::{
    ScheduleCaller, arm_in_txn, arm_setting_jobs, due_at_in_txn, due_by_in_txn,
    erase_schedule_actor_in_txn, erase_schedule_subject_in_txn, rearm_on_change, request_runs,
};
pub(crate) use self::jobs::{job_named, jobs};
pub use self::run::{JobOutcome, JobRun, ScheduleRunReport};
pub use self::zones::EngineZones;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::federation::EngineControlClass;
use crate::llm::model_pack::AccessSnapshot;
use crate::setting::Setting;
use crate::store::housekeeping_report::SweepWork;
use crate::store::housekeeping_schedule::Deadline;

/// Who may arm a job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmBy {
    /// The engine alone, from its own doors.
    Engine,
    /// The owner, and a live holder of this `engine.controls` class.
    Class(EngineControlClass),
    /// The owner, and an agent under its own live Grant that lists `vault.schedules.arm`; each
    /// occurrence is judged again when it fires.
    Actor,
}

/// What happens to an occurrence that comes late.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Late {
    /// It runs, late, once.
    Run,
    /// Past `after_secs` late it is dropped and never runs.
    Lapse { after_secs: u64 },
}

/// Where a job's trigger comes from.
#[derive(Clone, Copy)]
pub enum When {
    /// The value in force of this cadence key, at the vault: the engine arms the job from it
    /// ([`arm_setting_jobs`]) and re-arms it in the write that changes the key, whose
    /// `on_change` is [`rearm_on_change`]. Only an engine job has one.
    Setting(&'static Setting<Trigger>),
    /// Each arming names its own trigger: a deadline, an actor's timer.
    PerArming,
}

impl std::fmt::Debug for When {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setting(key) => formatter
                .debug_tuple("Setting")
                .field(&key.spec.name)
                .finish(),
            Self::PerArming => formatter.write_str("PerArming"),
        }
    }
}

/// What a pass lends its runs.
#[derive(Debug, Clone, Copy)]
pub struct JobPass<'a> {
    /// When the pass stops starting work; a run keeps within it.
    pub deadline: &'a Deadline,
    /// What the host's model offers hold; empty when the host lends none.
    pub access: &'a AccessSnapshot,
}

/// What one run answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobResult {
    pub ran: Ran,
    /// For a repeating job that ran to its end: due again no later than this, whatever its
    /// trigger says (work it saw coming before its next occurrence), but never sooner than its
    /// first retry after the run's end. Ignored otherwise.
    pub due_by: Option<u64>,
    /// A housekeeping sweep's account of its work, for the housekeeping report.
    pub sweep_work: Option<SweepWork>,
}

impl JobResult {
    /// A run that answers `ran` and nothing else.
    #[must_use]
    pub const fn of(ran: Ran) -> Self {
        Self {
            ran,
            due_by: None,
            sweep_work: None,
        }
    }
}

/// One kind of job. Declared once, in code, beside its handler.
pub struct JobSpec {
    /// Dotted lowercase ASCII, unique in the registry.
    pub code: &'static str,
    /// Where its trigger comes from.
    pub when: When,
    pub arm_by: ArmBy,
    pub late: Late,
    /// The first retry after a failure.
    pub retry_first_secs: u64,
    /// The longest wait between retries; the smaller of the cadence and an hour when `None`.
    pub retry_cap_secs: Option<u64>,
    /// Whether a stopped vault is started for it.
    pub wakes_host: bool,
    /// Whether it also runs at the first pass of every handle, whatever its schedule says: work
    /// a stopped process left durable must not wait a whole cadence after a restart. The host's
    /// pass asks for it ([`request_runs`]).
    pub at_open: bool,
    /// One run. It keeps within the pass's deadline and answers how far it got.
    pub run: fn(&crate::Vault, &Armed, &JobPass<'_>) -> Result<JobResult>,
}

impl JobSpec {
    /// The backoff cap for a job armed with `trigger`.
    #[must_use]
    pub fn retry_cap(&self, trigger: &Trigger) -> u64 {
        self.retry_cap_secs.unwrap_or_else(|| {
            trigger
                .cadence_secs()
                .map_or(RETRY_CAP_SECS, |cadence| cadence.min(RETRY_CAP_SECS))
        })
    }
}

impl std::fmt::Debug for JobSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("JobSpec")
            .field("code", &self.code)
            .finish_non_exhaustive()
    }
}

/// One armed job, as its run sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Armed {
    pub job: &'static str,
    /// What the job is about: nothing for an engine sweep.
    pub subject: Option<EntityId>,
    pub trigger: Trigger,
    /// The occurrence this run serves.
    pub due_at: u64,
    /// Where an unfinished run goes on from.
    pub cursor: Option<Vec<u8>>,
    /// The actor that armed it; `None` for the owner and the engine.
    pub armed_by: Option<EntityId>,
    /// Whether this run answers a "run now": one was asked for before it started, or before an
    /// earlier run of the same work that did not run to its end.
    pub requested: bool,
}
