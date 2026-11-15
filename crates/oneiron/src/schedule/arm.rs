//! Arming and disarming a job, the rows that record it, and who may do either.

use serde::{Deserialize, Serialize};

use super::{ArmBy, EngineZones, JobSpec, Trigger, When, job_named, jobs, retry_after};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::setting::SettingChange;
use crate::side_table::{self, Named, SideTable};
use crate::store::Store;

pub(super) const ROWS: SideTable<Vec<u8>, ScheduleRow, Named> =
    SideTable::new(&side_table::SCHEDULE);
pub(super) const DUE: SideTable<Vec<u8>, (), Named> = SideTable::new(&side_table::SCHEDULE_DUE);

/// The verb an agent's Grant lists to arm a job.
pub(crate) const ARM_VERB: &str = "vault.schedules.arm";

/// One armed job, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScheduleRow {
    /// The trigger in force since it was armed.
    pub(super) trigger: Trigger,
    /// The agent that armed it, and the Grant it armed under; `None` for the owner and the
    /// engine.
    pub(super) armed_by: Option<ArmedBy>,
    pub(super) next_due_at: u64,
    /// When its last run ended; 0 before the first.
    pub(super) finished_at: u64,
    /// When a run in flight started.
    pub(super) started_at: Option<u64>,
    /// Runs in a row that failed, panicked or were interrupted.
    pub(super) failures: u32,
    /// When someone asked for a run that has not started yet: due from then.
    pub(super) requested_at: Option<u64>,
    /// Where an unfinished run goes on from.
    pub(super) cursor: Option<Vec<u8>>,
    /// The run in flight, or the one that goes on from a run that did not run to its end,
    /// answers a "run now". It stays until a run of the work ends done.
    #[serde(default)]
    pub(super) answering: bool,
}

/// The agent behind an arming.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ArmedBy {
    pub(super) actor: EntityId,
    pub(super) grant: Option<EntityId>,
}

impl ScheduleRow {
    /// When it is due: its next due time, or a requested run's time when that is earlier.
    pub(super) fn due_at(&self) -> u64 {
        self.requested_at.map_or(self.next_due_at, |requested| {
            requested.min(self.next_due_at)
        })
    }

    /// A new arming with `trigger` at `now`: due at its first occurrence, with no failure, cursor
    /// or request; its last finish is kept.
    fn armed(
        trigger: Trigger,
        armed_by: Option<ArmedBy>,
        prior: Option<&Self>,
        now: u64,
    ) -> Result<Self> {
        let next_due_at = trigger
            .first_due(now, &EngineZones)
            .ok_or_else(|| refused("the trigger has no occurrence ahead"))?;
        Ok(Self {
            trigger,
            armed_by,
            next_due_at,
            finished_at: prior.map_or(0, |prior| prior.finished_at),
            started_at: None,
            failures: 0,
            requested_at: None,
            cursor: None,
            answering: false,
        })
    }
}

/// `SCHEDULE`'s key: the job's code, 0x00, the subject's bytes.
pub(super) fn row_key(job: &str, subject: Option<EntityId>) -> Vec<u8> {
    let mut key = job.as_bytes().to_vec();
    key.push(0);
    if let Some(subject) = subject {
        key.extend_from_slice(subject.as_bytes());
    }
    key
}

/// The job code and subject a `SCHEDULE` key names.
pub(super) fn parse_row_key(key: &[u8]) -> Option<(String, Option<EntityId>)> {
    let split = key.iter().position(|byte| *byte == 0)?;
    let job = std::str::from_utf8(&key[..split]).ok()?.to_owned();
    let rest = &key[split + 1..];
    let subject = if rest.is_empty() {
        None
    } else {
        Some(EntityId::from_bytes(<[u8; 16]>::try_from(rest).ok()?).ok()?)
    };
    Some((job, subject))
}

/// `SCHEDULE_DUE`'s key for the row under `key` due at `due`.
pub(super) fn due_key(due: u64, key: &[u8]) -> Vec<u8> {
    let mut out = due.to_be_bytes().to_vec();
    out.extend_from_slice(key);
    out
}

/// Writes `row` under `key` in place of `prior`, moving its due-index entry, in one write.
pub(super) fn store_row_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8],
    prior: Option<&ScheduleRow>,
    row: Option<&ScheduleRow>,
) -> Result<()> {
    if let Some(prior) = prior {
        DUE.delete(store, txn, &due_key(prior.due_at(), key))?;
    }
    match row {
        Some(row) => {
            ROWS.put(store, txn, &key.to_vec(), row)?;
            DUE.put(store, txn, &due_key(row.due_at(), key), &())?;
        }
        None => {
            ROWS.delete(store, txn, &key.to_vec())?;
        }
    }
    Ok(())
}

/// Who asks: the owner, by a proof the door revalidates, or an agent whose binding the caller
/// verified.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ScheduleCaller<'a> {
    Owner(&'a AuthenticatedOwner),
    Agent(EntityId),
}

/// One armed job, as the verbs show it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ScheduleView {
    pub job: String,
    /// What it is about, 32 hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub trigger: Trigger,
    /// When it is due: its next occurrence, or an asked-for run when that is earlier.
    pub due_at: u64,
    /// When its last run ended; 0 before the first.
    pub finished_at: u64,
    /// Its failures in a row.
    pub failures: u32,
    /// Whether a run is in flight.
    pub running: bool,
    /// The agent that armed it, 32 hex; none for the owner and the engine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub armed_by: Option<String>,
}

impl ScheduleView {
    fn of(job: &str, subject: Option<EntityId>, row: &ScheduleRow) -> Self {
        Self {
            job: job.to_owned(),
            subject: subject.map(|subject| subject.to_hex()),
            trigger: row.trigger.clone(),
            due_at: row.due_at(),
            finished_at: row.finished_at,
            failures: row.failures,
            running: row.started_at.is_some(),
            armed_by: row.armed_by.map(|armed| armed.actor.to_hex()),
        }
    }
}

/// The job kind named `job`, or a refusal.
fn job_spec(job: &str) -> Result<&'static JobSpec> {
    job_named(job).ok_or_else(|| Error::InvalidConfig(format!("no job kind is named `{job}`")))
}

fn refused(what: &str) -> Error {
    Error::InvalidConfig(format!("schedules: {what}"))
}

impl Vault {
    /// Arms `job` about `subject` with `trigger`, or re-arms it, in one write: the row and its
    /// due-index entry. The engine's own doors call it with no caller.
    ///
    /// - The owner arms any job a caller may arm; an agent arms an actor job under its own live
    ///   Grant that lists `vault.schedules.arm`, and a class job while it holds the class. An
    ///   engine job is the engine's alone.
    /// - An agent never re-arms a job someone else armed.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an unknown job, a trigger that can never fire, or a caller without
    /// the power; an owner proof that no longer holds; storage errors.
    pub(crate) fn arm_schedule(
        &self,
        caller: Option<ScheduleCaller<'_>>,
        job: &str,
        subject: Option<EntityId>,
        trigger: Trigger,
    ) -> Result<ScheduleView> {
        let spec = job_spec(job)?;
        if let Some(why) = trigger.refusal(&EngineZones) {
            return Err(refused(why));
        }
        self.with_write_txn_grouped(|txn| {
            let key = row_key(spec.code, subject);
            let prior = ROWS.get(&self.store, txn, &key)?;
            let armed_by = match caller {
                None => None,
                Some(caller) => self.arm_power_in_txn(txn, spec, caller, prior.as_ref())?,
            };
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let row = ScheduleRow::armed(trigger, armed_by, prior.as_ref(), now)?;
            store_row_in_txn(&self.store, txn, &key, prior.as_ref(), Some(&row))?;
            Ok(ScheduleView::of(spec.code, subject, &row))
        })
    }

    /// The arming `caller` makes of `spec`, when it may: `None` for the owner, the agent and
    /// its Grant for an agent.
    fn arm_power_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        spec: &JobSpec,
        caller: ScheduleCaller<'_>,
        prior: Option<&ScheduleRow>,
    ) -> Result<Option<ArmedBy>> {
        if spec.arm_by == ArmBy::Engine {
            return Err(refused("this job is the engine's to arm"));
        }
        let agent = match caller {
            ScheduleCaller::Owner(owner) => {
                owner.revalidate_in_txn(self, txn)?;
                return Ok(None);
            }
            ScheduleCaller::Agent(agent) => agent,
        };
        if prior.is_some_and(|prior| prior.armed_by.is_none_or(|armed| armed.actor != agent)) {
            return Err(refused("an agent re-arms only a job it armed itself"));
        }
        let grant = match spec.arm_by {
            ArmBy::Class(class) => self.engine_controls_grant_in(txn, agent, class)?,
            ArmBy::Actor | ArmBy::Engine => crate::authority::principal_standing_in_txn(
                self,
                txn,
                agent,
                EdgeActorClass::Agent,
                ARM_VERB,
            )?
            .and_then(|standing| standing.grant),
        };
        let grant = grant.ok_or_else(|| {
            refused("an agent arms a job under its own live Grant for it, or the job's class")
        })?;
        Ok(Some(ArmedBy {
            actor: agent,
            grant: Some(grant),
        }))
    }

    /// Whether `caller` may disarm or run `spec`'s row `row` now: the owner; the agent that
    /// armed it; a live holder of a class job's class. Never an engine job.
    fn may_touch_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        spec: &JobSpec,
        caller: ScheduleCaller<'_>,
        row: &ScheduleRow,
    ) -> Result<bool> {
        if spec.arm_by == ArmBy::Engine {
            return Ok(false);
        }
        match caller {
            ScheduleCaller::Owner(owner) => owner.revalidate_in_txn(self, txn).map(|_| true),
            ScheduleCaller::Agent(agent) => {
                Ok(row.armed_by.is_some_and(|armed| armed.actor == agent)
                    || match spec.arm_by {
                        ArmBy::Class(class) => {
                            self.engine_controls_grant_in(txn, agent, class)?.is_some()
                        }
                        ArmBy::Actor | ArmBy::Engine => false,
                    })
            }
        }
    }

    /// Disarms `job` about `subject`: its row and due-index entry go. Disarming what is not
    /// armed answers `false`.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an unknown job or a caller without the power; storage errors.
    pub(crate) fn disarm_schedule(
        &self,
        caller: Option<ScheduleCaller<'_>>,
        job: &str,
        subject: Option<EntityId>,
    ) -> Result<bool> {
        let spec = job_spec(job)?;
        self.with_write_txn_grouped(|txn| {
            let key = row_key(spec.code, subject);
            let Some(prior) = ROWS.get(&self.store, txn, &key)? else {
                return Ok(false);
            };
            if let Some(caller) = caller
                && !self.may_touch_in_txn(txn, spec, caller, &prior)?
            {
                return Err(refused(
                    "disarming needs the owner, the agent that armed it, or its class",
                ));
            }
            store_row_in_txn(&self.store, txn, &key, Some(&prior), None)?;
            Ok(true)
        })
    }

    /// "Run now": `job` about `subject` is due from now, whatever its trigger says, until a run
    /// starts.
    ///
    /// # Errors
    ///
    /// `InvalidConfig` for an unknown or unarmed job, or a caller without the power; storage
    /// errors.
    pub(crate) fn request_schedule_run(
        &self,
        caller: ScheduleCaller<'_>,
        job: &str,
        subject: Option<EntityId>,
    ) -> Result<ScheduleView> {
        let spec = job_spec(job)?;
        self.with_write_txn_grouped(|txn| {
            let key = row_key(spec.code, subject);
            let prior = ROWS
                .get(&self.store, txn, &key)?
                .ok_or_else(|| refused("the job is not armed"))?;
            if !self.may_touch_in_txn(txn, spec, caller, &prior)? {
                return Err(refused(
                    "a run now needs the owner, the agent that armed it, or its class",
                ));
            }
            let now = crate::ports::recorded_at_in_txn(&self.store, txn)?;
            let row = ScheduleRow {
                requested_at: Some(prior.requested_at.map_or(now, |earlier| earlier.min(now))),
                ..prior.clone()
            };
            store_row_in_txn(&self.store, txn, &key, Some(&prior), Some(&row))?;
            Ok(ScheduleView::of(spec.code, subject, &row))
        })
    }

    /// The armed jobs `caller` may see, narrowed to `job` and `subject` when given: every one for
    /// the owner; for an agent, those it armed and those of a class it holds.
    ///
    /// # Errors
    ///
    /// An owner proof that no longer holds; storage errors.
    pub(crate) fn schedules_for(
        &self,
        caller: ScheduleCaller<'_>,
        job: Option<&str>,
        subject: Option<EntityId>,
    ) -> Result<Vec<ScheduleView>> {
        let txn = self.store.env.read_txn()?;
        if let ScheduleCaller::Owner(owner) = caller {
            owner.revalidate_in_txn(self, &txn)?;
        }
        let prefix = job.map(|job| {
            let mut prefix = job.as_bytes().to_vec();
            prefix.push(0);
            prefix
        });
        let mut views = Vec::new();
        for row in ROWS.iter_from(&self.store, &txn, prefix.as_deref().unwrap_or_default())? {
            let (key, row) = row?;
            let Some((code, row_subject)) = parse_row_key(&key) else {
                continue;
            };
            if subject.is_some_and(|subject| row_subject != Some(subject)) {
                continue;
            }
            let shown = match (caller, job_named(&code)) {
                (ScheduleCaller::Owner(_), _) => true,
                (ScheduleCaller::Agent(_), None) => false,
                (ScheduleCaller::Agent(agent), Some(spec)) => {
                    row.armed_by.is_some_and(|armed| armed.actor == agent)
                        || match spec.arm_by {
                            ArmBy::Class(class) => {
                                self.engine_controls_grant_in(&txn, agent, class)?.is_some()
                            }
                            ArmBy::Actor | ArmBy::Engine => false,
                        }
                }
            };
            if shown {
                views.push(ScheduleView::of(&code, row_subject, &row));
            }
        }
        Ok(views)
    }
}

/// The engine arms `spec` about `subject` with `trigger` inside the caller's write: the door a
/// deadline's own write calls, and the arming of a cadence key's job. A row that already holds
/// `trigger` is left as it is, so arming again never moves a due time; a new trigger is due at
/// its first occurrence, with no failure, cursor or request.
///
/// # Errors
///
/// `InvalidConfig` for a trigger that can never fire, a zone the engine does not know, or one
/// with no occurrence ahead; storage errors.
pub(crate) fn arm_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    spec: &'static JobSpec,
    subject: Option<EntityId>,
    trigger: Trigger,
) -> Result<()> {
    if let Some(why) = trigger.refusal(&EngineZones) {
        return Err(refused(why));
    }
    let key = row_key(spec.code, subject);
    let prior = ROWS.get(&vault.store, txn, &key)?;
    if prior.as_ref().is_some_and(|prior| prior.trigger == trigger) {
        return Ok(());
    }
    let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
    let row = ScheduleRow::armed(trigger, None, prior.as_ref(), now)?;
    store_row_in_txn(&vault.store, txn, &key, prior.as_ref(), Some(&row))
}

/// The trigger in force for `spec`'s cadence key, at the vault, or `None` for a job that has no
/// cadence key.
fn cadence_in_txn(vault: &Vault, txn: &heed::RoTxn<'_>, spec: &JobSpec) -> Result<Option<Trigger>> {
    match spec.when {
        When::Setting(key) => Ok(Some(key.read_in_txn(vault, txn, &[], None)?.value)),
        When::PerArming => Ok(None),
    }
}

/// Arms every job of a kind `which` takes whose cadence is a Setting key from the key's value in
/// force, in one write. The host's pass calls it on its handle's first pass for every such job; a
/// job already armed with that trigger keeps its due time.
///
/// # Errors
///
/// As [`arm_in_txn`]; storage errors.
pub(crate) fn arm_setting_jobs(vault: &Vault, which: fn(&JobSpec) -> bool) -> Result<()> {
    vault.with_write_txn_grouped(|txn| {
        for spec in jobs().filter(|spec| which(spec)) {
            if let Some(trigger) = cadence_in_txn(vault, txn, spec)? {
                arm_in_txn(vault, txn, spec, None, trigger)?;
            }
        }
        Ok(())
    })
}

/// The `on_change` of every cadence key: in the write that changes the key, its job is armed
/// again from the value now in force. A trigger that cannot be armed refuses the change.
///
/// # Errors
///
/// As [`arm_in_txn`]; storage errors.
pub(crate) fn rearm_on_change(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    change: &SettingChange,
) -> Result<()> {
    for spec in jobs() {
        if matches!(spec.when, When::Setting(key) if key.spec.name == change.key)
            && let Some(trigger) = cadence_in_txn(vault, txn, spec)?
        {
            arm_in_txn(vault, txn, spec, None, trigger)?;
        }
    }
    Ok(())
}

/// "Run now" from the engine: every armed job of a kind `which` takes is due from now until a
/// run starts, and that run answers the request. The host's pass asks for its handle's
/// `at_open` jobs, and the owner's "run housekeeping now" for every cadence job; the caller has
/// proved its own power. Answers how many it asked for.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn request_runs(vault: &Vault, which: fn(&JobSpec) -> bool) -> Result<usize> {
    vault.with_write_txn_grouped(|txn| {
        let now = crate::ports::recorded_at_in_txn(&vault.store, txn)?;
        let mut asked = Vec::new();
        for row in ROWS.iter_from(&vault.store, txn, &[])? {
            let (key, row) = row?;
            let taken = parse_row_key(&key)
                .and_then(|(job, _)| job_named(&job))
                .is_some_and(which);
            if taken {
                asked.push((key, row));
            }
        }
        for (key, prior) in &asked {
            let row = ScheduleRow {
                requested_at: Some(prior.requested_at.map_or(now, |earlier| earlier.min(now))),
                ..prior.clone()
            };
            store_row_in_txn(&vault.store, txn, key, Some(prior), Some(&row))?;
        }
        Ok(asked.len())
    })
}

/// Pulls the due time of `job` about `subject` forward to `at` inside the caller's write: work
/// a door made due before the job's next occurrence. A job that is backing off, or has a run in
/// flight, keeps its due time; one not armed, or already due by `at`, is left as it is.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn due_by_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    job: &str,
    subject: Option<EntityId>,
    at: u64,
) -> Result<()> {
    let key = row_key(job, subject);
    let Some(prior) = ROWS.get(store, txn, &key)? else {
        return Ok(());
    };
    if prior.failures > 0 || prior.started_at.is_some() || prior.due_at() <= at {
        return Ok(());
    }
    let row = ScheduleRow {
        next_due_at: at,
        ..prior.clone()
    };
    store_row_in_txn(store, txn, &key, Some(&prior), Some(&row))
}

/// When `job` about `subject` is next due, or `None` when it is not armed: a requested run's
/// time or its next due time, and for a run that never finished, the retry after it.
///
/// # Errors
///
/// Storage errors.
pub(crate) fn due_at_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    job: &str,
    subject: Option<EntityId>,
) -> Result<Option<u64>> {
    let Some(row) = ROWS.get(store, txn, &row_key(job, subject))? else {
        return Ok(None);
    };
    Ok(Some(match (row.started_at, job_named(job)) {
        (Some(started), Some(spec)) => started.saturating_add(retry_after(
            row.failures.saturating_add(1),
            spec.retry_first_secs,
            spec.retry_cap(&row.trigger),
        )),
        _ => row.due_at(),
    }))
}

/// The rows an erase of `id` takes: every job about it, and every job it armed.
fn erase_rows_naming_in_txn(store: &Store, txn: &mut heed::RwTxn<'_>, id: &EntityId) -> Result<()> {
    let mut gone = Vec::new();
    for row in ROWS.iter_from(store, txn, &[])? {
        let (key, row) = row?;
        let about = parse_row_key(&key).is_some_and(|(_, subject)| subject == Some(*id));
        if about || row.armed_by.is_some_and(|armed| armed.actor == *id) {
            gone.push((key, row));
        }
    }
    for (key, row) in gone {
        store_row_in_txn(store, txn, &key, Some(&row), None)?;
    }
    Ok(())
}

/// `SCHEDULE`'s actor scrub: an erased actor's armings, and the jobs about it, are disarmed.
pub(crate) fn erase_schedule_actor_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if crate::deletion::names_no_actor(vault, txn, actor)? {
        return Ok(());
    }
    erase_rows_naming_in_txn(&vault.store, txn, actor)
}

/// The per-entity eraser: an erased entity's jobs are disarmed.
pub(crate) fn erase_schedule_subject_in_txn(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    erase_rows_naming_in_txn(store, txn, id)
}
