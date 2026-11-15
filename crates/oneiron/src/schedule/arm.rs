//! Arming and disarming a job, the rows that record it, and who may do either.

use serde::{Deserialize, Serialize};

use super::{ArmBy, EngineZones, JobSpec, Trigger, job_named};
use crate::Vault;
use crate::consent::AuthenticatedOwner;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
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
            let next_due_at = trigger
                .first_due(now, &EngineZones)
                .ok_or_else(|| refused("the trigger has no occurrence ahead"))?;
            let row = ScheduleRow {
                trigger,
                armed_by,
                next_due_at,
                finished_at: prior.as_ref().map_or(0, |prior| prior.finished_at),
                started_at: None,
                failures: 0,
                requested_at: None,
                cursor: None,
            };
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
