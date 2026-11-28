//! The lead turns' rows and the writers that move them outside a door: the GPU job's end hook,
//! the timer pass and the erase scrub. Every writer here runs in its caller's write.

use super::{
    LEAD_TURNS_CLAIM_VERB, LeadTurn, LeadTurnCause, LeadTurnClaim, LeadTurnFailureHold,
    LeadTurnFile, LeadTurnHold, LeadTurnHoldBy, LeadTurnOpen, LeadTurnOutcome,
    LeadTurnRegistration, LeadTurnStarter,
};
use crate::error::{Error, Result};
use crate::gpu_job::{GpuJob, GpuJobState};
use crate::memory::MEMORY_CODE_FORBIDDEN;
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::schedule::{ArmBy, Armed, JobPass, JobResult, JobSpec, Late, Ran, Trigger, When};
use crate::side_table::{self, Named, SideTable};
use crate::{EdgeActorClass, EntityId, Vault};

/// The registrations, by project.
pub(crate) const REGISTRATIONS: SideTable<EntityId, LeadTurnRegistration, Named> =
    SideTable::new(&side_table::PROJECT_LEAD_TURN_REGISTRATION);
/// The turn lines, by project and turn number.
pub(crate) const TURNS: SideTable<(EntityId, u64), LeadTurn, Named> =
    SideTable::new(&side_table::PROJECT_LEAD_TURN);
/// The kept files, by project, turn number and name.
pub(crate) const FILES: SideTable<(EntityId, u64, String), LeadTurnFile, Named> =
    SideTable::new(&side_table::PROJECT_LEAD_TURN_FILE);
/// The plain-job starters, by actor.
pub(crate) const STARTERS: SideTable<EntityId, LeadTurnStarter, Named> =
    SideTable::new(&side_table::PROJECT_LEAD_TURN_STARTER);

/// The timer job's code.
pub const LEAD_TURN_TIMER_JOB_CODE: &str = "project_lead_turn.timer";
/// The first retry of a failed timer pass.
const TIMER_RETRY_FIRST_SECS: u64 = 60;
const DAY_MS: i64 = 86_400_000;

/// One project's lead-turn timer: one row about the project, armed at the earliest of the timer's
/// next due time, the claimed turn's lease end and the hold's lift time, re-armed in each write
/// that moves one of them. A pass ([`timer_pass_in_txn`]) lifts a hold whose time came, ends a
/// lapsed claim, stops the timer when the lead holds no Grant for its turns, and folds the
/// timer's cause when it is due. It writes rows only: it runs no code and asks no machine.
pub(crate) static PROJECT_LEAD_TURN_TIMER_JOB: JobSpec = JobSpec {
    code: LEAD_TURN_TIMER_JOB_CODE,
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: TIMER_RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: true,
    at_open: false,
    once_per_pass: true,
    runs_here: |_vault, _txn| Ok(true),
    drive: crate::schedule::Drive::Runner,
    run: run_timer,
};

fn run_timer(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    let Some(project) = armed.subject else {
        return Ok(JobResult::of(Ran::Done));
    };
    let next = vault.with_write_txn_grouped(|txn| {
        let now_ms = vault.now_recorded_ms();
        timer_pass_in_txn(vault, txn, project, now_ms)
    })?;
    Ok(JobResult {
        due_by: next.map(|due_ms| due_ms.div_ceil(1000)),
        ..JobResult::of(Ran::Done)
    })
}

/// One timer pass of `project`'s turns at `now_ms`, in the caller's write: a hold whose lift time
/// came lifts and its held causes become one held line; a claim whose lease ran out ends
/// `lapsed`; a lead with no live Grant listing `.claim` that reaches the project ends its open
/// turns `lead_without_grant` and stops the timer; a due timer folds its cause (into the held
/// causes, written as one held line, while a hold stands). Answers when the timer is due next,
/// in milliseconds; `None` once it stopped.
///
/// # Errors
///
/// Store errors.
pub(crate) fn timer_pass_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    project: EntityId,
    now_ms: u64,
) -> Result<Option<u64>> {
    let Some(mut registration) = REGISTRATIONS.get_lenient(&vault.store, txn, &project)? else {
        disarm_timer_in_txn(vault, txn, project)?;
        return Ok(None);
    };
    if !registration.armed {
        disarm_timer_in_txn(vault, txn, project)?;
        return Ok(None);
    }
    if registration
        .hold
        .as_ref()
        .is_some_and(|hold| !hold.stands_at(now_ms))
    {
        registration.hold = None;
        flush_held_in_txn(vault, txn, &mut registration, now_ms)?;
    }
    if let Some(claimed) = registration.claimed
        && claimed.lease_until_ms <= now_ms
    {
        end_claimed_in_txn(
            vault,
            txn,
            &mut registration,
            LeadTurnOutcome::Lapsed,
            now_ms,
        )?;
        place_failure_hold_in_txn(vault, txn, &mut registration, claimed.seq, now_ms)?;
    }
    if !lead_stands_in_txn(vault, txn, &registration)? {
        stop_without_grant_in_txn(vault, txn, &mut registration, now_ms)?;
        return Ok(None);
    }
    if registration.next_due_ms <= now_ms {
        let cause = LeadTurnCause::Timer {
            due_at_ms: registration.next_due_ms,
        };
        let held = registration
            .hold
            .as_ref()
            .is_some_and(|hold| hold.stands_at(now_ms));
        fold_cause(&mut registration, cause, now_ms);
        if held {
            flush_held_in_txn(vault, txn, &mut registration, now_ms)?;
        }
        registration.next_due_ms = now_ms.saturating_add(secs_ms(registration.settings.every_secs));
    }
    put_registration_in_txn(vault, txn, &mut registration)?;
    Ok(Some(timer_due_ms(&registration)))
}

/// Folds the end of `job` into its company's owed turn, in the job's own end write, when a write
/// moves it out of live (the shared row writer, `gpu_job` `put_gpu_job_in_txn`). The company is
/// the family of the line unit that claims the job, or, for a plain job, the project whose
/// registration lists its starter. One registration read by key and at most one put of it
/// (ACCEPT condition 2): a registration that does not decode is passed over, and only the store's
/// own error fails the write.
///
/// # Errors
///
/// Store errors.
pub(crate) fn gpu_job_left_live_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    job: &GpuJob,
    now_ms: u64,
) -> Result<()> {
    let Some((project, starter)) = job_company_in_txn(vault, txn, job)? else {
        return Ok(());
    };
    let Some(mut registration) = REGISTRATIONS.get_lenient(&vault.store, txn, &project)? else {
        return Ok(());
    };
    if !registration.armed || !registration.settings.on_job_end {
        return Ok(());
    }
    if let Some(starter) = starter
        && !registration.plain_job_starters.contains(&starter)
    {
        return Ok(());
    }
    let cause = LeadTurnCause::JobEnded {
        job: job.id,
        end: job_end(&job.state),
        at_ms: now_ms,
    };
    if !fold_cause(&mut registration, cause, now_ms) {
        return Ok(());
    }
    registration.revision += 1;
    REGISTRATIONS.put(&vault.store, txn, &project, &registration)
}

/// The company of `job` and, for a plain job, its starter.
fn job_company_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    job: &GpuJob,
) -> Result<Option<(EntityId, Option<EntityId>)>> {
    if let Some(key) = &job.claim {
        return Ok(
            crate::gpu_line::claim_in_txn(vault, txn, key)?.map(|claim| (claim.family, None))
        );
    }
    let Some(starter) = job.started_by else {
        return Ok(None);
    };
    Ok(STARTERS
        .get_lenient(&vault.store, txn, &starter)?
        .map(|row| (row.project, Some(starter))))
}

/// The end a job's state names, as its cause shows it.
fn job_end(state: &GpuJobState) -> String {
    match state {
        GpuJobState::Ended { reason } => serde_json::to_value(reason)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_else(|| "ended".to_owned()),
        GpuJobState::Stopped => "stopped_at_maximum".to_owned(),
        GpuJobState::Held { .. } => "held_before_start".to_owned(),
        _ => "ended".to_owned(),
    }
}

/// Folds `cause` into the held causes while a hold stands at `now_ms`, else into the owed turn,
/// opening it (and moving the timer to `every_secs` from now) when none is owed. False, changing
/// nothing, when the same job already ended into it.
pub(super) fn fold_cause(
    registration: &mut LeadTurnRegistration,
    cause: LeadTurnCause,
    now_ms: u64,
) -> bool {
    let max_causes = registration.settings.max_causes;
    if registration
        .hold
        .as_ref()
        .is_some_and(|hold| hold.stands_at(now_ms))
    {
        return registration
            .held
            .get_or_insert_with(|| LeadTurnOpen::opened_at(now_ms))
            .fold(cause, max_causes);
    }
    if registration.owed.is_some() || registration.owed.is_none() {
        registration.owed = Some(LeadTurnOpen::opened_at(now_ms));
        registration.next_due_ms = now_ms.saturating_add(secs_ms(registration.settings.every_secs));
    }
    registration
        .owed
        .as_mut()
        .is_some_and(|owed| owed.fold(cause, max_causes))
}

/// Writes `open` as a new turn line ended `outcome` at `now_ms`, taking the next turn number.
pub(super) fn write_line_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    registration: &mut LeadTurnRegistration,
    open: LeadTurnOpen,
    outcome: LeadTurnOutcome,
    now_ms: u64,
) -> Result<u64> {
    let seq = registration.next_seq;
    registration.next_seq += 1;
    let line = LeadTurn {
        seq,
        opened_at_ms: open.opened_at_ms,
        causes: open.causes,
        cause_count: open.cause_count,
        claimed_at_ms: None,
        lease_until_ms: None,
        ended_at_ms: Some(now_ms),
        outcome: Some(outcome),
        status: None,
        rc: None,
        model_named: registration.lead_model.clone(),
        model_reported: None,
        files: Vec::new(),
        placed_hold: false,
    };
    TURNS.put(&vault.store, txn, &(registration.project, seq), &line)?;
    Ok(seq)
}

/// Writes the causes a hold refused as one held line.
pub(super) fn flush_held_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    registration: &mut LeadTurnRegistration,
    now_ms: u64,
) -> Result<()> {
    if let Some(held) = registration.held.take() {
        write_line_in_txn(
            vault,
            txn,
            registration,
            held,
            LeadTurnOutcome::Held,
            now_ms,
        )?;
    }
    Ok(())
}

/// Places `hold` unless one stands, and ends the owed turn as a held line in the same write.
pub(super) fn place_hold_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    registration: &mut LeadTurnRegistration,
    hold: LeadTurnHold,
    now_ms: u64,
) -> Result<bool> {
    if registration
        .hold
        .as_ref()
        .is_some_and(|standing| standing.stands_at(now_ms))
    {
        return Ok(false);
    }
    registration.hold = Some(hold);
    if let Some(owed) = registration.owed.take() {
        write_line_in_txn(
            vault,
            txn,
            registration,
            owed,
            LeadTurnOutcome::Held,
            now_ms,
        )?;
    }
    Ok(true)
}

/// The hold the registration's `failure_hold` places after turn `seq` did not succeed.
pub(super) fn place_failure_hold_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    registration: &mut LeadTurnRegistration,
    seq: u64,
    now_ms: u64,
) -> Result<()> {
    let lifts_at_ms = match registration.settings.failure_hold {
        LeadTurnFailureHold::None => return Ok(()),
        LeadTurnFailureHold::UntilRelease => None,
        LeadTurnFailureHold::UntilNextDay => Some(next_day_boundary_ms(
            now_ms,
            registration.settings.day_offset_secs,
        )),
    };
    let hold = LeadTurnHold {
        by: LeadTurnHoldBy::Engine,
        at_ms: now_ms,
        reason: format!("turn {seq} did not succeed"),
        lifts_at_ms,
        turn: Some(seq),
    };
    if place_hold_in_txn(vault, txn, registration, hold, now_ms)? {
        let key = (registration.project, seq);
        if let Some(mut line) = TURNS.get_lenient(&vault.store, txn, &key)? {
            line.placed_hold = true;
            TURNS.put(&vault.store, txn, &key, &line)?;
        }
    }
    Ok(())
}

/// The first day boundary after `now_ms` of a day `offset_secs` east of UTC.
pub(super) fn next_day_boundary_ms(now_ms: u64, offset_secs: i64) -> u64 {
    let offset_ms = offset_secs.saturating_mul(1000);
    let local = i64::try_from(now_ms)
        .unwrap_or(i64::MAX)
        .saturating_add(offset_ms);
    let next_local = local
        .div_euclid(DAY_MS)
        .saturating_add(1)
        .saturating_mul(DAY_MS);
    u64::try_from(next_local.saturating_sub(offset_ms)).unwrap_or(0)
}

/// Ends the claimed turn `outcome` at `now_ms`.
fn end_claimed_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    registration: &mut LeadTurnRegistration,
    outcome: LeadTurnOutcome,
    now_ms: u64,
) -> Result<()> {
    let Some(claimed) = registration.claimed.take() else {
        return Ok(());
    };
    let key = (registration.project, claimed.seq);
    if let Some(mut line) = TURNS.get_lenient(&vault.store, txn, &key)?
        && line.ended_at_ms.is_none()
    {
        line.ended_at_ms = Some(now_ms);
        line.outcome = Some(outcome);
        TURNS.put(&vault.store, txn, &key, &line)?;
    }
    Ok(())
}

/// Whether the lead holds a live Grant that lists `.claim` and reaches the project, read in
/// `txn` as the claim door reads it.
fn lead_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    registration: &LeadTurnRegistration,
) -> Result<bool> {
    let Some(lead) = registration.lead else {
        return Ok(false);
    };
    let memory = vault.memory(lead, EdgeActorClass::Agent);
    match memory.verb_grant_caller_admits_over_in_txn(
        txn,
        None,
        LEAD_TURNS_CLAIM_VERB,
        registration.project,
    ) {
        Ok(VerbGrantCaller::Agent { actor, .. }) => Ok(actor == lead),
        Ok(VerbGrantCaller::Owner) => Ok(false),
        Err(error) if error.code == MEMORY_CODE_FORBIDDEN => Ok(false),
        Err(error) => Err(Error::InvalidConfig(format!(
            "the lead's standing could not be read: {}",
            error.message
        ))),
    }
}

/// Ends the owed and the claimed turn `lead_without_grant` and stops the timer.
fn stop_without_grant_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    registration: &mut LeadTurnRegistration,
    now_ms: u64,
) -> Result<()> {
    end_claimed_in_txn(
        vault,
        txn,
        registration,
        LeadTurnOutcome::LeadWithoutGrant,
        now_ms,
    )?;
    let open = registration
        .owed
        .take()
        .unwrap_or_else(|| LeadTurnOpen::opened_at(now_ms));
    write_line_in_txn(
        vault,
        txn,
        registration,
        open,
        LeadTurnOutcome::LeadWithoutGrant,
        now_ms,
    )?;
    registration.armed = false;
    put_registration_in_txn(vault, txn, registration)
}

/// Writes `registration`, bumping its revision, and arms its timer at the earliest time a pass
/// has work, or disarms it once the timer stopped.
pub(super) fn put_registration_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    registration: &mut LeadTurnRegistration,
) -> Result<()> {
    registration.revision += 1;
    REGISTRATIONS.put(&vault.store, txn, &registration.project, registration)?;
    if !registration.armed {
        return disarm_timer_in_txn(vault, txn, registration.project);
    }
    crate::schedule::arm_in_txn(
        &vault.store,
        txn,
        &PROJECT_LEAD_TURN_TIMER_JOB,
        Some(registration.project),
        Trigger::At {
            at: timer_due_ms(registration).div_ceil(1000),
        },
    )
}

fn disarm_timer_in_txn(vault: &Vault, txn: &mut heed::RwTxn<'_>, project: EntityId) -> Result<()> {
    crate::schedule::disarm_in_txn(&vault.store, txn, LEAD_TURN_TIMER_JOB_CODE, Some(project))
        .map(drop)
}

/// The earliest time a pass has work: the timer's due time, the claim's lease end, the hold's
/// lift time.
pub(super) fn timer_due_ms(registration: &LeadTurnRegistration) -> u64 {
    [
        Some(registration.next_due_ms),
        registration
            .claimed
            .map(|claimed: LeadTurnClaim| claimed.lease_until_ms),
        registration.hold.as_ref().and_then(|hold| hold.lifts_at_ms),
    ]
    .into_iter()
    .flatten()
    .min()
    .unwrap_or(registration.next_due_ms)
}

pub(super) fn secs_ms(secs: u64) -> u64 {
    secs.saturating_mul(1000)
}

/// Takes erased `entity` out of the lead turns (the entity erase's side-table scrub, which a
/// project's hard delete and an actor's erase both run, `deletion::actor_fields`). A project's
/// erase deletes its registration, every turn line and kept file, and the starters it listed
/// (ACCEPT condition 4). An actor's erase takes it off the registration that lists it as a
/// starter, and off every registration it leads, which then stops its timer. Registered on two
/// tables; the second call finds nothing left.
///
/// # Errors
///
/// Store errors.
pub(crate) fn erase_lead_turn_entity_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    entity: &EntityId,
) -> Result<()> {
    if REGISTRATIONS.contains(&vault.store, wtxn, entity)? {
        if let Some(registration) = REGISTRATIONS.get_lenient(&vault.store, wtxn, entity)? {
            for starter in &registration.plain_job_starters {
                if STARTERS
                    .get_lenient(&vault.store, wtxn, starter)?
                    .is_some_and(|row| row.project == *entity)
                {
                    STARTERS.delete(&vault.store, wtxn, starter)?;
                }
            }
        }
        for key in FILES.scan_keys(&vault.store, wtxn, entity.as_bytes())? {
            FILES.delete(&vault.store, wtxn, &key)?;
        }
        for key in TURNS.scan_keys(&vault.store, wtxn, entity.as_bytes())? {
            TURNS.delete(&vault.store, wtxn, &key)?;
        }
        REGISTRATIONS.delete(&vault.store, wtxn, entity)?;
        disarm_timer_in_txn(vault, wtxn, *entity)?;
    }
    if let Some(row) = STARTERS.get_lenient(&vault.store, wtxn, entity)? {
        if let Some(mut registration) =
            REGISTRATIONS.get_lenient(&vault.store, wtxn, &row.project)?
        {
            registration
                .plain_job_starters
                .retain(|starter| starter != entity);
            registration.revision += 1;
            REGISTRATIONS.put(&vault.store, wtxn, &row.project, &registration)?;
        }
        STARTERS.delete(&vault.store, wtxn, entity)?;
    }
    let led: Vec<LeadTurnRegistration> = REGISTRATIONS
        .iter_from(&vault.store, wtxn, &[])?
        .filter_map(|row| row.ok().map(|(_, registration)| registration))
        .filter(|registration| registration.lead == Some(*entity))
        .collect();
    for mut registration in led {
        registration.lead = None;
        registration.armed = false;
        put_registration_in_txn(vault, wtxn, &mut registration)?;
    }
    Ok(())
}

/// The kept file under `name` of turn `seq`.
pub(super) fn file_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    project: EntityId,
    seq: u64,
    name: &str,
) -> Result<Option<LeadTurnFile>> {
    FILES.get(&vault.store, txn, &(project, seq, name.to_owned()))
}
