//! Programs a turn does not wake (untangle slice 6.8c, B-3 = A): a due time, the host turning
//! idle, or a change feed moving past its subscription's cursor. Each occurrence records one owed
//! wake, as a landed turn does, carrying the authority its arming sealed; the one drain admits it
//! and judges that authority again. No loop of its own runs: an actor's timer programs are one
//! armed job of the schedule's runner, due at the earliest of their due times (DESIGN
//! 15-setting-primitive, stage 5b-3), run where due watcher ticks are (each fact-hook runner pass
//! and each housekeeping pass, on the node that releases ticks); feed programs are released beside
//! them, and idle programs where the host's idle check asks for the idle curator.

use crate::Vault;
use crate::dreamer_wake::WakeIdleState;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::schedule::{ArmBy, Armed, JobPass, JobResult, JobSpec, Late, Ran, Trigger, When};
use crate::side_table::{self, Named, SideTable};

use super::types::{
    LandedTurnRef, OccurrenceKind, ProgramTrigger, TurnProgramArming, TurnProgramWake,
};
use super::{ADMISSION, ARM, WAKE};

/// The soonest a timer row is due again after its run, and its first retry after a failure: one
/// actor's timers can fall due seconds apart, and the fact-hook runner's pass released each within
/// its tick (two seconds), so the row must not wait the schedule's usual first retry of a minute.
const TIMER_RETRY_FIRST_SECS: u64 = 1;

/// An actor's timer programs: one row about the actor, armed at the earliest due time of its
/// timer armings, re-armed in the write that arms, moves or disarms one, and disarmed when it has
/// none left. One run records the wake each of its timers due by then owes and moves each to its
/// next due time, in one write. Only the node that releases the vault's ticks runs it.
pub(crate) static PROGRAM_TIMER_JOB: JobSpec = JobSpec {
    code: "dreamer_runner.program_timer",
    when: When::PerArming,
    arm_by: ArmBy::Engine,
    late: Late::Run,
    retry_first_secs: TIMER_RETRY_FIRST_SECS,
    retry_cap_secs: None,
    wakes_host: true,
    at_open: false,
    once_per_pass: true,
    runs_here: crate::runtime_hooks::releases_ticks_here,
    drive: crate::schedule::Drive::Runner,
    run: run_program_timer,
};
/// Each idle or feed program, keyed by its occurrence kind's tag, then the actor and the
/// registration, so a release reads only the programs it releases. A feed program's row keeps
/// where its wake scan stands.
const TRIGGER: SideTable<([u8; 1], EntityId, EntityId), TriggerRow, Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_TRIGGER);

/// An idle or feed program's trigger row.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TriggerRow {
    /// A feed program's wake scan, kept between releases (review #6982).
    #[serde(default)]
    feed_scan: crate::feeds::FeedWakeScan,
}

/// How many drain batches one pass admits; the next pass admits the rest.
const DRAIN_BATCHES: usize = 8;
/// The shortest repeat a timer program may ask for.
const MIN_TIMER_EVERY_SECS: u64 = 60;

/// Checks `trigger` for an arming of `actor` in `txn`: only a turn program names a conversation, a
/// repeating timer waits at least a minute, an idle program a second, and a feed program follows a
/// subscription of its own actor.
///
/// # Errors
///
/// `InvalidConfig` for a trigger out of those bounds; `EntityNotFound` for a subscription that is
/// not `actor`'s.
pub(super) fn validate_trigger_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    trigger: &ProgramTrigger,
    conversation: Option<EntityId>,
) -> Result<()> {
    if trigger.is_turn() {
        return Ok(());
    }
    if conversation.is_some() {
        return Err(invalid("only a turn program names a conversation"));
    }
    match trigger {
        ProgramTrigger::Timer { every_secs, .. }
            if *every_secs != 0 && *every_secs < MIN_TIMER_EVERY_SECS =>
        {
            Err(invalid("a timer program repeats at most once a minute"))
        }
        ProgramTrigger::Idle { quiet_secs: 0 } => Err(invalid(
            "an idle program waits a quiet time of at least a second",
        )),
        ProgramTrigger::Feed { subscription } => {
            if crate::feeds::subscription_stands_in_txn(vault, txn, actor, *subscription)? {
                Ok(())
            } else {
                Err(Error::EntityNotFound)
            }
        }
        _ => Ok(()),
    }
}

/// Indexes `arming` under its trigger, in its arming's writer: a timer re-arms its actor's timer
/// row, an idle or feed program goes under its kind. A turn program needs no index.
pub(super) fn index_trigger_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    arming: &TurnProgramArming,
) -> Result<()> {
    let key = (arming.actor, arming.registration);
    match arming.trigger.occurrence_kind() {
        Some(OccurrenceKind::Timer) => arm_actor_timers_in_txn(
            vault,
            txn,
            arming.actor,
            Some(arming.registration),
            arming.next_due,
        )
        .map(drop),
        None => Ok(()),
        Some(kind) => TRIGGER.put(
            vault,
            txn,
            &([kind.tag()], key.0, key.1),
            &TriggerRow::default(),
        ),
    }
}

/// Drops `arming`'s trigger index row, in the writer that disarms it: a timer re-arms its actor's
/// timer row without it.
pub(super) fn unindex_trigger_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    arming: &TurnProgramArming,
) -> Result<()> {
    let key = (arming.actor, arming.registration);
    match arming.trigger.occurrence_kind() {
        Some(OccurrenceKind::Timer) => {
            arm_actor_timers_in_txn(vault, txn, arming.actor, Some(arming.registration), None)
                .map(drop)
        }
        None => Ok(()),
        Some(kind) => TRIGGER
            .delete(vault, txn, &([kind.tag()], key.0, key.1))
            .map(drop),
    }
}

/// Drops the trigger index rows of `armings`, the armings of `actor` its erase takes, in the
/// erase's writer: its timer row goes once, and each idle or feed row.
pub(super) fn unindex_actor_triggers_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    armings: &[TurnProgramArming],
) -> Result<()> {
    for arming in armings {
        if let Some(kind) = arming.trigger.occurrence_kind()
            && !matches!(kind, OccurrenceKind::Timer)
        {
            TRIGGER.delete(
                vault,
                txn,
                &([kind.tag()], arming.actor, arming.registration),
            )?;
        }
    }
    crate::schedule::disarm_in_txn(&vault.store, txn, PROGRAM_TIMER_JOB.code, Some(actor)).map(drop)
}

/// Arms `actor`'s timer row at the earliest next due time of its timer armings, in the caller's
/// write, or disarms it when none is left; answers that time. The armings are read from the arming
/// table, but the one registered as `registration`, whose next due time is `next_due` (it is being
/// armed, moved or disarmed in this write), so the caller may write its arming before or after.
fn arm_actor_timers_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    registration: Option<EntityId>,
    next_due: Option<u64>,
) -> Result<Option<u64>> {
    let mut earliest = next_due;
    for row in ARM.iter_from(vault, &*txn, actor.as_bytes())? {
        let ((_, armed), arming) = row?;
        if Some(armed) == registration || !matches!(arming.trigger, ProgramTrigger::Timer { .. }) {
            continue;
        }
        earliest = match (earliest, arming.next_due) {
            (Some(seen), Some(due)) => Some(seen.min(due)),
            (seen, due) => seen.or(due),
        };
    }
    match earliest {
        Some(at) => crate::schedule::arm_in_txn(
            &vault.store,
            txn,
            &PROGRAM_TIMER_JOB,
            Some(actor),
            Trigger::At { at },
        )?,
        None => {
            crate::schedule::disarm_in_txn(&vault.store, txn, PROGRAM_TIMER_JOB.code, Some(actor))?;
        }
    }
    Ok(earliest)
}

/// Records the wake one occurrence owes `arming`, sealed with the authority the arming sealed, in
/// the release's writer; `false` when it is owed or admitted already, or the arming sealed none.
/// `mark` names the occurrence (`OccurrenceKind::occurrence_id`); `at` is its time.
fn record_occurrence_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    arming: &TurnProgramArming,
    kind: OccurrenceKind,
    mark: &[u8],
    at: u64,
) -> Result<bool> {
    let Some(authority) = arming.sealed.clone() else {
        return Ok(false);
    };
    let occurrence = kind.occurrence_id(arming.registration, mark)?;
    let wake = TurnProgramWake {
        registration: arming.registration,
        revision: arming.revision,
        authority,
        turn: LandedTurnRef {
            turn: occurrence,
            conversation: occurrence,
            landed_at: at,
        },
        occurrence: Some(kind),
        held: None,
    };
    if WAKE.contains(vault, &*txn, &wake.key())?
        || ADMISSION.contains(vault, &*txn, &wake.admission_id())?
    {
        return Ok(false);
    }
    WAKE.put(vault, txn, &wake.key(), &wake)?;
    super::index::index_wake_in_txn(vault, txn, arming.actor, wake.key())?;
    Ok(true)
}

/// A timer's next due time after it woke at `due_at`, read at `now`: `None` for a timer that
/// wakes once; past `now` otherwise, so due times missed while no node released wake it once.
fn next_due_after(due_at: u64, every_secs: u64, now: u64) -> Result<Option<u64>> {
    if every_secs == 0 {
        return Ok(None);
    }
    let missed = now.saturating_sub(due_at) / every_secs;
    missed
        .checked_add(1)
        .and_then(|steps| steps.checked_mul(every_secs))
        .and_then(|step| due_at.checked_add(step))
        .map(Some)
        .ok_or(Error::ArithmeticOverflow("turn program timer due time"))
}

/// The keys of the programs indexed under `kind`, read in `txn`.
fn indexed_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    kind: OccurrenceKind,
) -> Result<Vec<(EntityId, EntityId)>> {
    Ok(TRIGGER
        .scan_keys(vault, txn, &[kind.tag()])?
        .into_iter()
        .map(|(_, actor, registration)| (actor, registration))
        .collect())
}

impl Vault {
    /// Records the wake each idle program owes once the host is idle as `idle` reads (compute
    /// available, no turn or background work running) and no inbound has arrived for its quiet
    /// time (untangle slice 6.8c): once per idle stretch, the stretch named by
    /// `idle.last_inbound_at`. Answers how many wakes it recorded; [`Vault::wake_turn_programs`]
    /// admits them.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn release_idle_program_wakes(&self, idle: WakeIdleState, now: u64) -> Result<usize> {
        if !idle.compute_available || idle.running_turns || idle.live_background_work {
            return Ok(0);
        }
        let armed = {
            let txn = self.store.env.read_txn()?;
            indexed_in_txn(self, &txn, OccurrenceKind::Idle)?
        };
        if armed.is_empty() {
            return Ok(0);
        }
        let stretch = idle.last_inbound_at.to_be_bytes();
        self.with_write_txn_grouped(|txn| {
            let mut recorded = 0;
            for (actor, registration) in &armed {
                let Some(arming) = ARM.get(self, &*txn, &(*actor, *registration))? else {
                    // An arming its erase took whole leaves its index row to the next release.
                    TRIGGER.delete(
                        self,
                        txn,
                        &([OccurrenceKind::Idle.tag()], *actor, *registration),
                    )?;
                    continue;
                };
                let ProgramTrigger::Idle { quiet_secs } = arming.trigger else {
                    continue;
                };
                if now < idle.last_inbound_at.saturating_add(quiet_secs) {
                    continue;
                }
                if record_occurrence_in_txn(
                    self,
                    txn,
                    &arming,
                    OccurrenceKind::Idle,
                    &stretch,
                    now,
                )? {
                    recorded += 1;
                }
            }
            Ok(recorded)
        })
    }

    /// Records the wake each feed program owes while its subscription holds an entry its own lane
    /// shows (untangle slice 6.8c, lead call K), on the node that releases due watcher ticks:
    /// once per first entry it can see, so a feed that shows it nothing new wakes it once, and a
    /// change its lane does not show never wakes it. The wake is judged under the authority its
    /// arming sealed, as the program's own reads are. Answers how many wakes it recorded;
    /// [`Vault::wake_turn_programs`] admits them.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn release_feed_program_wakes(&self, now: u64) -> Result<usize> {
        let armed = {
            let txn = self.store.env.read_txn()?;
            if !crate::runtime_hooks::releases_ticks_here(self, &txn)? {
                return Ok(0);
            }
            let mut armed = Vec::new();
            for (actor, registration) in indexed_in_txn(self, &txn, OccurrenceKind::Feed)? {
                let Some(arming) = ARM.get(self, &txn, &(actor, registration))? else {
                    armed.push((actor, registration, None));
                    continue;
                };
                let ProgramTrigger::Feed { subscription } = arming.trigger else {
                    continue;
                };
                let key = match &arming.sealed {
                    Some(authority) => authority.reader_key_in_txn(self, &txn)?,
                    None => None,
                };
                let prior = TRIGGER
                    .get(
                        self,
                        &txn,
                        &([OccurrenceKind::Feed.tag()], actor, registration),
                    )?
                    .unwrap_or_default()
                    .feed_scan;
                armed.push((
                    actor,
                    registration,
                    key.map(|key| (subscription, key, prior)),
                ));
            }
            armed
        };
        if armed.is_empty() {
            return Ok(0);
        }
        // Each mark is read under the program's own lane, outside the write that records it.
        let mut scans = Vec::with_capacity(armed.len());
        for (actor, registration, reader) in armed {
            // The lane the feed verbs read with (`Memory::read_lane(Recorded)`), so a claim the
            // program's read would be shown, a Proposed one among them, wakes it (review #6982).
            let scanned = match reader {
                Some((subscription, key, prior)) => crate::feeds::feed_wake_mark(
                    self,
                    &self
                        .scoped_read(key)
                        .with_claim_status(crate::claim::ClaimReadStatus::Recorded),
                    subscription,
                    &prior,
                )?,
                None => None,
            };
            scans.push((actor, registration, scanned));
        }
        self.with_write_txn_grouped(|txn| {
            let mut recorded = 0;
            for (actor, registration, scanned) in scans {
                let key = ([OccurrenceKind::Feed.tag()], actor, registration);
                let Some(arming) = ARM.get(self, &*txn, &(actor, registration))? else {
                    TRIGGER.delete(self, txn, &key)?;
                    continue;
                };
                // A program whose authority no longer stands, or whose lane is shown nothing new,
                // owes nothing; a subscription gone since arming is refused at admission.
                let Some((mark, feed_scan)) = scanned else {
                    continue;
                };
                TRIGGER.put(self, txn, &key, &TriggerRow { feed_scan })?;
                let Some(mark) = mark else {
                    continue;
                };
                if record_occurrence_in_txn(
                    self,
                    txn,
                    &arming,
                    OccurrenceKind::Feed,
                    mark.as_bytes(),
                    now,
                )? {
                    recorded += 1;
                }
            }
            Ok(recorded)
        })
    }
}

/// One run of [`PROGRAM_TIMER_JOB`]: releases the timers of the actor it is about, due by now on
/// the recording clock, in one write ([`release_actor_timers_in_txn`]), and is due again at the
/// actor's new earliest timer; with none left its row went in that write.
fn run_program_timer(vault: &Vault, armed: &Armed, _pass: &JobPass<'_>) -> Result<JobResult> {
    let Some(actor) = armed.subject else {
        return Ok(JobResult::of(Ran::Done));
    };
    let next = vault.with_write_txn_grouped(|txn| {
        let now = vault.store.clock.now_recorded_at();
        release_actor_timers_in_txn(vault, txn, actor, now)
    })?;
    Ok(JobResult {
        due_by: next,
        ..JobResult::of(Ran::Done)
    })
}

/// Records the wake each timer program of `actor` due at or before `now` owes (untangle slice
/// 6.8c), moves each to its next due time and re-arms the actor's timer row, in the caller's write.
/// One due time wakes a program once: its arming moves past it in the write that records it, and a
/// wake owed or admitted already is not recorded again. Answers the actor's earliest next due
/// time. [`Vault::wake_turn_programs`] admits the wakes, as it admits a turn's.
fn release_actor_timers_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    actor: EntityId,
    now: u64,
) -> Result<Option<u64>> {
    let mut due = Vec::new();
    for row in ARM.iter_from(vault, &*txn, actor.as_bytes())? {
        let ((_, registration), arming) = row?;
        if let (ProgramTrigger::Timer { every_secs, .. }, Some(due_at)) =
            (arming.trigger, arming.next_due)
            && due_at <= now
        {
            due.push((registration, arming, every_secs, due_at));
        }
    }
    for (registration, mut arming, every_secs, due_at) in due {
        record_occurrence_in_txn(
            vault,
            txn,
            &arming,
            OccurrenceKind::Timer,
            &due_at.to_be_bytes(),
            due_at,
        )?;
        arming.next_due = next_due_after(due_at, every_secs, now)?;
        ARM.put(vault, txn, &(actor, registration), &arming)?;
    }
    arm_actor_timers_in_txn(vault, txn, actor, None, None)
}

/// The release step each fact-hook runner pass and each housekeeping pass takes after the due
/// watcher ticks and timer programs its runner ran: feed programs' wakes, then the admission of
/// every owed wake, the timers' included, a bounded number of batches, whether or not this pass
/// recorded any (review #6982): what a pass leaves owed, the next admits. It never fails its pass:
/// a release or drain that fails is logged and taken again by the next pass.
pub(crate) fn release_program_wakes(vault: &Vault, now: u64) {
    if let Err(error) = vault.release_feed_program_wakes(now) {
        tracing::warn!(
            kind = ?error.kind(),
            %error,
            trigger = "feed",
            "turn program wakes wait for the next pass"
        );
    }
    admit_owed(vault, now);
}

/// The idle check's release step: idle programs' wakes, then the admission of every owed wake,
/// as a pass's release step admits them. It never fails the check.
pub(crate) fn release_idle_programs(vault: &Vault, idle: WakeIdleState, now: u64) {
    if let Err(error) = vault.release_idle_program_wakes(idle, now) {
        tracing::warn!(
            kind = ?error.kind(),
            %error,
            "idle turn program wakes wait for the next idle check"
        );
    }
    admit_owed(vault, now);
}

/// Admits owed wakes through the one drain, a bounded number of batches.
fn admit_owed(vault: &Vault, now: u64) {
    for _ in 0..DRAIN_BATCHES {
        match super::wake::drain_turn_program_wakes(vault, now) {
            Ok(drain) if drain.more => {}
            Ok(_) => return,
            Err(error) => {
                tracing::warn!(
                    kind = ?error.kind(),
                    %error,
                    "owed turn program wakes wait for the next drain"
                );
                return;
            }
        }
    }
}

fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(reason.to_owned())
}
