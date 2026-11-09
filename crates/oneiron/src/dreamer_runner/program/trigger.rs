//! Programs a turn does not wake (untangle slice 6.8c, B-3 = A): a due time, the host turning
//! idle, or a change feed moving past its subscription's cursor. Each occurrence records one owed
//! wake, as a landed turn does, carrying the authority its arming sealed; the one drain admits it
//! and judges that authority again. No loop of its own runs: timer and feed programs are released
//! where due watcher ticks are (each fact-hook runner pass and each housekeeping pass, on the node
//! that releases ticks), and idle programs where the host's idle check asks for the idle curator.

use crate::Vault;
use crate::dreamer_wake::WakeIdleState;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::side_table::{self, Named, SideTable};

use super::types::{
    LandedTurnRef, OccurrenceKind, ProgramTrigger, TurnProgramArming, TurnProgramWake,
};
use super::{ADMISSION, ARM, WAKE};

/// Each timer program's next due time, keyed by that time, then the actor and the registration.
const TIMER_DUE: SideTable<(u64, EntityId, EntityId), (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_TIMER_DUE);
/// Each idle or feed program, keyed by its occurrence kind's tag, then the actor and the
/// registration, so a release reads only the programs it releases.
const TRIGGER: SideTable<([u8; 1], EntityId, EntityId), (), Named> =
    SideTable::new(&side_table::DREAMER_TURN_PROGRAM_TRIGGER);

/// How many due timers one write releases; the release takes the next batch until none is due.
const RELEASE_BATCH: usize = 64;
/// How many drain batches one pass admits after it recorded wakes; the next pass admits the rest.
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

/// Indexes `arming` under its trigger, in its arming's writer: a timer under its next due time,
/// an idle or feed program under its kind. A turn program needs no index.
pub(super) fn index_trigger_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    arming: &TurnProgramArming,
) -> Result<()> {
    let key = (arming.actor, arming.registration);
    match (arming.trigger.occurrence_kind(), arming.next_due) {
        (Some(OccurrenceKind::Timer), Some(due)) => {
            TIMER_DUE.put(vault, txn, &(due, key.0, key.1), &())
        }
        (Some(OccurrenceKind::Timer), None) | (None, _) => Ok(()),
        (Some(kind), _) => TRIGGER.put(vault, txn, &([kind.tag()], key.0, key.1), &()),
    }
}

/// Drops `arming`'s trigger index row, in the writer that disarms or erases it.
pub(super) fn unindex_trigger_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    arming: &TurnProgramArming,
) -> Result<()> {
    let key = (arming.actor, arming.registration);
    match (arming.trigger.occurrence_kind(), arming.next_due) {
        (Some(OccurrenceKind::Timer), Some(due)) => {
            TIMER_DUE.delete(vault, txn, &(due, key.0, key.1)).map(drop)
        }
        (Some(OccurrenceKind::Timer), None) | (None, _) => Ok(()),
        (Some(kind), _) => TRIGGER
            .delete(vault, txn, &([kind.tag()], key.0, key.1))
            .map(drop),
    }
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
    /// Records the wake each timer program due at or before `now` owes (untangle slice 6.8c), on
    /// the node that releases due watcher ticks, and moves each timer to its next due time in the
    /// same write. One due time wakes a program once, however many releases see it. Answers how
    /// many wakes it recorded; [`Vault::wake_turn_programs`] admits them, as it admits a turn's.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn release_timer_program_wakes(&self, now: u64) -> Result<usize> {
        let mut recorded = 0;
        loop {
            let (released, more) = release_timer_batch(self, now)?;
            recorded += released;
            if !more {
                return Ok(recorded);
            }
        }
    }

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
                armed.push((actor, registration, key.map(|key| (subscription, key))));
            }
            armed
        };
        if armed.is_empty() {
            return Ok(0);
        }
        // Each mark is read under the program's own lane, outside the write that records it.
        let mut marks = Vec::with_capacity(armed.len());
        for (actor, registration, reader) in armed {
            let mark = match reader {
                Some((subscription, key)) => {
                    crate::feeds::feed_wake_mark(self, &self.scoped_read(key), subscription)?
                }
                None => None,
            };
            marks.push((actor, registration, mark));
        }
        self.with_write_txn_grouped(|txn| {
            let mut recorded = 0;
            for (actor, registration, mark) in &marks {
                let Some(arming) = ARM.get(self, &*txn, &(*actor, *registration))? else {
                    TRIGGER.delete(
                        self,
                        txn,
                        &([OccurrenceKind::Feed.tag()], *actor, *registration),
                    )?;
                    continue;
                };
                // A program whose authority no longer stands, or whose lane is shown nothing new,
                // owes nothing; a subscription gone since arming is refused at admission.
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

/// One write's release of due timers: how many wakes it recorded, and whether more are due.
fn release_timer_batch(vault: &Vault, now: u64) -> Result<(usize, bool)> {
    let mut due = {
        let txn = vault.store.env.read_txn()?;
        if !crate::runtime_hooks::releases_ticks_here(vault, &txn)? {
            return Ok((0, false));
        }
        let mut due = Vec::new();
        for row in TIMER_DUE.iter_from(vault, &txn, &[])? {
            let (key, ()) = row?;
            if key.0 > now || due.len() > RELEASE_BATCH {
                break;
            }
            due.push(key);
        }
        due
    };
    let more = due.len() > RELEASE_BATCH;
    due.truncate(RELEASE_BATCH);
    if due.is_empty() {
        return Ok((0, false));
    }
    let recorded = vault.with_write_txn_grouped(|txn| {
        let mut recorded = 0;
        for key in &due {
            let (due_at, actor, registration) = key;
            // A row another release already moved woke its program already.
            if !TIMER_DUE.delete(vault, txn, key)? {
                continue;
            }
            let Some(mut arming) = ARM.get(vault, &*txn, &(*actor, *registration))? else {
                continue;
            };
            let ProgramTrigger::Timer { every_secs, .. } = arming.trigger else {
                continue;
            };
            if arming.next_due != Some(*due_at) {
                continue;
            }
            if record_occurrence_in_txn(
                vault,
                txn,
                &arming,
                OccurrenceKind::Timer,
                &due_at.to_be_bytes(),
                *due_at,
            )? {
                recorded += 1;
            }
            arming.next_due = next_due_after(*due_at, every_secs, now)?;
            if let Some(next) = arming.next_due {
                TIMER_DUE.put(vault, txn, &(next, *actor, *registration), &())?;
            }
            ARM.put(vault, txn, &(*actor, *registration), &arming)?;
        }
        Ok(recorded)
    })?;
    Ok((recorded, more))
}

/// When this node next releases a timer program: the earliest due time in the timer index, on the
/// node that releases due watcher ticks; `None` elsewhere and while no timer waits. A stopped
/// vault's housekeeping wakes then.
pub(crate) fn next_program_timer_at(vault: &Vault) -> Result<Option<u64>> {
    let txn = vault.store.env.read_txn()?;
    if !crate::runtime_hooks::releases_ticks_here(vault, &txn)? {
        return Ok(None);
    }
    Ok(TIMER_DUE
        .iter_from(vault, &txn, &[])?
        .next()
        .transpose()?
        .map(|((due_at, _, _), ())| due_at))
}

/// The release step each fact-hook runner pass and each housekeeping pass takes after due watcher
/// ticks: timer and feed programs' wakes, then the admission of what they recorded. It never fails
/// its pass: a release or drain that fails is logged and taken again by the next pass.
pub(crate) fn release_program_wakes(vault: &Vault, now: u64) {
    let mut recorded = 0;
    for (trigger, released) in [
        ("timer", vault.release_timer_program_wakes(now)),
        ("feed", vault.release_feed_program_wakes(now)),
    ] {
        match released {
            Ok(count) => recorded += count,
            Err(error) => tracing::warn!(
                kind = ?error.kind(),
                %error,
                trigger,
                "turn program wakes wait for the next pass"
            ),
        }
    }
    if recorded > 0 {
        admit_owed(vault, now);
    }
}

/// The idle check's release step: idle programs' wakes, then the admission of what they
/// recorded. It never fails the check.
pub(crate) fn release_idle_programs(vault: &Vault, idle: WakeIdleState, now: u64) {
    match vault.release_idle_program_wakes(idle, now) {
        Ok(0) => {}
        Ok(_) => admit_owed(vault, now),
        Err(error) => tracing::warn!(
            kind = ?error.kind(),
            %error,
            "idle turn program wakes wait for the next idle check"
        ),
    }
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
